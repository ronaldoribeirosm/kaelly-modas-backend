const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { calcularPrecoPrazo } = require('correios-brasil');

// 🚀 IMPORTANDO A STRIPE NO LUGAR DO MERCADO PAGO
const Stripe = require('stripe');

// Carrega variáveis do .env
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BACKEND_URL = process.env.BACKEND_URL || 'https://yf-pratas-backend.onrender.com';

// --- DEFINIÇÃO DA URL DO FRONTEND (PRODUÇÃO VS LOCAL) ---
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// --- SEGURANÇA E CONFIGURAÇÕES ---
const JWT_SECRET = process.env.JWT_SECRET || 'chave_mestra_yf_pratas_seguranca_total';

// 🚀 INICIALIZANDO A STRIPE
// Pegamos a chave secreta (Secret Key) do seu .env
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Email (Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.use(cors());

// 🚀 TRUQUE DE MESTRE PARA O WEBHOOK DA STRIPE FUNCIONAR:
// A Stripe precisa ler os dados puros (raw) para garantir que não é um hacker forjando o pagamento.
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// --- UPLOAD (Temporário para enviar pro ImgBB) ---
app.use('/uploads', express.static('uploads'));
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// --- ROTA SAÚDE ---
app.get('/', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ message: 'API Kaelly Modas: Online 🚀', time: result.rows[0].now, env: process.env.NODE_ENV });
    } catch (err) { res.status(500).json({ error: 'Erro no banco de dados' }); }
});

// ==========================================
//              AUTENTICAÇÃO
// ==========================================

app.post('/auth/register', async (req, res) => {
    const { nome, email, password } = req.body;
    try {
        const userCheck = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) return res.status(400).json({ error: 'Email já cadastrado.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const count = await pool.query('SELECT COUNT(*) FROM usuarios');
        const isAdmin = count.rows[0].count === '0';

        const newUser = await pool.query(
            'INSERT INTO usuarios (nome, email, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, is_admin',
            [nome, email, hashedPassword, isAdmin]
        );
        res.json({ message: 'Criado com sucesso!', user: newUser.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Erro no cadastro' }); }
});

app.post('/auth/login', async (req, res) => {
    const { email, password, code } = req.body; 
    try {
        const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const user = userResult.rows[0];
        if (!user) return res.status(400).json({ error: 'Usuário não encontrado.' });

        // Correção do nome da coluna de senha para bater com a tabela nova
        const validPassword = await bcrypt.compare(password, user.password_hash || user.senha);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

        // LÓGICA 2FA COMPLETA
        if (user.two_factor_enabled) {
            if (!code) {
                const newCode = Math.floor(100000 + Math.random() * 900000).toString();
                // Assumindo que você criou as colunas de email_code no DB novo. Se não, avise!
                await pool.query(`UPDATE usuarios SET two_factor_secret = $1 WHERE id = $2`, [newCode, user.id]);
                
                try {
                    await transporter.sendMail({
                        from: `Kaelly Modas <${process.env.EMAIL_USER}>`,
                        to: email,
                        subject: 'Seu Código de Acesso Seguro',
                        text: `Seu código de verificação é: ${newCode} (Válido para este login)`
                    });
                } catch (e) { console.error("Erro ao enviar email", e); }
                
                return res.json({ require2fa: true, message: 'Código enviado para seu e-mail.' }); 
            }

            if (user.two_factor_secret !== code) return res.status(400).json({ error: 'Código inválido.' });

            await pool.query(`UPDATE usuarios SET two_factor_secret = NULL WHERE id = $1`, [user.id]);
        }

        const token = jwt.sign({ id: user.id, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ 
            message: 'Login OK', 
            token, 
            user: { id: user.id, nome: user.nome, email: user.email, is_admin: user.is_admin, two_factor_enabled: user.two_factor_enabled } 
        });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Erro no login' }); }
});

app.post('/auth/2fa/enable', async (req, res) => {
    const { email } = req.body;
    try {
        await pool.query('UPDATE usuarios SET two_factor_enabled = TRUE WHERE email = $1', [email]);
        res.json({ message: 'Autenticação de dois fatores ativada!' });
    } catch (err) { res.status(500).json({ error: 'Erro ao ativar 2FA' }); }
});

// ==========================================
//              PRODUTOS (COM IMGBB)
// ==========================================

app.get('/produtos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM produtos ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Erro ao buscar produtos' }); }
});

app.get('/produtos/categoria/:tipo', async (req, res) => {
    const { tipo } = req.params;
    try {
        const result = await pool.query('SELECT * FROM produtos WHERE categoria ILIKE $1', [`%${tipo}%`]);
        res.json(result.rows);
    } catch (err) { console.error(err); res.status(500).json({ error: 'Erro no servidor' }); }
});

app.get('/produtos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM produtos WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Produto não encontrado' });
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Erro no servidor' }); }
});

app.post('/produtos', upload.single('imagem'), async (req, res) => {
    const { nome, descricao, preco, categoria, estoque } = req.body;
    let imgUrl = 'https://via.placeholder.com/150';
    
    try {
        if (req.file) {
            const fileData = fs.readFileSync(req.file.path).toString('base64');
            const formData = new FormData();
            formData.append('image', fileData);

            const imgbbRes = await fetch(`https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`, {
                method: 'POST',
                body: formData
            }).then(r => r.json());

            if (imgbbRes.success) imgUrl = imgbbRes.data.url;
            fs.unlinkSync(req.file.path); 
        }

        const newP = await pool.query(
            'INSERT INTO produtos (nome, descricao, preco, categoria, imagem_url, estoque) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', 
            [nome, descricao, parseFloat(preco), categoria, imgUrl, parseInt(estoque)]
        );
        res.json(newP.rows[0]);
    } catch (e) { 
        console.error("Erro upload:", e);
        res.status(500).json({ error: 'Erro ao criar produto' }); 
    }
});

app.put('/produtos/:id', upload.single('imagem'), async (req, res) => {
    const { id } = req.params;
    const { nome, descricao, preco, categoria, estoque } = req.body;
    try {
        const old = await pool.query('SELECT * FROM produtos WHERE id = $1', [id]);
        if (old.rows.length === 0) return res.status(404).json({ error: 'Não encontrado' });
        
        let imgUrl = old.rows[0].imagem_url;
        
        if (req.file) {
            const fileData = fs.readFileSync(req.file.path).toString('base64');
            const formData = new FormData();
            formData.append('image', fileData);

            const imgbbRes = await fetch(`https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`, {
                method: 'POST',
                body: formData
            }).then(r => r.json());

            if (imgbbRes.success) imgUrl = imgbbRes.data.url;
            fs.unlinkSync(req.file.path);
        }

        const up = await pool.query(
            'UPDATE produtos SET nome=$1, descricao=$2, preco=$3, categoria=$4, estoque=$5, imagem_url=$6 WHERE id=$7 RETURNING *', 
            [nome, descricao, parseFloat(preco), categoria, parseInt(estoque), imgUrl, id]
        );
        res.json(up.rows[0]);
    } catch (e) { res.status(500).json({ error: 'Erro ao editar produto' }); }
});

app.delete('/produtos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM produtos WHERE id = $1 RETURNING *', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado' });
        res.json({ message: 'Produto deletado com sucesso!', produto: result.rows[0] });
    } catch (e) { res.status(500).json({ error: 'Erro ao deletar' }); }
});

// ==========================================
//              CARRINHO
// ==========================================

app.post('/carrinho', authenticateToken, async (req, res) => {
    const { produto_id, quantidade } = req.body;
    try {
        const check = await pool.query('SELECT * FROM carrinho WHERE usuario_id = $1 AND produto_id = $2', [req.user.id, produto_id]);
        if (check.rows.length > 0) {
            await pool.query('UPDATE carrinho SET quantidade = quantidade + $1 WHERE id = $2', [quantidade, check.rows[0].id]);
        } else {
            await pool.query('INSERT INTO carrinho (usuario_id, produto_id, quantidade) VALUES ($1, $2, $3)', [req.user.id, produto_id, quantidade]);
        }
        res.json({ message: 'Adicionado ao carrinho' });
    } catch (e) { res.status(500).json({ error: 'Erro no carrinho' }); }
});

app.get('/carrinho', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT c.id, c.quantidade, p.id as produto_id, p.nome, p.preco, p.imagem_url FROM carrinho c JOIN produtos p ON c.produto_id = p.id WHERE c.usuario_id = $1 ORDER BY c.criado_em ASC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro no carrinho' }); }
});

app.delete('/carrinho/:pid', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM carrinho WHERE usuario_id = $1 AND produto_id = $2', [req.user.id, req.params.pid]);
        res.json({ message: 'Item removido' });
    } catch (e) { res.status(500).json({ error: 'Erro ao remover' }); }
});

// ==========================================
//           FRETE E PAGAMENTO (STRIPE)
// ==========================================

app.post('/calcular-frete', async (req, res) => {
    const { cepDestino, estadoDestino } = req.body;
    if (!cepDestino) return res.status(400).json({ error: 'CEP obrigatório' });

    const args = { sCepOrigem: '12460000', sCepDestino: cepDestino.replace(/\D/g, ''), nVlPeso: '0.3', nCdFormato: '1', nVlComprimento: '16', nVlAltura: '4', nVlLargura: '11', nCdServico: ['04014', '04510'], nVlDiametro: '0' };

    try {
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout Correios')), 4000));
        const response = await Promise.race([calcularPrecoPrazo(args), timeoutPromise]);
        
        const opcoes = response.map(item => ({ 
            tipo: item.Codigo === '04014' ? 'SEDEX' : 'PAC', 
            valor: parseFloat(item.Valor.replace(',', '.')), 
            prazo: item.PrazoEntrega, 
            erro: item.Erro !== '0' 
        })).filter(i => !i.erro);
        
        if (opcoes.length === 0) throw new Error("Sem opções dos Correios");
        res.json(opcoes);

    } catch (error) {
        console.log("⚠️ Falha Correios. Usando Tabela Local/Estado.");
        const cepLimpo = cepDestino ? cepDestino.replace(/\D/g, '') : '';
        let valor = 35.00, prazo = '7-10';
        
        if (estadoDestino) {
            const uf = estadoDestino.toUpperCase();
            if (uf === 'SP') { 
                if (cepLimpo.startsWith('1246')) { valor = 0.00; prazo = '1-2'; } 
                else if (cepLimpo.startsWith('120') || cepLimpo.startsWith('121')) { valor = 10.00; prazo = '2-3'; } 
                else if (cepLimpo.startsWith('122')) { valor = 15.00; prazo = '2-4'; } 
                else { valor = 22.00; prazo = '3-5'; }
            }
            else if (['RJ', 'MG', 'ES'].includes(uf)) { valor = 28.00; prazo = '4-6'; }
            else if (['PR', 'SC', 'RS'].includes(uf)) { valor = 32.00; prazo = '5-8'; }
            else if (['DF', 'GO', 'MS', 'MT'].includes(uf)) { valor = 45.00; prazo = '6-9'; }
            else if (['BA', 'SE', 'AL', 'PE', 'PB', 'RN', 'CE', 'PI', 'MA'].includes(uf)) { valor = 58.00; prazo = '8-15'; }
            else { valor = 75.00; prazo = '10-20'; } 
        }
        res.json([{ tipo: 'Envio Expresso (Transportadora)', valor, prazo }]);
    }
});

// 🚀 NOVA ROTA DE PEDIDOS COM STRIPE
app.post('/pedidos', authenticateToken, async (req, res) => {
    const { dados_cliente, endereco, itens, frete, prazo } = req.body;
    try {
        const total = itens.reduce((acc, i) => acc + (Number(i.preco) * Number(i.quantity)), 0) + Number(frete);
        const itensHist = itens.map(i => ({ nome: i.nome, quantity: i.quantity, preco: i.preco }));
        const detalhes = { valor: frete, prazo: prazo || 'A definir', transportadora: 'Correios' };

        // 1. Cria o Pedido PENDENTE no Banco PRIMEIRO
        const newOrder = await pool.query(
            `INSERT INTO pedidos (usuario_id, total, dados_cliente, endereco_entrega, status, itens, detalhes_envio) VALUES ($1, $2, $3, $4, 'pendente', $5, $6) RETURNING id`,
            [req.user.id, total, JSON.stringify(dados_cliente), JSON.stringify(endereco), JSON.stringify(itensHist), JSON.stringify(detalhes)]
        );
        const pedidoId = newOrder.rows[0].id; 

        // 2. Transforma os itens para o formato da Stripe (em centavos!)
        const line_items = itens.map(i => ({
            price_data: {
                currency: 'brl',
                product_data: { name: i.nome },
                unit_amount: Math.round(Number(i.preco) * 100), // R$ 50.00 vira 5000 centavos
            },
            quantity: Number(i.quantity) || 1,
        }));

        // Adiciona o Frete se tiver
        if (frete > 0) {
            line_items.push({
                price_data: {
                    currency: 'brl',
                    product_data: { name: 'Frete / Envio Especial' },
                    unit_amount: Math.round(Number(frete) * 100),
                },
                quantity: 1,
            });
        }

        // 3. Cria a Sessão de Checkout na Stripe
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'], // Se quiser PIX na Stripe precisa habilitar no painel deles
            line_items,
            mode: 'payment',
            client_reference_id: String(pedidoId), // Grava nosso ID de pedido na Stripe!
            customer_email: dados_cliente.email,
            // Truque mágico: Enganamos o Frontend enviando os parâmetros que ele já esperava do MP
            success_url: `${FRONTEND_URL}/sucesso?collection_status=approved&preference_id={CHECKOUT_SESSION_ID}&payment_id=stripe_pagamento`,
            cancel_url: `${FRONTEND_URL}/`,
        });
        
        // 4. Salva a ID da sessão da Stripe na coluna preference_id
        await pool.query(`UPDATE pedidos SET preference_id = $1 WHERE id = $2`, [session.id, pedidoId]);

        // Retorna a URL de pagamento para a tela do Checkout redirecionar a cliente
        res.json({ id: session.id, pedido_id: pedidoId, url: session.url });
    } catch (e) { 
        console.error("❌ Erro ao criar pedido na Stripe:", e); 
        res.status(500).json({ error: "Erro ao processar pedido no servidor." }); 
    }
});

// 🚀 ROTA NOVA PARA O FRONTEND VERIFICAR SE FOI PAGO MESMO
app.post('/verificar-pagamento', async (req, res) => {
    const { preference_id } = req.body;
    try {
        // Puxa a sessão da Stripe
        const session = await stripe.checkout.sessions.retrieve(preference_id);
        if (session.payment_status === 'paid') {
            res.sendStatus(200);
        } else {
            res.sendStatus(400);
        }
    } catch (e) {
        console.error(e);
        res.sendStatus(500);
    }
});


// ==========================================
//       WEBHOOK (Ouvinte Oficial da Stripe)
// ==========================================
app.post('/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
        // Stripe verifica se a mensagem realmente veio deles (Anti-Hacker)
        if (endpointSecret) {
            event = stripe.webhooks.constructEvent(req.rawBody, sig, endpointSecret);
        } else {
            // Se você não colocou a chave secreta de webhook no .env, ele processa sem verificar (Não recomendado em Produção)
            event = req.body;
        }
    } catch (err) {
        console.error(`⚠️ Erro de Assinatura Webhook.`, err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Se o pagamento foi concluído com sucesso
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const pedidoId = session.client_reference_id;

        // Se o status da fatura é 'pago' e temos o ID do nosso banco
        if (session.payment_status === 'paid' && pedidoId) {
            try {
                await pool.query(`UPDATE pedidos SET status = 'pago' WHERE id = $1`, [pedidoId]);
                console.log(`✅ Pagamento Stripe Aprovado! Pedido ${pedidoId} atualizado para PAGO.`);
            } catch(e) {
                console.error("Erro ao atualizar DB pelo Webhook:", e);
            }
        }
    }

    // Responde 200 pra Stripe não tentar enviar de novo
    res.send();
});


// ==========================================
//          ÁREA DO CLIENTE & ADMIN
// ==========================================

app.get('/meus-pedidos', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM pedidos WHERE usuario_id = $1 ORDER BY criado_em DESC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro ao buscar pedidos' }); }
});

app.get('/admin/pedidos', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT is_admin FROM usuarios WHERE id = $1', [req.user.id]);
        if (!check.rows.length || !check.rows[0].is_admin) return res.status(403).json({ error: 'Acesso negado' });
        
        const r = await pool.query('SELECT * FROM pedidos ORDER BY id DESC');
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro ao buscar pedidos (admin)' }); }
});

app.put('/admin/pedidos/:id/status', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { status, codigo_rastreio } = req.body;

    try {
        const check = await pool.query('SELECT is_admin FROM usuarios WHERE id = $1', [req.user.id]);
        if (!check.rows[0].is_admin) return res.sendStatus(403);

        if (codigo_rastreio) {
            await pool.query('UPDATE pedidos SET status = $1, codigo_rastreio = $2 WHERE id = $3', [status, codigo_rastreio, id]);
        } else {
            await pool.query('UPDATE pedidos SET status = $1 WHERE id = $2', [status, id]);
        }
        res.json({ message: 'Status atualizado!' });
    } catch (e) { res.status(500).json({ error: 'Erro ao atualizar pedido' }); }
});

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT} | Front: ${FRONTEND_URL}`));