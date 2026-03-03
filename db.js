const { Pool } = require('pg');
require('dotenv').config();

// Cria a conexão usando as configurações do arquivo .env
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessário para conectar no Neon
    }
});

// Teste de conexão ao iniciar
pool.connect((err) => {
    if (err) {
        console.error('❌ Erro ao conectar no Banco de Dados:', err.message);
    } else {
        console.log('✅ Conectado ao Banco de Dados Neon (PostgreSQL) com sucesso!');
    }
});

module.exports = pool;