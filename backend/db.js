const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'phishing-detection',
  password: 'sethulakshmi1!',
  port: 5432,
});

module.exports = pool;