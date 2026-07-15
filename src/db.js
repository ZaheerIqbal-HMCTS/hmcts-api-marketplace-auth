const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error(
    'DATABASE_URL is not set. Add it in your hosting provider\'s environment variables ' +
    '(e.g. Render: create a Postgres instance, then copy its "Internal Database URL" here).'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render's managed Postgres requires SSL, but uses a certificate that
  // Node won't automatically trust as a public CA - this is the standard,
  // documented way to connect to it.
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      organisation TEXT,
      role TEXT NOT NULL CHECK (role IN ('consumer', 'producer')),
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, initDb };
