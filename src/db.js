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

  // "My applications and teams" - Phase 1 (see the design doc: no teams yet,
  // every application is owned directly by the user who created it).
  // Ids are generated in application code (crypto.randomUUID()) rather than
  // a DB-side default, so this doesn't depend on any Postgres extension
  // (pgcrypto/uuid-ossp) being available on the hosting Postgres instance.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'development', 'integration-test', 'production')),
      owner_type TEXT NOT NULL CHECK (owner_type IN ('user')),
      owner_id INTEGER NOT NULL,
      created_by INTEGER NOT NULL REFERENCES users(id),
      public_key_url TEXT,
      callback_url TEXT,
      custom_attributes JSONB NOT NULL DEFAULT '{}',
      connected_apis JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE (owner_type, owner_id, name)
    );
  `);

  // Raw keys are never stored, only bcrypt hashes, matching password
  // handling above - the raw value is returned once, at creation time, and
  // never again. key_preview (last 4 chars) is what the UI shows afterwards.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id UUID PRIMARY KEY,
      application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
      key_hash TEXT NOT NULL,
      key_preview TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      revoked_at TIMESTAMPTZ
    );
  `);
}

module.exports = { pool, initDb };
