'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const DIRECT_URL = process.env.DIRECT_URL;
if (!DIRECT_URL) {
  console.error('DIRECT_URL is not set in backend/.env');
  process.exit(1);
}

async function main() {
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '009_push_tokens_locale.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const pool = new Pool({
    connectionString: DIRECT_URL,
    ssl: { rejectUnauthorized: false },
  });

  const client = await pool.connect();
  try {
    await client.query(sql);

    const columnCheck = await client.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'push_tokens'
        AND column_name = 'locale'
    `);

    const indexCheck = await client.query(`
      SELECT indexname
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename = 'push_tokens'
        AND indexname = 'idx_push_tokens_locale'
      ORDER BY indexname
    `);

    const summary = {
      migration: '009_push_tokens_locale.sql',
      localeColumnExists: (columnCheck.rows || []).length > 0,
      indexes: indexCheck.rows.map((r) => r.indexname),
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err.message || String(err));
  process.exit(1);
});
