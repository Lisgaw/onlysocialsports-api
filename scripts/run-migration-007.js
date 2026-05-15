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
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '007_push_tokens.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const pool = new Pool({
    connectionString: DIRECT_URL,
    ssl: { rejectUnauthorized: false },
  });

  const client = await pool.connect();
  try {
    await client.query(sql);

    const tableCheck = await client.query(`
      SELECT to_regclass('public.push_tokens') AS table_name
    `);

    const indexCheck = await client.query(`
      SELECT indexname
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename = 'push_tokens'
        AND indexname IN ('idx_push_tokens_user_id', 'idx_push_tokens_active')
      ORDER BY indexname
    `);

    const summary = {
      migration: '007_push_tokens.sql',
      tableExists: tableCheck.rows?.[0]?.table_name === 'push_tokens',
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
