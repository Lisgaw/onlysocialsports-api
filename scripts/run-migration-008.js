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
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '008_auth_audit_logs.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const pool = new Pool({
    connectionString: DIRECT_URL,
    ssl: { rejectUnauthorized: false },
  });

  const client = await pool.connect();
  try {
    await client.query(sql);

    const tableCheck = await client.query(`
      SELECT to_regclass('public.auth_audit_logs') AS table_name
    `);

    const indexCheck = await client.query(`
      SELECT indexname
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename = 'auth_audit_logs'
        AND indexname IN (
          'idx_auth_audit_logs_created_at',
          'idx_auth_audit_logs_event_type',
          'idx_auth_audit_logs_email',
          'idx_auth_audit_logs_user_id'
        )
      ORDER BY indexname
    `);

    const summary = {
      migration: '008_auth_audit_logs.sql',
      tableExists: tableCheck.rows?.[0]?.table_name === 'auth_audit_logs',
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
