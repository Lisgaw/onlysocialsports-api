'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DIRECT_URL,
  ssl: { rejectUnauthorized: false },
});

async function run() {
  const client = await pool.connect();
  try {
    await client.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS sport_name TEXT');
    await client.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS country_name TEXT');
    await client.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS district_name TEXT');
    await client.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ');
    console.log('OK: Added missing columns to posts table');

    const res = await client.query(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'posts' ORDER BY ordinal_position"
    );
    console.log('Posts columns:', res.rows.map(r => r.column_name).join(', '));
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
