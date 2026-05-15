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
    // Reload PostgREST schema cache
    await client.query("NOTIFY pgrst, 'reload schema'");
    console.log('OK: PostgREST schema cache reloaded');

    // Test direct insert
    const insertSql = `
      INSERT INTO posts (id, user_id, post_type, content, title, sport_id, sport_name, country_name, city_id, city_name, district_id, district_name, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `;
    const res = await client.query(insertSql, [
      'post_test_' + Date.now(),
      'user_c4a07ee5-42b5-4f67-b2e0-c3d35c99d110', // admin user
      'SOCIAL_LISTING',
      'Direct DB test post',
      'Test Title',
      'basketball',
      'Basketbol',
      null,
      null,
      null,
      null,
      null,
      new Date().toISOString()
    ]);
    console.log('Direct insert OK:', JSON.stringify(res.rows[0], null, 2));

    // Clean up
    await client.query('DELETE FROM posts WHERE id = $1', [res.rows[0].id]);
    console.log('Cleaned up test post');
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
