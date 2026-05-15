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
    // Find admin user
    const users = await client.query("SELECT id, name, email FROM users WHERE email = 'admin@sporpartner.com'");
    if (users.rows.length === 0) { console.error('No admin user'); return; }
    const adminId = users.rows[0].id;
    console.log('Admin user:', adminId, users.rows[0].name);

    // Test direct insert with real user id
    const res = await client.query(`
      INSERT INTO posts (id, user_id, post_type, content, title, sport_id, sport_name, updated_at)
      VALUES ($1, $2, 'SOCIAL_LISTING', 'Direct test', 'Test', 'basketball', 'Basketbol', $3)
      RETURNING id, post_type, content, sport_name, updated_at
    `, ['post_test_' + Date.now(), adminId, new Date().toISOString()]);
    console.log('Direct insert OK:', JSON.stringify(res.rows[0]));
    
    // Clean up
    await client.query('DELETE FROM posts WHERE id = $1', [res.rows[0].id]);
    console.log('Cleaned up');
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
