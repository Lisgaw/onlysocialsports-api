/**
 * Run SQL migration on Supabase via direct PostgreSQL connection.
 * Usage: cd backend && node scripts/run-migration.js
 */
'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const DIRECT_URL = process.env.DIRECT_URL;
if (!DIRECT_URL) {
  console.error('❌ DIRECT_URL not set in .env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DIRECT_URL,
  ssl: { rejectUnauthorized: false },
});

async function run() {
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '001_initial_schema.sql');
  const sql = fs.readFileSync(sqlPath, 'utf-8');
  console.log(`📄 Migration dosyası: ${(sql.length / 1024).toFixed(1)} KB`);

  const client = await pool.connect();
  try {
    console.log('🔄 Migration çalıştırılıyor...');
    await client.query(sql);
    console.log('✅ Migration başarılı!');

    // Verify tables
    const res = await client.query(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = ANY($1)
      ORDER BY table_name
    `, [['sports', 'cities', 'districts', 'countries', 'users', 'listings', 'matches',
         'conversations', 'messages', 'challenges', 'notifications', 'follows',
         'blocked_users', 'interests', 'ratings', 'posts', 'post_reactions',
         'comments', 'comment_likes', 'bot_tasks', 'otps', 'noshows',
         'user_privacy', 'communities', 'groups', 'group_members', 'refresh_tokens']]);

    console.log(`\n📊 Oluşturulan tablolar (${res.rows.length}/27):`);
    res.rows.forEach(r => console.log(`   ✅ ${r.table_name}`));

    // Check seed data
    const sports = await client.query('SELECT COUNT(*) FROM sports');
    const cities = await client.query('SELECT COUNT(*) FROM cities');
    const countries = await client.query('SELECT COUNT(*) FROM countries');
    console.log(`\n🌱 Seed Data:`);
    console.log(`   Sports: ${sports.rows[0].count}`);
    console.log(`   Cities: ${cities.rows[0].count}`);
    console.log(`   Countries: ${countries.rows[0].count}`);
  } catch (err) {
    console.error('❌ Migration hatası:', err.message);
    if (err.position) {
      const lines = sql.substring(0, parseInt(err.position)).split('\n');
      console.error(`   Satır: ~${lines.length}`);
      console.error(`   Yakın kod: ${lines[lines.length - 1]}`);
    }
  } finally {
    client.release();
    await pool.end();
  }
}

run();
