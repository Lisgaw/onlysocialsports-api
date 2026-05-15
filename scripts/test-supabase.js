/**
 * Supabase Bağlantı Testi & Migration Runner
 * 
 * Kullanım:
 *   cd backend
 *   node scripts/test-supabase.js
 *   node scripts/test-supabase.js --migrate
 */
'use strict';

// .env yükle
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL veya SUPABASE_SERVICE_KEY tanımlı değil!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

async function testConnection() {
  console.log('🔍 Supabase bağlantısı test ediliyor...');
  console.log(`   URL: ${SUPABASE_URL}`);
  console.log(`   Key: ${SUPABASE_KEY.substring(0, 30)}...`);
  
  try {
    // Test 1: Basit sorgu
    const { data, error } = await supabase.from('sports').select('id').limit(1);
    
    if (error) {
      if (error.code === '42P01') {
        console.log('⚠️  "sports" tablosu bulunamadı — migration gerekli.');
        return { connected: true, tablesExist: false };
      }
      throw error;
    }
    
    console.log('✅ Supabase bağlantısı başarılı!');
    console.log(`   sports tablosu mevcut (${data ? data.length : 0} kayıt test edildi)`);
    
    // Test 2: Tüm tabloları kontrol et
    const tables = [
      'sports', 'cities', 'districts', 'countries', 'users', 'refresh_tokens',
      'listings', 'matches', 'conversations', 'messages', 'challenges',
      'notifications', 'follows', 'blocked_users', 'interests', 'ratings',
      'posts', 'post_reactions', 'comments', 'comment_likes', 'bot_tasks',
      'otps', 'noshows', 'user_privacy', 'communities', 'groups', 'group_members'
    ];
    
    const results = {};
    for (const table of tables) {
      try {
        const { count, error: err } = await supabase
          .from(table)
          .select('*', { count: 'exact', head: true });
        results[table] = err ? `❌ ${err.code}` : `✅ ${count} kayıt`;
      } catch (e) {
        results[table] = `❌ ${e.message}`;
      }
    }
    
    console.log('\n📊 Tablo Durumu:');
    for (const [table, status] of Object.entries(results)) {
      console.log(`   ${table.padEnd(20)} ${status}`);
    }
    
    return { connected: true, tablesExist: true, tables: results };
  } catch (err) {
    console.error('❌ Bağlantı hatası:', err.message);
    if (err.message.includes('Invalid API key')) {
      console.error('   → API key geçersiz! Supabase Dashboard → Settings → API → service_role key');
    }
    return { connected: false, tablesExist: false, error: err.message };
  }
}

async function runMigration() {
  console.log('\n🔄 SQL Migration çalıştırılıyor...');
  
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '001_initial_schema.sql');
  if (!fs.existsSync(sqlPath)) {
    console.error('❌ Migration dosyası bulunamadı:', sqlPath);
    return false;
  }
  
  const sql = fs.readFileSync(sqlPath, 'utf-8');
  console.log(`   SQL dosyası: ${(sql.length / 1024).toFixed(1)} KB`);
  
  // Supabase JS client ile raw SQL çalıştırma
  // Not: rpc kullanılmalı veya Dashboard SQL Editor'dan çalıştırılmalı
  try {
    const { data, error } = await supabase.rpc('exec_sql', { sql_text: sql });
    if (error) throw error;
    console.log('✅ Migration başarılı!');
    return true;
  } catch (err) {
    console.log('⚠️  RPC ile migration çalıştırılamadı:', err.message);
    console.log('\n📋 Alternatif: Aşağıdaki SQL\'i Supabase Dashboard → SQL Editor\'a yapıştırın:');
    console.log(`   Dosya: ${sqlPath}`);
    console.log(`   Boyut: ${(sql.length / 1024).toFixed(1)} KB`);
    console.log('   URL: https://supabase.com/dashboard/project/ahvnbxycwnwbrgtcrsnf/sql/new');
    return false;
  }
}

async function main() {
  const doMigrate = process.argv.includes('--migrate');
  
  const result = await testConnection();
  
  if (!result.connected) {
    console.log('\n💡 Çözüm: Supabase Dashboard → Settings → API → service_role key\'i .env\'ye kopyalayın.');
    process.exit(1);
  }
  
  if (!result.tablesExist || doMigrate) {
    await runMigration();
    // Migration sonrası tekrar test
    await testConnection();
  }
  
  console.log('\n✨ Test tamamlandı.');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
