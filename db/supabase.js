'use strict';

/**
 * Supabase Client — PostgreSQL bağlantı katmanı
 *
 * Kullanım:
 *   1. Supabase Dashboard → Settings → API → URL + anon key
 *   2. .env dosyasına ekle:
 *        SUPABASE_URL=https://xxxxx.supabase.co
 *        SUPABASE_SERVICE_KEY=eyJhbGci...
 *   3. server.js'de: const db = require('./db/supabase');
 *      db.from('users').select('*').eq('email', email);
 */

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.warn(
    '⚠️  SUPABASE_URL veya SUPABASE_SERVICE_KEY tanımlı değil.\n' +
    '   Supabase devre dışı — in-memory store kullanılacak.'
  );
}

/**
 * Supabase service-role client.
 * Service key kullanılıyor çünkü kendi JWT auth'umuz var (RLS bypass).
 */
const supabase = SUPABASE_URL && SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
      db: { schema: 'public' },
    })
  : null;

/**
 * Supabase bağlantısını test et.
 * @returns {Promise<boolean>}
 */
async function testConnection() {
  if (!supabase) return false;
  try {
    const { data, error } = await supabase.from('sports').select('id').limit(1);
    if (error) throw error;
    console.log('✅ Supabase bağlantısı başarılı.');
    return true;
  } catch (err) {
    console.error('❌ Supabase bağlantı hatası:', err.message);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERY HELPERS — store.js arayüzünü taklit eden yardımcılar
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Tablo sorgula (SELECT).
 * @param {string} table - Tablo adı
 * @param {Object} [options]
 * @param {string} [options.select] - Kolon seçimi (default: '*')
 * @param {Object} [options.filters] - {column: value} eşitlik filtreleri
 * @param {string} [options.order] - Sıralama kolonu
 * @param {boolean} [options.ascending] - Artan mı?
 * @param {number} [options.limit] - Maks kayıt
 * @param {number} [options.offset] - Atlama
 * @returns {Promise<Array>}
 */
async function query(table, options = {}) {
  const { select = '*', filters = {}, order, ascending = false, limit, offset } = options;

  let q = supabase.from(table).select(select);

  for (const [col, val] of Object.entries(filters)) {
    if (val !== undefined && val !== null) {
      q = q.eq(col, val);
    }
  }

  if (order) q = q.order(order, { ascending });
  if (limit) q = q.limit(limit);
  if (offset) q = q.range(offset, offset + (limit || 20) - 1);

  const { data, error } = await q;
  if (error) throw error;
  return data || [];
}

/**
 * Tek kayıt getir (SELECT ... LIMIT 1).
 */
async function findOne(table, filters = {}) {
  let q = supabase.from(table).select('*');
  for (const [col, val] of Object.entries(filters)) {
    q = q.eq(col, val);
  }
  const { data, error } = await q.limit(1).single();
  if (error && error.code !== 'PGRST116') throw error; // PGRST116 = no rows
  return data || null;
}

/**
 * Kayıt ID ile getir.
 */
async function findById(table, id) {
  return findOne(table, { id });
}

/**
 * Yeni kayıt ekle (INSERT).
 * @returns {Promise<Object>} Eklenen kayıt
 */
async function insert(table, record) {
  const { data, error } = await supabase
    .from(table)
    .insert(record)
    .select()
    .single();
  if (error) throw error;
  return data;
}

/**
 * Toplu kayıt ekle (INSERT MANY).
 */
async function insertMany(table, records) {
  const { data, error } = await supabase
    .from(table)
    .insert(records)
    .select();
  if (error) throw error;
  return data || [];
}

/**
 * Kayıt güncelle (UPDATE).
 */
async function update(table, id, changes) {
  const { data, error } = await supabase
    .from(table)
    .update(changes)
    .eq('id', id)
    .select()
    .single();
  if (error) throw error;
  return data;
}

/**
 * Filtreli güncelle (UPDATE WHERE).
 */
async function updateWhere(table, filters, changes) {
  let q = supabase.from(table).update(changes);
  for (const [col, val] of Object.entries(filters)) {
    q = q.eq(col, val);
  }
  const { data, error } = await q.select();
  if (error) throw error;
  return data || [];
}

/**
 * Kayıt sil (DELETE).
 */
async function remove(table, id) {
  const { error } = await supabase
    .from(table)
    .delete()
    .eq('id', id);
  if (error) throw error;
  return true;
}

/**
 * Filtreli sil (DELETE WHERE).
 */
async function removeWhere(table, filters) {
  let q = supabase.from(table).delete();
  for (const [col, val] of Object.entries(filters)) {
    q = q.eq(col, val);
  }
  const { error } = await q;
  if (error) throw error;
  return true;
}

/**
 * Kayıt say (COUNT).
 */
async function count(table, filters = {}) {
  let q = supabase.from(table).select('id', { count: 'exact', head: true });
  for (const [col, val] of Object.entries(filters)) {
    q = q.eq(col, val);
  }
  const { count: c, error } = await q;
  if (error) throw error;
  return c || 0;
}

/**
 * Text search (ILIKE).
 */
async function search(table, column, searchTerm, options = {}) {
  const { select = '*', limit = 20 } = options;
  const { data, error } = await supabase
    .from(table)
    .select(select)
    .ilike(column, `%${searchTerm}%`)
    .limit(limit);
  if (error) throw error;
  return data || [];
}

/**
 * Raw Supabase query builder erişimi.
 * Karmaşık sorgular için: db.raw().from('users').select('*').or('...')
 */
function raw() {
  return supabase;
}

module.exports = {
  supabase,
  testConnection,
  query,
  findOne,
  findById,
  insert,
  insertMany,
  update,
  updateWhere,
  remove,
  removeWhere,
  count,
  search,
  raw,
};
