'use strict';
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DATA_FILE = path.join(DATA_DIR, 'store-snapshot.json');
const SAVE_INTERVAL = 30 * 1000; // 30 saniye

// Kaydedilecek collection isimleri (store.js'deki array/Set'ler)
const COLLECTIONS = [
  'users', 'listings', 'matches', 'conversations', 'messages',
  'challenges', 'notifications', 'follows', 'blockedUsers', 'reports',
  'interests', 'ratings', 'communities', 'groups', 'groupMembers',
  'posts', 'postReactions', 'comments', 'commentLikes', 'botTasks',
  'otps', 'noshows', 'botEcosystems', 'botGroups',
];

// Set olarak tutulan collection'lar
const SET_COLLECTIONS = ['refreshTokens'];

/**
 * Store verilerini JSON dosyasına kaydet.
 */
function saveSnapshot(store) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const snapshot = {};

    // Normal array collection'lar
    for (const name of COLLECTIONS) {
      if (store[name]) {
        snapshot[name] = Array.isArray(store[name]) ? store[name] : [];
      }
    }

    // Set collection'lar → array'e çevir
    for (const name of SET_COLLECTIONS) {
      if (store[name]) {
        snapshot[name] = Array.from(store[name]);
      }
    }

    // Map/Object collection'lar
    if (store.userPrivacy) {
      snapshot.userPrivacy = store.userPrivacy;
    }

    // Atomik yazma: önce temp dosyaya yaz, sonra rename
    const tmpFile = DATA_FILE + '.tmp';
    fs.writeFileSync(tmpFile, JSON.stringify(snapshot, null, 0), 'utf-8');
    fs.renameSync(tmpFile, DATA_FILE);

    const size = fs.statSync(DATA_FILE).size;
    console.log(`💾 Snapshot kaydedildi: ${(size / 1024).toFixed(1)}KB`);
    return true;
  } catch (err) {
    console.error('❌ Snapshot kaydetme hatası:', err.message);
    return false;
  }
}

/**
 * JSON dosyasından store verilerini yükle.
 */
function loadSnapshot(store) {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      console.log('📂 Snapshot dosyası bulunamadı, seed verileri kullanılacak.');
      return false;
    }

    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    const snapshot = JSON.parse(raw);

    let loadedCount = 0;

    // Normal array collection'lar
    for (const name of COLLECTIONS) {
      if (snapshot[name] && Array.isArray(snapshot[name]) && store[name]) {
        store[name].length = 0; // mevcut seed'i temizle
        store[name].push(...snapshot[name]);
        loadedCount += snapshot[name].length;
      }
    }

    // Set collection'lar
    for (const name of SET_COLLECTIONS) {
      if (snapshot[name] && Array.isArray(snapshot[name]) && store[name]) {
        store[name].clear();
        for (const item of snapshot[name]) {
          store[name].add(item);
        }
        loadedCount += snapshot[name].length;
      }
    }

    // Map/Object
    if (snapshot.userPrivacy && store.userPrivacy) {
      Object.assign(store.userPrivacy, snapshot.userPrivacy);
    }

    const size = fs.statSync(DATA_FILE).size;
    console.log(`✅ Snapshot yüklendi: ${loadedCount} kayıt, ${(size / 1024).toFixed(1)}KB`);
    return true;
  } catch (err) {
    console.error('❌ Snapshot yükleme hatası:', err.message);
    return false;
  }
}

/**
 * Periyodik kaydetme ve graceful shutdown kur.
 */
function startPersistence(store) {
  // Başlangıçta yükle
  const loaded = loadSnapshot(store);
  if (loaded) {
    console.log('📦 Önceki oturum verisi geri yüklendi.');
  }

  // Periyodik kaydet
  const intervalId = setInterval(() => saveSnapshot(store), SAVE_INTERVAL);

  // Graceful shutdown
  const shutdown = (signal) => {
    console.log(`\n🛑 ${signal} alındı, veri kaydediliyor...`);
    clearInterval(intervalId);
    saveSnapshot(store);
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  console.log(`⏱️  Otomatik kayıt: her ${SAVE_INTERVAL / 1000}sn | Dosya: ${DATA_FILE}`);
}

module.exports = { startPersistence, saveSnapshot, loadSnapshot };
