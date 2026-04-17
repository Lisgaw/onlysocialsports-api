'use strict';

/**
 * Global Shield — 11 Dilde Akıllı İçerik Filtreleme Motoru
 *
 * 3 Katmanlı Savunma:
 *   1. Trie-based Hızlı Liste (Direct Match)   — O(m) karmaşıklık (m = kelime uzunluğu)
 *   2. Karakter Hilesi Yakalayıcı (Fuzzy Match) — Normalize → Trie lookup
 *   3. Hafif Niyet Analizi (Intent Patterns)     — Regex tabanlı
 */

const bannedWords = require('./banned-words.json');

// ─── TRIE DATA STRUCTURE ───────────────────────────────────────────────────────

class TrieNode {
  constructor() {
    this.children = Object.create(null);
    this.isEnd = false;
  }
}

class Trie {
  constructor() {
    this.root = new TrieNode();
  }

  insert(word) {
    let node = this.root;
    for (const ch of word) {
      if (!node.children[ch]) node.children[ch] = new TrieNode();
      node = node.children[ch];
    }
    node.isEnd = true;
  }

  /** Kelimeyi içerip içermediğini kontrol eder (tam eşleşme) */
  contains(word) {
    let node = this.root;
    for (const ch of word) {
      if (!node.children[ch]) return false;
      node = node.children[ch];
    }
    return node.isEnd;
  }

  /**
   * Metin içinde herhangi bir yasaklı kelime var mı?
   * Kelime sınırı (word boundary) kontrolü yaparak
   * "basket" içindeki "bas" gibi yanlış pozitiflerden kaçınır.
   */
  searchInText(text) {
    const words = text.split(/[\s.,!?;:'"()\[\]{}\-_\/\\@#$%^&*+=~`|<>]+/);
    for (const word of words) {
      if (word.length < 2) continue;
      if (this.contains(word)) {
        return { found: true, matched: word };
      }
    }
    return { found: false, matched: null };
  }
}

// ─── KARAKTER HİLESİ NORMALİZER ───────────────────────────────────────────────

/**
 * Leetspeak ve karakter hileleri sözlüğü.
 * "s3x" → "sex", "f.u.c.k" → "fuck", "@ss" → "ass" vb.
 */
const CHAR_MAP = {
  '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's',
  '6': 'g', '7': 't', '8': 'b', '9': 'g',
  '@': 'a', '€': 'e', '£': 'l', '$': 's', '¢': 'c',
  '!': 'i', '|': 'l',
  'ı': 'i', 'İ': 'i',
  'ğ': 'g', 'Ğ': 'g',
  'ü': 'u', 'Ü': 'u',
  'ş': 's', 'Ş': 's',
  'ö': 'o', 'Ö': 'o',
  'ç': 'c', 'Ç': 'c',
  'â': 'a', 'ê': 'e', 'î': 'i', 'ô': 'o', 'û': 'u',
  'à': 'a', 'è': 'e', 'ì': 'i', 'ò': 'o', 'ù': 'u',
  'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
  'ä': 'a', 'ë': 'e', 'ï': 'i',
  'ñ': 'n', 'ß': 'ss',
};

/**
 * Metni normalize eder:
 * 1. Küçük harfe çevirir
 * 2. Aradaki nokta, tire, alt çizgi, yıldız gibi "ayırıcıları" siler
 * 3. Leetspeak karakterleri asıl harflerine çevirir
 * 4. Tekrarlı harfleri sıkıştırır (fuuuck → fuck)
 */
function normalizeText(text) {
  let result = text.toLowerCase();

  // Ayırıcı karakterleri sil (a.m.k → amk, f-u-c-k → fuck)
  result = result.replace(/[.\-_*~`'"+^°#]+/g, '');

  // Leetspeak & özel karakter dönüşümü
  let normalized = '';
  for (const ch of result) {
    normalized += CHAR_MAP[ch] || ch;
  }

  // Tekrarlı harfleri sıkıştır (3+ aynı harf → 1 harf)
  normalized = normalized.replace(/(.)\1{2,}/g, '$1');

  return normalized;
}

// ─── NİYET ANALİZİ ────────────────────────────────────────────────────────────

const INTENT_REGEXES = {
  phoneNumber: new RegExp(bannedWords.intentPatterns.phoneNumber, 'g'),
  sexualContent: new RegExp(bannedWords.intentPatterns.sexualContent, 'gi'),
  spamUrl: new RegExp(bannedWords.intentPatterns.spamUrl, 'gi'),
};

/**
 * Metin temiz görünse bile şüpheli kalıpları tespit eder.
 * Örn: telefon numarası paylaşımı, cinsel kalıplar, spam URL'leri.
 */
function checkIntent(text) {
  for (const [intentName, regex] of Object.entries(INTENT_REGEXES)) {
    regex.lastIndex = 0; // Reset regex state
    if (regex.test(text)) {
      return { flagged: true, intent: intentName };
    }
  }
  return { flagged: false, intent: null };
}

// ─── SHIELD MODULE BUILDER ─────────────────────────────────────────────────────

/** Tüm dillerin kelimelerini tek bir Trie'ye yükler */
function buildTrie() {
  const trie = new Trie();
  const languages = ['tr', 'en', 'de', 'fr', 'es', 'ru', 'ar', 'ja', 'pt', 'hi', 'zh'];
  let totalWords = 0;

  for (const lang of languages) {
    const words = bannedWords[lang];
    if (!Array.isArray(words)) continue;
    for (const word of words) {
      // Orijinal kelimeyi ekle
      trie.insert(word.toLowerCase());
      // Normalize edilmiş halini de ekle (fuzzy match için)
      const normalized = normalizeText(word);
      if (normalized !== word.toLowerCase()) {
        trie.insert(normalized);
      }
      totalWords++;
    }
  }

  console.log(`[GlobalShield] Trie built: ${totalWords} words from ${languages.length} languages`);
  return trie;
}

// Modül yüklendiğinde Trie'yi bir kere oluştur (startup)
const globalTrie = buildTrie();

// ─── PUBLIC API ────────────────────────────────────────────────────────────────

/**
 * Ana filtre fonksiyonu: Metni 3 katmandan geçirir.
 *
 * @param {string} text — Kontrol edilecek metin
 * @returns {{ clean: boolean, reason?: string, matched?: string }}
 *
 * Performans: Trie lookup O(m), normalize O(n), intent regex O(n)
 * Toplam: O(n) — n = metin uzunluğu
 */
function shield(text) {
  if (!text || typeof text !== 'string') return { clean: true };

  const lowerText = text.toLowerCase();

  // ── Katman 1: Hızlı Liste (Direct Match) ──
  const directResult = globalTrie.searchInText(lowerText);
  if (directResult.found) {
    return { clean: false, reason: 'BANNED_WORD', matched: directResult.matched };
  }

  // ── Katman 2: Karakter Hilesi (Fuzzy Match) ──
  const normalizedText = normalizeText(text);
  if (normalizedText !== lowerText) {
    const fuzzyResult = globalTrie.searchInText(normalizedText);
    if (fuzzyResult.found) {
      return { clean: false, reason: 'OBFUSCATED_WORD', matched: fuzzyResult.matched };
    }
  }

  // ── Katman 3: Niyet Analizi ──
  const intentResult = checkIntent(lowerText);
  if (intentResult.flagged) {
    return { clean: false, reason: 'INTENT_' + intentResult.intent.toUpperCase(), matched: intentResult.intent };
  }

  return { clean: true };
}

/**
 * Birden fazla alanı tek seferde kontrol eder.
 *
 * @param {Object} fields — { fieldName: fieldValue, ... }
 * @returns {{ clean: boolean, field?: string, reason?: string, matched?: string }}
 */
function shieldMultiple(fields) {
  for (const [fieldName, value] of Object.entries(fields)) {
    if (typeof value !== 'string') continue;
    const result = shield(value);
    if (!result.clean) {
      return { clean: false, field: fieldName, reason: result.reason, matched: result.matched };
    }
  }
  return { clean: true };
}

module.exports = { shield, shieldMultiple, normalizeText, globalTrie };
