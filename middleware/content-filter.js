'use strict';

/**
 * Content Filter Middleware — Global Shield entegrasyonu
 *
 * Belirtilen request body alanlarını Global Shield'dan geçirir.
 * Kirli içerik tespit edilirse 400 döner, temizse next() çağrılır.
 *
 * Kullanım:
 *   router.post('/', contentFilter('title', 'description'), handler)
 *   router.patch('/', contentFilter('name', 'bio', 'username'), handler)
 */

const { shieldMultiple } = require('../lib/global-shield');

// Hata mesajları (dil-agnostik, Flutter l10n tarafında çevrilecek)
const ERROR_REASONS = {
  BANNED_WORD:           'Yasaklı içerik tespit edildi. Lütfen uygunsuz kelimeleri kaldırın.',
  OBFUSCATED_WORD:      'Gizlenmiş uygunsuz içerik tespit edildi.',
  INTENT_PHONENUMBER:    'Telefon numarası paylaşımı bu alanda yasaktır.',
  INTENT_SEXUALCONTENT:  'Cinsel içerikli ifadeler yasaktır.',
  INTENT_SPAMURL:        'Şüpheli bağlantı tespit edildi.',
};

/**
 * Belirtilen alanları filtreleyen middleware factory.
 *
 * @param {...string} fieldNames — Kontrol edilecek body alanları
 * @returns {Function} Express middleware
 */
function contentFilter(...fieldNames) {
  return (req, res, next) => {
    if (!req.body) return next();

    // Kontrol edilecek alanları topla
    const fields = {};
    for (const name of fieldNames) {
      const value = req.body[name];
      if (typeof value === 'string' && value.trim().length > 0) {
        fields[name] = value;
      }
    }

    // Hiç kontrol edilecek alan yoksa geç
    if (Object.keys(fields).length === 0) return next();

    const result = shieldMultiple(fields);

    if (!result.clean) {
      const message = ERROR_REASONS[result.reason] || ERROR_REASONS.BANNED_WORD;
      return res.status(400).json({
        message,
        error: 'CONTENT_FILTER',
        field: result.field,
        reason: result.reason,
      });
    }

    next();
  };
}

module.exports = { contentFilter };
