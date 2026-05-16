'use strict';
/**
 * Sports Partner API â€” Production Server (Supabase-backed)
 *
 * Vercel Serverless Function entry point.
 * ALL routes use Supabase PostgreSQL instead of in-memory store.
 * WebSocket NOT supported on Vercel â€” HTTP-only.
 */

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const bcrypt     = require('bcryptjs');
const { v4: uuid } = require('uuid');
const compression = require('compression');
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');

// â”€â”€ Supabase â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const db = require('../db/supabase');
const { toCamel, toSnake, toUserResponse, fromUserBody, parsePagination } = require('../db/helpers');
const { generateTokens, verifyRefreshToken, authMiddleware } = require('../middleware/auth');

let contentFilterFn;
try { contentFilterFn = require('../middleware/content-filter').contentFilter; } catch { contentFilterFn = null; }
const contentFilter = contentFilterFn || ((..._f) => (_req, _res, next) => next());

const app = express();

const DEFAULT_CORS_ALLOWED_ORIGINS = [
  'https://onlysocialsport.com',
  'https://www.onlysocialsport.com',
  'https://api.onlysocialsport.com',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

function splitAllowlist(raw) {
  return String(raw || '')
    .split(/[\n,;\s]+/)
    .map(v => v.trim())
    .filter(Boolean);
}

const CORS_ALLOW_ALL = String(process.env.CORS_ALLOW_ALL || '').trim().toLowerCase() === 'true';
const CORS_ALLOWED_ORIGINS = (() => {
  const envValues = splitAllowlist(process.env.CORS_ALLOWED_ORIGINS || process.env.CORS_ORIGIN_ALLOWLIST);
  if (envValues.length > 0) return envValues;
  return DEFAULT_CORS_ALLOWED_ORIGINS;
})();

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function originMatchesPattern(origin, pattern) {
  if (!pattern) return false;
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return origin === pattern;

  const regex = new RegExp(`^${escapeRegex(pattern).replace(/\\\*/g, '.*')}$`);
  return regex.test(origin);
}

function isOriginAllowed(origin) {
  if (CORS_ALLOW_ALL) return true;
  if (!origin) return true; // Native mobile / server-to-server requests may omit Origin.

  for (const allowedOrigin of CORS_ALLOWED_ORIGINS) {
    if (originMatchesPattern(origin, allowedOrigin)) return true;
  }

  return false;
}

const corsOptions = {
  origin(origin, callback) {
    const allowed = isOriginAllowed(origin);
    if (!allowed && origin) {
      console.warn('cors blocked origin:', origin);
    }
    callback(null, allowed);
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 'Authorization',
    'X-API-Version', 'X-Client-Type',
  ],
  exposedHeaders: ['Content-Length'],
  optionsSuccessStatus: 204,
};

// â”€â”€ Middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// compression removed â€” Vercel CDN handles gzip/brotli automatically
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: false,  // CORP: same-origin Flutter web'i engelliyordu
  crossOriginOpenerPolicy: false,    // COOP: same-origin Flutter web'i engelliyordu
}));
app.use(cors(corsOptions));
// OPTIONS preflight isteklerini hemen yanÄ±tla (helmet/cors Ã¶nce ele alÄ±r)
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '500kb' }));

// â”€â”€ Rate Limiting (in-memory, per-instance) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX) || 300;
const rateBuckets = new Map();
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.ip || 'unknown';
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.start > 60000) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > RATE_LIMIT_MAX) return res.status(429).json({ message: 'Rate limit exceeded.' });
  next();
});
// setInterval removed â€” serverless functions don't persist between invocations
// Rate buckets auto-expire via the check in the middleware above

// â”€â”€ Brute Force Protection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const loginAttempts = new Map();
const LOGIN_MAX = 5;
const LOGIN_WINDOW = 15 * 60 * 1000;

const PASSWORD_RESET_CODE_TTL_MINUTES = Math.max(
  1,
  Number.parseInt(process.env.PASSWORD_RESET_CODE_TTL_MINUTES || '15', 10) || 15,
);
const PASSWORD_RESET_CODE_TTL_MS = PASSWORD_RESET_CODE_TTL_MINUTES * 60 * 1000;
const PASSWORD_RESET_MIN_PASSWORD_LENGTH = Math.max(
  6,
  Number.parseInt(process.env.PASSWORD_RESET_MIN_PASSWORD_LENGTH || '8', 10) || 8,
);
const PASSWORD_RESET_RATE_WINDOW_MS = Math.max(
  60 * 1000,
  Number.parseInt(process.env.PASSWORD_RESET_RATE_WINDOW_MS || `${15 * 60 * 1000}`, 10)
    || (15 * 60 * 1000),
);
const PASSWORD_RESET_MAX_PER_IP = Math.max(
  1,
  Number.parseInt(process.env.PASSWORD_RESET_MAX_PER_IP || '20', 10) || 20,
);
const PASSWORD_RESET_MAX_PER_EMAIL = Math.max(
  1,
  Number.parseInt(process.env.PASSWORD_RESET_MAX_PER_EMAIL || '5', 10) || 5,
);
const PASSWORD_RESET_VERIFY_MAX_PER_IP = Math.max(
  1,
  Number.parseInt(process.env.PASSWORD_RESET_VERIFY_MAX_PER_IP || '25', 10) || 25,
);
const PASSWORD_RESET_VERIFY_MAX_PER_TOKEN = Math.max(
  1,
  Number.parseInt(process.env.PASSWORD_RESET_VERIFY_MAX_PER_TOKEN || '10', 10) || 10,
);

const passwordResetRequestBucketsByIp = new Map();
const passwordResetRequestBucketsByEmail = new Map();
const passwordResetVerifyBucketsByIp = new Map();
const passwordResetVerifyBucketsByToken = new Map();

let passwordResetMailerInitialized = false;
let passwordResetMailer = null;
let hasAuthAuditLogsTable = true;

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function sanitize(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const r = {};
  for (const [k, v] of Object.entries(obj))
    r[k] = typeof v === 'string' ? v.replace(/[<>]/g, '') : v;
  return r;
}

function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

function getRequestIp(req) {
  const forwarded = req?.headers?.['x-forwarded-for'];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const ip = String(raw || req?.ip || req?.socket?.remoteAddress || '')
    .split(',')[0]
    .trim();
  return ip || 'unknown';
}

function consumeRateLimitBucket(store, key, { windowMs, max }) {
  if (!key) return { allowed: true, count: 0, retryAfterMs: 0 };

  const now = Date.now();
  let bucket = store.get(key);
  if (!bucket || (now - bucket.start) >= windowMs) {
    bucket = { start: now, count: 0 };
  }

  bucket.count += 1;
  store.set(key, bucket);

  return {
    allowed: bucket.count <= max,
    count: bucket.count,
    retryAfterMs: Math.max(0, windowMs - (now - bucket.start)),
  };
}

function isMissingTable(error, tableName) {
  const msg = String(error?.message || '').toLowerCase();
  if (!msg) return false;

  const table = String(tableName || '').toLowerCase();
  if (table && !msg.includes(table)) return false;

  return (
    msg.includes('does not exist') ||
    msg.includes('could not find') ||
    msg.includes('relation')
  );
}

function maybeString(value, maxLength = 1000) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.length > maxLength ? text.slice(0, maxLength) : text;
}

function getPasswordResetMailer() {
  if (passwordResetMailerInitialized) return passwordResetMailer;
  passwordResetMailerInitialized = true;

  const host = String(process.env.SMTP_HOST || '').trim();
  const port = Number.parseInt(process.env.SMTP_PORT || '587', 10);
  const user = String(process.env.SMTP_USER || '').trim();
  const pass = String(process.env.SMTP_PASS || '').trim();

  if (!host || !Number.isFinite(port) || port <= 0 || !user || !pass) {
    passwordResetMailer = null;
    return null;
  }

  const secureRaw = String(process.env.SMTP_SECURE || '').trim().toLowerCase();
  const secure = secureRaw ? secureRaw === 'true' : port === 465;

  passwordResetMailer = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });

  return passwordResetMailer;
}

function isPasswordResetEmailConfigured() {
  const fromAddress = String(process.env.SMTP_FROM || process.env.SMTP_USER || '').trim();
  return !!getPasswordResetMailer() && !!fromAddress;
}

function buildPasswordResetUrl({ email, token, code }) {
  const baseUrl = String(process.env.PASSWORD_RESET_URL || '').trim();
  if (!baseUrl) return '';
  const separator = baseUrl.includes('?') ? '&' : '?';
  return `${baseUrl}${separator}token=${encodeURIComponent(token)}&code=${encodeURIComponent(code)}&email=${encodeURIComponent(email)}`;
}

async function sendPasswordResetEmail({ email, name, token, code }) {
  const transporter = getPasswordResetMailer();
  const fromAddress = String(process.env.SMTP_FROM || process.env.SMTP_USER || '').trim();
  if (!transporter || !fromAddress) {
    return { ok: false, code: 'smtp_not_configured', message: 'SMTP is not configured.' };
  }

  const fromName = String(process.env.SMTP_FROM_NAME || 'SporPartner').trim();
  const from = fromName ? `${fromName} <${fromAddress}>` : fromAddress;
  const resetUrl = buildPasswordResetUrl({ email, token, code });
  const greetingName = maybeString(name, 80) || 'Merhaba';

  const textLines = [
    `${greetingName},`,
    '',
    'SporPartner hesabin icin sifre sifirlama talebi aldik.',
    `Dogrulama kodun: ${code}`,
    `Kod gecerlilik suresi: ${PASSWORD_RESET_CODE_TTL_MINUTES} dakika.`,
  ];
  if (resetUrl) {
    textLines.push('', `Sifirlama baglantisi: ${resetUrl}`);
  }
  textLines.push('', 'Bu talebi sen yapmadiysan bu e-postayi yok sayabilirsin.');

  const htmlParts = [
    `<p>${greetingName},</p>`,
    '<p>SporPartner hesabin icin sifre sifirlama talebi aldik.</p>',
    `<p><strong>Dogrulama kodun: ${code}</strong></p>`,
    `<p>Kod gecerlilik suresi: ${PASSWORD_RESET_CODE_TTL_MINUTES} dakika.</p>`,
  ];
  if (resetUrl) {
    htmlParts.push(`<p><a href="${resetUrl}">Sifreyi sifirlamak icin tikla</a></p>`);
  }
  htmlParts.push('<p>Bu talebi sen yapmadiysan bu e-postayi yok sayabilirsin.</p>');

  try {
    await transporter.sendMail({
      from,
      to: email,
      subject: 'SporPartner sifre sifirlama kodu',
      text: textLines.join('\n'),
      html: htmlParts.join(''),
    });
    return { ok: true, code: 'sent', message: null };
  } catch (error) {
    return {
      ok: false,
      code: 'smtp_send_failed',
      message: error?.message || String(error),
    };
  }
}

async function writeAuthAuditLog(req, {
  eventType,
  userId = null,
  email = null,
  success = true,
  reason = '',
  metadata = {},
} = {}) {
  if (!eventType || !hasAuthAuditLogsTable) return;

  const client = db.raw();
  if (!client) return;

  const payload = {
    id: `audit_${uuid()}`,
    event_type: eventType,
    user_id: userId || null,
    email: normalizeEmail(email) || null,
    ip_address: maybeString(getRequestIp(req), 64),
    user_agent: maybeString(req?.headers?.['user-agent'], 512),
    success: success !== false,
    reason: maybeString(reason, 255),
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
    created_at: new Date().toISOString(),
  };

  try {
    const { error } = await client.from('auth_audit_logs').insert(payload);
    if (!error) return;

    if (isMissingTable(error, 'auth_audit_logs')) {
      hasAuthAuditLogsTable = false;
      return;
    }

    throw error;
  } catch (error) {
    console.warn('auth audit log write warning:', error?.message || error);
  }
}

const SOCIAL_PLATFORMS = [
  'instagram','tiktok','facebook','twitter','youtube','linkedin',
  'discord','twitch','snapchat','telegram','whatsapp','vk','litmatch'
];
const BOT_SOCIAL_PLATFORM_POOL = ['instagram', 'youtube', 'telegram', 'vk', 'tiktok', 'twitter'];

function hashText(seed = '') {
  let h = 0;
  const s = String(seed || '');
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) - h + s.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

function seededInt(seed, min, max) {
  const lo = Number(min);
  const hi = Number(max);
  if (!Number.isFinite(lo) || !Number.isFinite(hi) || hi <= lo) return lo;
  return lo + (hashText(seed) % (hi - lo + 1));
}

function normalizedHandleBase(name) {
  const raw = String(name || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  return raw.length >= 3 ? raw : 'sportbot';
}

function buildBotSocialLinks({ botName, citySeed, countryCode, botIndex = 0, botId = '' }) {
  const links = {};
  for (const p of SOCIAL_PLATFORMS) links[p] = null;

  const seedBase = `${botId}-${botName}-${citySeed}-${countryCode || ''}-${botIndex}`;
  const base = normalizedHandleBase(botName);
  const selectedPlatforms = [...BOT_SOCIAL_PLATFORM_POOL]
    .sort((a, b) => hashText(`${seedBase}-${a}`) - hashText(`${seedBase}-${b}`))
    .slice(0, 3);

  for (const platform of selectedPlatforms) {
    const suffix = seededInt(`${seedBase}-${platform}-suffix`, 100, 99999);
    links[platform] = `${base}_${suffix}`.slice(0, 28);
  }
  return links;
}

function buildBotAudience({ botName, citySeed, countryCode, botIndex = 0, botId = '' }) {
  const seedBase = `${botId}-${botName}-${citySeed}-${countryCode || ''}-${botIndex}`;
  return {
    followerCount: seededInt(`${seedBase}-followers`, 400, 500),
    followingCount: seededInt(`${seedBase}-following`, 400, 500),
  };
}

function countBotSocialLinks(row) {
  let count = 0;
  for (const p of SOCIAL_PLATFORMS) {
    const v = row?.[p];
    const hasValue = typeof v === 'string' ? v.trim().length > 0 : !!v;
    if (hasValue) count++;
  }
  return count;
}

function buildBotPublicPersona({ botName, citySeed, countryCode, botIndex = 0, botId = '' }) {
  const socialLinks = buildBotSocialLinks({ botName, citySeed, countryCode, botIndex, botId });
  const audience = buildBotAudience({ botName, citySeed, countryCode, botIndex, botId });
  return {
    socialLinks,
    followerCount: audience.followerCount,
    followingCount: audience.followingCount,
  };
}

const REQUIRED_LISTING_SPORTS = [
  { id: 'okey', name: 'Okey', icon: 'ï¿½', category: 'Masa SporlarÄ±' },
  { id: 'tavla', name: 'Tavla', icon: 'ğŸ²', category: 'Masa SporlarÄ±' },
  { id: 'satranc', name: 'SatranÃ§', icon: 'â™Ÿï¸', category: 'Masa SporlarÄ±' },
  { id: 'karting', name: 'Karting', icon: 'ğŸï¸', category: 'Motor SporlarÄ±' },
];

const SPORT_ICON_UPDATES = [
  { id: 'hiking', icon: 'ğŸš¶' },
  { id: 'skateboarding', icon: 'ğŸ‚' },
  { id: 'okey', icon: '🃏' },
];

let sportIconsEnsured = false;

async function ensureSportIcons() {
  if (sportIconsEnsured) return;
  try {
    const client = db.raw();
    if (!client) return;
    for (const item of SPORT_ICON_UPDATES) {
      await client.from('sports').update({ icon: item.icon }).eq('id', item.id);
    }
    sportIconsEnsured = true;
  } catch (error) {
    console.error('ensureSportIcons error:', error?.message || error);
  }
}

let requiredListingSportsEnsured = false;

async function ensureRequiredListingSports() {
  if (requiredListingSportsEnsured) return;

  try {
    const client = db.raw();
    if (!client) return;

    const requiredIds = REQUIRED_LISTING_SPORTS.map(item => item.id);
    const { data: existing, error: readError } = await client
      .from('sports')
      .select('id')
      .in('id', requiredIds);
    if (readError) throw readError;

    const existingIds = new Set((existing || []).map(row => row.id));
    const missing = REQUIRED_LISTING_SPORTS.filter(item => !existingIds.has(item.id));
    if (missing.length === 0) {
      requiredListingSportsEnsured = true;
      return;
    }

    const { error: insertError } = await client.from('sports').insert(
      missing.map(item => ({
        id: item.id,
        name: item.name,
        icon: item.icon,
        category: item.category,
      }))
    );

    // Unique conflict olursa baÅŸka bir request aynÄ± anda eklemiÅŸ olabilir.
    if (insertError && insertError.code !== '23505') throw insertError;

    requiredListingSportsEnsured = true;
  } catch (error) {
    console.error('ensureRequiredListingSports error:', error?.message || error);
  }
}

function buildBotBaselinePatch({ bot, eco, botIndex = 0 }) {
  const patch = {};
  const seedCity = bot.city_id || eco.city_id || bot.city || eco.city_name || 'city';
  const persona = buildBotPublicPersona({
    botName: bot.name,
    citySeed: seedCity,
    countryCode: bot.country_code || eco.country_code,
    botIndex,
    botId: bot.id,
  });

  const followerCount = Number(bot.follower_count || 0);
  if (followerCount < 400 || followerCount > 500) {
    patch.follower_count = persona.followerCount;
  }
  const followingCount = Number(bot.following_count || 0);
  if (followingCount < 400 || followingCount > 500) {
    patch.following_count = persona.followingCount;
  }

  let socialCount = countBotSocialLinks(bot);
  if (socialCount < 3) {
    for (const platform of BOT_SOCIAL_PLATFORM_POOL) {
      const existing = bot[platform];
      const hasExisting = typeof existing === 'string' ? existing.trim().length > 0 : !!existing;
      if (hasExisting) continue;

      const candidate = persona.socialLinks[platform];
      if (!candidate) continue;
      patch[platform] = candidate;
      socialCount++;
      if (socialCount >= 3) break;
    }
  }

  return patch;
}

function normalizeVisibility(v, fallback = 'EVERYONE') {
  const raw = String(v || '').toUpperCase();
  if (raw === 'PUBLIC' || raw === 'EVERYONE') return 'EVERYONE';
  if (raw === 'FOLLOWERS' || raw === 'FRIENDS' || raw === 'PRIVATE') return 'FOLLOWERS';
  if (raw === 'NOBODY' || raw === 'NONE') return 'NOBODY';
  return fallback;
}

function normalizePrivacy(input = {}) {
  const socialRaw = input.socialPlatformVisibility && typeof input.socialPlatformVisibility === 'object'
    ? input.socialPlatformVisibility : {};
  const socialPlatformVisibility = {};
  for (const p of SOCIAL_PLATFORMS)
    socialPlatformVisibility[p] = normalizeVisibility(
      socialRaw[p],
      normalizeVisibility(input.socialLinksVisibility, 'EVERYONE')
    );
  return {
    profileVisibility: normalizeVisibility(input.profileVisibility, 'EVERYONE'),
    showOnlineStatus: input.showOnlineStatus !== false,
    allowMessages: normalizeVisibility(input.allowMessages || input.whoCanMessage, 'EVERYONE'),
    showLocation: input.showLocation !== false,
    showSports: input.showSports !== false,
    showOnLeaderboard: input.showOnLeaderboard !== false,
    isPrivateProfile: input.isPrivateProfile === true,
    socialLinksVisibility: normalizeVisibility(input.socialLinksVisibility, 'EVERYONE'),
    whoCanSeeMyInterests: normalizeVisibility(input.whoCanSeeMyInterests, 'EVERYONE'),
    whoCanMessage: normalizeVisibility(input.whoCanMessage || input.allowMessages, 'EVERYONE'),
    whoCanChallenge: normalizeVisibility(input.whoCanChallenge, 'EVERYONE'),
    whoCanSeeSportListings: normalizeVisibility(input.whoCanSeeSportListings, 'EVERYONE'),
    whoCanSeeSocialListings: normalizeVisibility(input.whoCanSeeSocialListings, 'EVERYONE'),
    socialPlatformVisibility,
  };
}

function legacyVisibilityToModern(v, fallback = 'EVERYONE') {
  const raw = String(v || '').toUpperCase();
  if (raw === 'PUBLIC' || raw === 'EVERYONE') return 'EVERYONE';
  if (raw === 'FOLLOWERS_ONLY' || raw === 'FOLLOWERS' || raw === 'FRIENDS') return 'FOLLOWERS';
  if (raw === 'PRIVATE' || raw === 'NOBODY' || raw === 'NONE') return 'NOBODY';
  return fallback;
}

function modernVisibilityToLegacy(v, kind = 'generic') {
  const modern = normalizeVisibility(v, 'EVERYONE');
  if (kind === 'profile') {
    if (modern === 'FOLLOWERS') return 'FOLLOWERS_ONLY';
    if (modern === 'NOBODY') return 'PRIVATE';
    return 'PUBLIC';
  }
  if (modern === 'FOLLOWERS') return 'FOLLOWERS';
  if (modern === 'NOBODY') return 'NOBODY';
  return 'EVERYONE';
}

const LEGACY_SPV_MARKER = '|SPV|';

function decodeLegacyAllowMessages(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) {
    return {
      whoCanMessage: 'EVERYONE',
      socialPlatformVisibility: null,
      socialDefaultVisibility: null,
    };
  }

  const markerIdx = raw.indexOf(LEGACY_SPV_MARKER);
  if (markerIdx < 0) {
    return {
      whoCanMessage: legacyVisibilityToModern(raw, 'EVERYONE'),
      socialPlatformVisibility: null,
      socialDefaultVisibility: null,
    };
  }

  const basePart = raw.slice(0, markerIdx);
  const encodedPart = raw.slice(markerIdx + LEGACY_SPV_MARKER.length);

  let socialPlatformVisibility = null;
  let socialDefaultVisibility = null;
  if (encodedPart) {
    try {
      const json = Buffer.from(encodedPart, 'base64').toString('utf8');
      const parsed = JSON.parse(json);
      if (parsed && typeof parsed === 'object') {
        socialDefaultVisibility = normalizeVisibility(parsed._default, 'EVERYONE');
        const map = {};
        for (const p of SOCIAL_PLATFORMS) {
          if (!Object.prototype.hasOwnProperty.call(parsed, p)) continue;
          map[p] = normalizeVisibility(parsed[p], socialDefaultVisibility);
        }
        socialPlatformVisibility = map;
      } else {
        socialPlatformVisibility = null;
      }
    } catch {
      socialPlatformVisibility = null;
      socialDefaultVisibility = null;
    }
  }

  return {
    whoCanMessage: legacyVisibilityToModern(basePart, 'EVERYONE'),
    socialPlatformVisibility,
    socialDefaultVisibility,
  };
}

function encodeLegacyAllowMessages(whoCanMessage, socialPlatformVisibility, socialDefaultVisibility = 'EVERYONE') {
  const base = modernVisibilityToLegacy(whoCanMessage, 'generic');
  const defaultVisibility = normalizeVisibility(socialDefaultVisibility, 'EVERYONE');
  const compact = {};

  if (defaultVisibility !== 'EVERYONE') {
    compact._default = defaultVisibility;
  }

  for (const p of SOCIAL_PLATFORMS) {
    const v = normalizeVisibility(socialPlatformVisibility?.[p], defaultVisibility);
    if (v !== defaultVisibility) compact[p] = v;
  }

  if (Object.keys(compact).length === 0) return base;
  const encoded = Buffer.from(JSON.stringify(compact), 'utf8').toString('base64');
  return `${base}${LEGACY_SPV_MARKER}${encoded}`;
}

function buildLegacyPrivacyPatch(input = {}) {
  return {
    profile_visibility: modernVisibilityToLegacy(input.profileVisibility, 'profile'),
    show_online_status: input.showOnlineStatus !== false,
    show_sports: input.showSports !== false,
    show_location: input.showLocation !== false,
    show_social_links: normalizeVisibility(input.socialLinksVisibility, 'EVERYONE') !== 'NOBODY',
    allow_messages_from: encodeLegacyAllowMessages(
      input.whoCanMessage || input.allowMessages,
      input.socialPlatformVisibility,
      input.socialLinksVisibility
    ),
    updated_at: new Date().toISOString(),
  };
}

const privacyDefaults = () => normalizePrivacy({});

async function canViewerSee(viewerId, ownerId, visibility) {
  const rule = normalizeVisibility(visibility, 'EVERYONE');
  if (viewerId && ownerId && viewerId === ownerId) return true;
  if (rule === 'NOBODY') return false;
  if (rule === 'EVERYONE') return true;
  // FOLLOWERS â€” check if viewer follows owner
  const f = await db.findOne('follows', { follower_id: viewerId, following_id: ownerId });
  return f?.status === 'accepted';
}

async function getPrivacy(userId) {
  const row = await db.findOne('user_privacy', { user_id: userId });
  if (!row) return privacyDefaults();
  const hasSettingsColumn = Object.prototype.hasOwnProperty.call(row, 'settings');
  if (hasSettingsColumn && row.settings) {
    const settings = row.settings;
    return normalizePrivacy(typeof settings === 'string' ? JSON.parse(settings) : settings);
  }

  const decodedLegacy = decodeLegacyAllowMessages(row.allow_messages_from);
  const legacyMap = decodedLegacy.socialPlatformVisibility || {};
  const legacyMapSize = Object.keys(legacyMap).length;

  let legacySocialDefault = decodedLegacy.socialDefaultVisibility;
  if (!legacySocialDefault) {
    legacySocialDefault = row.show_social_links === false ? 'NOBODY' : 'EVERYONE';

    // Backward compatibility for old encoded payloads (without _default marker):
    // if global legacy value says NOBODY but encoded map is partial, missing keys
    // were previously intended to stay EVERYONE.
    if (
      legacySocialDefault === 'NOBODY' &&
      legacyMapSize > 0 &&
      legacyMapSize < SOCIAL_PLATFORMS.length
    ) {
      legacySocialDefault = 'EVERYONE';
    }
  }

  // Legacy schema fallback: map flat columns into modern privacy shape.
  return normalizePrivacy({
    profileVisibility: legacyVisibilityToModern(row.profile_visibility, 'EVERYONE'),
    showOnlineStatus: row.show_online_status !== false,
    showLocation: row.show_location !== false,
    showSports: row.show_sports !== false,
    showOnLeaderboard: row.show_statistics !== false,
    isPrivateProfile: legacyVisibilityToModern(row.profile_visibility, 'EVERYONE') === 'NOBODY',
    socialLinksVisibility: legacySocialDefault,
    whoCanMessage: decodedLegacy.whoCanMessage,
    allowMessages: decodedLegacy.whoCanMessage,
    socialPlatformVisibility: legacyMap,
  });
}

async function pushNotification(n) {
  const notif = {
    id: uuid(),
    user_id: n.userId,
    type: n.type,
    title: n.title,
    body: n.body,
    related_id: n.relatedId || null,
    link: n.link || null,
    sender_id: n.senderId || null,
    sender_name: n.senderName || null,
    sender_avatar: n.senderAvatar || null,
    is_read: false,
  };

  let inserted = true;
  try {
    await db.insert('notifications', notif);
  } catch (e) {
    inserted = false;
    console.error('notif insert err:', e.message);
  }

  if (inserted) {
    try {
      await sendPushForNotification(notif);
    } catch (e) {
      console.error('push send err:', e?.message || e);
    }
  }

  return toCamel(notif);
}

const PUSH_PLATFORM_ALLOWLIST = new Set(['android', 'ios', 'web']);
const PUSH_LOCALE_ALLOWLIST = new Set(['tr', 'en', 'ar', 'de', 'es', 'fr', 'pt', 'ru', 'ja', 'zh', 'hi', 'bn']);
const COUNTRY_TO_PUSH_LOCALE = Object.freeze({
  TR: 'tr',
  EN: 'en',
  US: 'en',
  GB: 'en',
  AU: 'en',
  CA: 'en',
  IE: 'en',
  NZ: 'en',
  AR: 'ar',
  SA: 'ar',
  AE: 'ar',
  DE: 'de',
  AT: 'de',
  CH: 'de',
  ES: 'es',
  MX: 'es',
  FR: 'fr',
  BE: 'fr',
  PT: 'pt',
  BR: 'pt',
  RU: 'ru',
  JA: 'ja',
  JP: 'ja',
  ZH: 'zh',
  CN: 'zh',
  TW: 'zh',
  HI: 'hi',
  IN: 'hi',
  BN: 'bn',
  BD: 'bn',
});
const DIRECT_CHALLENGE_COPY = Object.freeze({
  tr: {
    rivalTitle: '\u2694\uFE0F Rakip Teklifi!',
    partnerTitle: '\uD83E\uDD1D Partner Teklifi!',
    bodyTemplate: '{sender} sana {sport} teklifi g\u00F6nderdi.',
    senderFallback: 'Birisi',
    sportFallback: 'spor',
  },
  en: {
    rivalTitle: '\u2694\uFE0F Rival Offer!',
    partnerTitle: '\uD83E\uDD1D Partner Offer!',
    bodyTemplate: '{sender} sent you a {sport} offer.',
    senderFallback: 'Someone',
    sportFallback: 'sport',
  },
  ar: {
    rivalTitle: '\u2694\uFE0F عرض منافس!',
    partnerTitle: '\uD83E\uDD1D عرض شريك!',
    bodyTemplate: '{sender} ارسل لك عرض {sport}.',
    senderFallback: 'شخص ما',
    sportFallback: 'رياضة',
  },
  de: {
    rivalTitle: '\u2694\uFE0F Rivalen-Angebot!',
    partnerTitle: '\uD83E\uDD1D Partner-Angebot!',
    bodyTemplate: '{sender} hat dir ein {sport}-Angebot gesendet.',
    senderFallback: 'Jemand',
    sportFallback: 'Sport',
  },
  es: {
    rivalTitle: '\u2694\uFE0F Oferta de rival!',
    partnerTitle: '\uD83E\uDD1D Oferta de companero!',
    bodyTemplate: '{sender} te envio una oferta de {sport}.',
    senderFallback: 'Alguien',
    sportFallback: 'deporte',
  },
  fr: {
    rivalTitle: '\u2694\uFE0F Offre de rival!',
    partnerTitle: '\uD83E\uDD1D Offre de partenaire!',
    bodyTemplate: '{sender} vous a envoye une offre de {sport}.',
    senderFallback: 'Quelqu\'un',
    sportFallback: 'sport',
  },
  pt: {
    rivalTitle: '\u2694\uFE0F Oferta de rival!',
    partnerTitle: '\uD83E\uDD1D Oferta de parceiro!',
    bodyTemplate: '{sender} enviou uma oferta de {sport} para voce.',
    senderFallback: 'Alguem',
    sportFallback: 'esporte',
  },
  ru: {
    rivalTitle: '\u2694\uFE0F Предложение соперника!',
    partnerTitle: '\uD83E\uDD1D Предложение партнера!',
    bodyTemplate: '{sender} отправил(а) вам предложение по {sport}.',
    senderFallback: 'Кто-то',
    sportFallback: 'спорт',
  },
  ja: {
    rivalTitle: '\u2694\uFE0F ライバルオファー！',
    partnerTitle: '\uD83E\uDD1D パートナーオファー！',
    bodyTemplate: '{sender} が {sport} のオファーを送りました。',
    senderFallback: 'だれか',
    sportFallback: 'スポーツ',
  },
  zh: {
    rivalTitle: '\u2694\uFE0F 对手邀请！',
    partnerTitle: '\uD83E\uDD1D 搭档邀请！',
    bodyTemplate: '{sender} 向你发送了 {sport} 邀请。',
    senderFallback: '有人',
    sportFallback: '运动',
  },
  hi: {
    rivalTitle: '\u2694\uFE0F प्रतिद्वंद्वी ऑफर!',
    partnerTitle: '\uD83E\uDD1D पार्टनर ऑफर!',
    bodyTemplate: '{sender} ने आपको {sport} का ऑफर भेजा।',
    senderFallback: 'कोई',
    sportFallback: 'खेल',
  },
  bn: {
    rivalTitle: '\u2694\uFE0F প্রতিদ্বন্দ্বী অফার!',
    partnerTitle: '\uD83E\uDD1D পার্টনার অফার!',
    bodyTemplate: '{sender} আপনাকে {sport} অফার পাঠিয়েছে।',
    senderFallback: 'কেউ',
    sportFallback: 'খেলা',
  },
});
const FCM_LEGACY_ENDPOINT = 'https://fcm.googleapis.com/fcm/send';
const FCM_OAUTH_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const FCM_OAUTH_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const PUSH_FCM_TIMEOUT_MS = Number.parseInt(process.env.PUSH_FCM_TIMEOUT_MS || '8000', 10);
const PUSH_FCM_TOKEN_REFRESH_SKEW_MS = 60 * 1000;
const INVALID_PUSH_TOKEN_ERRORS = new Set([
  'NotRegistered',
  'InvalidRegistration',
  'MismatchSenderId',
  'registration-token-not-registered',
  'UNREGISTERED',
]);
const PUSH_TELEMETRY_ENABLED = new Set(['1', 'true', 'yes', 'on']).has(
  String(process.env.PUSH_TELEMETRY_LOG || process.env.PUSH_TELEMETRY_ENABLED || '')
    .trim()
    .toLowerCase(),
);

let firebaseServiceAccountCache;
let firebaseAccessTokenCache = {
  token: '',
  expiresAt: 0,
};

function maskPushTokenForLogs(token) {
  const clean = normalizePushToken(token);
  if (!clean) return '';
  if (clean.length <= 12) return clean;
  return `${clean.slice(0, 8)}...${clean.slice(-4)}`;
}

function clipForLogs(value, max = 220) {
  const text = String(value || '');
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
}

function logPushTelemetry(event, payload = {}) {
  if (!PUSH_TELEMETRY_ENABLED) return;
  try {
    console.log('[PUSH_TELEMETRY]', JSON.stringify({
      event,
      ts: new Date().toISOString(),
      ...payload,
    }));
  } catch (error) {
    console.log('[PUSH_TELEMETRY]', event, payload, error?.message || error);
  }
}

function normalizePushToken(token) {
  if (typeof token !== 'string') return '';
  return token.trim();
}

function normalizePushPlatform(platform) {
  const normalized = typeof platform === 'string' ? platform.trim().toLowerCase() : 'android';
  if (!normalized) return 'android';
  return PUSH_PLATFORM_ALLOWLIST.has(normalized) ? normalized : 'android';
}

function normalizePushLocale(locale, fallback = '') {
  const normalized = String(locale || '').trim().toLowerCase().split(/[-_]/)[0];
  if (PUSH_LOCALE_ALLOWLIST.has(normalized)) return normalized;

  const countryCode = String(locale || '').trim().toUpperCase();
  if (COUNTRY_TO_PUSH_LOCALE[countryCode]) return COUNTRY_TO_PUSH_LOCALE[countryCode];

  const normalizedFallback = String(fallback || '').trim().toLowerCase().split(/[-_]/)[0];
  if (PUSH_LOCALE_ALLOWLIST.has(normalizedFallback)) return normalizedFallback;

  return '';
}

function encodeLegacyPlatformWithLocale(platform, locale) {
  const normalizedPlatform = normalizePushPlatform(platform);
  const normalizedLocale = normalizePushLocale(locale, '');
  if (!normalizedLocale) return normalizedPlatform;
  return `${normalizedPlatform}|${normalizedLocale}`;
}

function decodeLegacyPlatformWithLocale(platformValue) {
  const raw = String(platformValue || '').trim();
  if (!raw) return { platform: 'android', locale: '' };

  const [platformPart, localePart] = raw.split('|');
  return {
    platform: normalizePushPlatform(platformPart),
    locale: normalizePushLocale(localePart, ''),
  };
}

function isMissingColumn(error, columnName) {
  const msg = String(error?.message || '').toLowerCase();
  if (!msg) return false;

  const column = String(columnName || '').toLowerCase();
  if (column && !msg.includes(column)) return false;

  return (
    msg.includes('column') &&
    (msg.includes('does not exist') || msg.includes('could not find'))
  );
}

function isMissingPushTokensTable(error) {
  return isMissingTable(error, 'push_tokens');
}

async function upsertPushToken({ userId, token, platform, locale = '' }) {
  const client = db.raw();
  if (!client) return { stored: false, reason: 'db_unavailable' };

  const cleanToken = normalizePushToken(token);
  if (!cleanToken) return { stored: false, reason: 'invalid_token' };
  const normalizedPlatform = normalizePushPlatform(platform);
  const normalizedLocale = normalizePushLocale(locale, '');

  const now = new Date().toISOString();
  const payload = {
    user_id: userId,
    token: cleanToken,
    platform: normalizedPlatform,
    locale: normalizedLocale || null,
    is_active: true,
    updated_at: now,
    last_seen_at: now,
  };

  let localeStored = true;
  let { error } = await client.from('push_tokens').upsert(payload, {
    onConflict: 'user_id,token',
    ignoreDuplicates: false,
  });

  if (error && isMissingColumn(error, 'locale')) {
    localeStored = false;
    const legacyPayload = {
      user_id: userId,
      token: cleanToken,
      platform: encodeLegacyPlatformWithLocale(normalizedPlatform, normalizedLocale),
      is_active: true,
      updated_at: now,
      last_seen_at: now,
    };

    const retry = await client.from('push_tokens').upsert(legacyPayload, {
      onConflict: 'user_id,token',
      ignoreDuplicates: false,
    });
    error = retry.error;
  }

  if (error) {
    if (isMissingPushTokensTable(error)) {
      return { stored: false, reason: 'missing_table' };
    }
    throw error;
  }

  return {
    stored: true,
    reason: localeStored ? 'ok' : 'ok_locale_column_missing',
    locale: normalizedLocale || null,
    localeStored,
  };
}

async function deactivatePushToken({ userId, token = null }) {
  const client = db.raw();
  if (!client) return { stored: false, reason: 'db_unavailable' };

  const now = new Date().toISOString();
  let query = client
    .from('push_tokens')
    .update({ is_active: false, updated_at: now })
    .eq('user_id', userId)
    .eq('is_active', true);

  const cleanToken = normalizePushToken(token);
  if (cleanToken) query = query.eq('token', cleanToken);

  const { error } = await query;
  if (error) {
    if (isMissingPushTokensTable(error)) {
      return { stored: false, reason: 'missing_table' };
    }
    throw error;
  }

  return { stored: true, reason: 'ok' };
}

function getFcmServerKey() {
  return String(process.env.FCM_SERVER_KEY || process.env.FIREBASE_SERVER_KEY || '').trim();
}

function decodeBase64Utf8(value) {
  if (!value) return '';
  try {
    return Buffer.from(String(value), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function parseFirebaseServiceAccount(value) {
  if (!value) return null;

  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object') return parsed;
  } catch {
    // fall through and try base64-decoding
  }

  const decoded = decodeBase64Utf8(value);
  if (!decoded) return null;

  try {
    const parsed = JSON.parse(decoded);
    if (parsed && typeof parsed === 'object') return parsed;
  } catch {
    return null;
  }

  return null;
}

function getFirebaseServiceAccount() {
  if (firebaseServiceAccountCache !== undefined) return firebaseServiceAccountCache;

  const rawJson = String(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || process.env.FIREBASE_SERVICE_ACCOUNT || '').trim();
  const rawBase64 = String(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64 || '').trim();

  const parsed = parseFirebaseServiceAccount(rawJson) || parseFirebaseServiceAccount(rawBase64);
  if (!parsed) {
    firebaseServiceAccountCache = null;
    return firebaseServiceAccountCache;
  }

  const clientEmail = String(parsed.client_email || '').trim();
  const privateKeyRaw = String(parsed.private_key || '').trim();
  const privateKey = privateKeyRaw.replace(/\\n/g, '\n');
  const projectId = String(process.env.FIREBASE_PROJECT_ID || parsed.project_id || '').trim();

  if (!clientEmail || !privateKey || !projectId) {
    firebaseServiceAccountCache = null;
    return firebaseServiceAccountCache;
  }

  firebaseServiceAccountCache = { clientEmail, privateKey, projectId };
  return firebaseServiceAccountCache;
}

function toBase64Url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createGoogleJwtAssertion(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccount.clientEmail,
    scope: FCM_OAUTH_SCOPE,
    aud: FCM_OAUTH_TOKEN_ENDPOINT,
    iat: now,
    exp: now + 3600,
  };

  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createSign('RSA-SHA256')
    .update(unsignedToken)
    .end()
    .sign(serviceAccount.privateKey);

  return `${unsignedToken}.${toBase64Url(signature)}`;
}

async function getFirebaseAccessToken(serviceAccount) {
  const now = Date.now();
  if (
    firebaseAccessTokenCache.token &&
    firebaseAccessTokenCache.expiresAt - PUSH_FCM_TOKEN_REFRESH_SKEW_MS > now
  ) {
    return { ok: true, token: firebaseAccessTokenCache.token };
  }

  if (typeof fetch !== 'function') {
    return { ok: false, code: 'fetch_unavailable', message: 'Global fetch is not available.' };
  }

  let assertion;
  try {
    assertion = createGoogleJwtAssertion(serviceAccount);
  } catch (error) {
    return { ok: false, code: 'credential_error', message: error?.message || String(error) };
  }

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), PUSH_FCM_TIMEOUT_MS);

  try {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    });

    const response = await fetch(FCM_OAUTH_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
      signal: controller.signal,
    });

    const responseText = await response.text();
    let parsed = null;
    try {
      parsed = responseText ? JSON.parse(responseText) : null;
    } catch {
      parsed = null;
    }

    if (!response.ok) {
      return {
        ok: false,
        code: `auth_http_${response.status}`,
        message: parsed?.error_description || parsed?.error || responseText || response.statusText,
      };
    }

    const token = String(parsed?.access_token || '').trim();
    const expiresIn = Number(parsed?.expires_in || 0);
    if (!token || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      return {
        ok: false,
        code: 'auth_invalid_response',
        message: 'OAuth token response did not include a valid access token.',
      };
    }

    firebaseAccessTokenCache = {
      token,
      expiresAt: now + (expiresIn * 1000),
    };

    return { ok: true, token };
  } catch (error) {
    if (error?.name === 'AbortError') {
      return { ok: false, code: 'auth_timeout', message: 'Firebase auth request timed out.' };
    }
    return { ok: false, code: 'auth_request_error', message: error?.message || String(error) };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function resolvePushProvider() {
  const serviceAccount = getFirebaseServiceAccount();
  if (serviceAccount) return { mode: 'fcm_v1', serviceAccount };

  const serverKey = getFcmServerKey();
  if (serverKey) return { mode: 'fcm_legacy', serverKey };

  return null;
}

function toPushDataValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function buildPushDataPayload(notif) {
  const notifType = toPushDataValue(notif.type);
  const notifId = toPushDataValue(notif.id);
  return {
    // Event envelope type consumed by Flutter realtime bridge.
    type: 'new_notification',
    id: notifId,
    notificationId: notifId,
    notifType,
    notificationType: notifType,
    relatedId: toPushDataValue(notif.related_id),
    link: toPushDataValue(notif.link),
    senderId: toPushDataValue(notif.sender_id),
    title: toPushDataValue(notif.title),
    body: toPushDataValue(notif.body),
    message: toPushDataValue(notif.body),
  };
}

async function listActivePushTokens(userId, limit = 10) {
  const client = db.raw();
  if (!client) return { tokens: [], reason: 'db_unavailable' };

  let { data, error } = await client
    .from('push_tokens')
    .select('token,platform,locale')
    .eq('user_id', userId)
    .eq('is_active', true)
    .order('last_seen_at', { ascending: false })
    .limit(limit);

  if (error && isMissingColumn(error, 'locale')) {
    const fallback = await client
      .from('push_tokens')
      .select('token,platform')
      .eq('user_id', userId)
      .eq('is_active', true)
      .order('last_seen_at', { ascending: false })
      .limit(limit);

    data = (fallback.data || []).map((row) => {
      const decoded = decodeLegacyPlatformWithLocale(row.platform);
      return {
        token: row.token,
        platform: decoded.platform,
        locale: decoded.locale || null,
      };
    });
    error = fallback.error;
  }

  if (error) {
    if (isMissingPushTokensTable(error)) {
      return { tokens: [], reason: 'missing_table' };
    }
    throw error;
  }

  const normalizedRows = (data || []).map((row) => {
    const decoded = decodeLegacyPlatformWithLocale(row.platform);
    return {
      token: row.token,
      platform: decoded.platform,
      locale: normalizePushLocale(row.locale, '') || decoded.locale || null,
    };
  });

  return { tokens: normalizedRows, reason: 'ok' };
}

function localizeSportNameForPush({ sportId = '', rawName = '', locale = '' }) {
  const fallback = maybeString(rawName, 80) || 'sport';
  const botAutomation = getBotAutomation();
  if (!botAutomation?.translateSportName) return fallback;

  try {
    const localized = botAutomation.translateSportName(sportId, locale, fallback);
    return maybeString(localized, 80) || fallback;
  } catch {
    return fallback;
  }
}

async function resolveUserPreferredPushLocale(userId, fallback = 'tr') {
  const normalizedFallback = normalizePushLocale(fallback, 'tr') || 'tr';

  try {
    const tokenResult = await listActivePushTokens(userId, 10);
    for (const token of (tokenResult.tokens || [])) {
      const tokenLocale = normalizePushLocale(token?.locale, '');
      if (tokenLocale) return tokenLocale;
    }
  } catch {
    // ignore and continue fallback chain
  }

  try {
    const user = await userById(userId);
    const userLocale = normalizePushLocale(user?.country_code, '');
    if (userLocale) return userLocale;
  } catch {
    // ignore and return fallback
  }

  return normalizedFallback;
}

function buildDirectChallengePushCopy({ locale = 'tr', challengeType = 'RIVAL', senderName = '', sportName = '' }) {
  const lang = normalizePushLocale(locale, 'en') || 'en';
  const copy = DIRECT_CHALLENGE_COPY[lang] || DIRECT_CHALLENGE_COPY.en;
  const normalizedType = String(challengeType || 'RIVAL').toUpperCase() === 'PARTNER' ? 'PARTNER' : 'RIVAL';
  const title = normalizedType === 'PARTNER' ? copy.partnerTitle : copy.rivalTitle;
  const sender = maybeString(senderName, 80) || copy.senderFallback;
  const sport = maybeString(sportName, 80) || copy.sportFallback;
  const body = String(copy.bodyTemplate || '{sender} sent you a {sport} offer.')
    .replace('{sender}', sender)
    .replace('{sport}', sport);

  return {
    title,
    body,
  };
}

async function sendFcmLegacyMessage({ token, title, body, data }) {
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'fetch_unavailable', message: 'Global fetch is not available.' };
  }

  const serverKey = getFcmServerKey();
  if (!serverKey) {
    return { ok: false, code: 'provider_not_configured', message: 'FCM_SERVER_KEY is not set.' };
  }

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), PUSH_FCM_TIMEOUT_MS);

  try {
    const payload = {
      to: token,
      priority: 'high',
      notification: {
        title: title || 'SporPartner',
        body: body || '',
      },
      data: data || {},
      content_available: true,
      mutable_content: true,
    };

    const response = await fetch(FCM_LEGACY_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `key=${serverKey}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const responseText = await response.text();
    let parsed = null;
    try {
      parsed = responseText ? JSON.parse(responseText) : null;
    } catch {
      parsed = null;
    }

    if (!response.ok) {
      return {
        ok: false,
        code: `http_${response.status}`,
        message: responseText || response.statusText,
      };
    }

    const result = parsed?.results?.[0] || null;
    if (result?.message_id) {
      return { ok: true, code: 'sent', message: null };
    }

    if (result?.error) {
      return { ok: false, code: result.error, message: result.error };
    }

    if (parsed?.success > 0) {
      return { ok: true, code: 'sent', message: null };
    }

    return { ok: false, code: 'unknown_failure', message: responseText || 'Unknown FCM failure.' };
  } catch (error) {
    if (error?.name === 'AbortError') {
      return { ok: false, code: 'timeout', message: 'FCM request timed out.' };
    }
    return { ok: false, code: 'request_error', message: error?.message || String(error) };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function sendFcmV1Message({ token, title, body, data, serviceAccount }) {
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'fetch_unavailable', message: 'Global fetch is not available.' };
  }

  const account = serviceAccount || getFirebaseServiceAccount();
  if (!account) {
    return {
      ok: false,
      code: 'provider_not_configured',
      message: 'Firebase service account env is not set.',
    };
  }

  const auth = await getFirebaseAccessToken(account);
  if (!auth.ok) return auth;

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), PUSH_FCM_TIMEOUT_MS);

  try {
    const endpoint = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(account.projectId)}/messages:send`;
    const payload = {
      message: {
        token,
        notification: {
          title: title || 'SporPartner',
          body: body || '',
        },
        data: data || {},
      },
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auth.token}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const responseText = await response.text();
    let parsed = null;
    try {
      parsed = responseText ? JSON.parse(responseText) : null;
    } catch {
      parsed = null;
    }

    if (response.ok) {
      return { ok: true, code: 'sent', message: null };
    }

    const status = String(parsed?.error?.status || '').trim();
    const details = Array.isArray(parsed?.error?.details) ? parsed.error.details : [];
    const fcmDetail = details.find((item) => item && typeof item.errorCode === 'string');
    const fcmErrorCode = String(fcmDetail?.errorCode || '').trim();
    const message = parsed?.error?.message || responseText || response.statusText;

    if (fcmErrorCode) {
      return { ok: false, code: fcmErrorCode, message };
    }

    if (status) {
      return { ok: false, code: status, message };
    }

    return {
      ok: false,
      code: `http_${response.status}`,
      message,
    };
  } catch (error) {
    if (error?.name === 'AbortError') {
      return { ok: false, code: 'timeout', message: 'FCM request timed out.' };
    }
    return { ok: false, code: 'request_error', message: error?.message || String(error) };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function deactivateInvalidPushToken({ userId, token }) {
  const cleanToken = normalizePushToken(token);
  if (!cleanToken) return;
  await deactivatePushToken({ userId, token: cleanToken });
}

async function sendPushForNotification(notif) {
  const provider = resolvePushProvider();
  const providerMode = provider?.mode || 'none';

  if (!provider) {
    logPushTelemetry('send_skipped', {
      notificationId: notif.id,
      userId: notif.user_id,
      notifType: notif.type,
      providerMode,
      reason: 'provider_not_configured',
    });
    return { sent: 0, attempted: 0, reason: 'provider_not_configured' };
  }

  const tokenResult = await listActivePushTokens(notif.user_id, 10);
  logPushTelemetry('send_start', {
    notificationId: notif.id,
    userId: notif.user_id,
    notifType: notif.type,
    providerMode,
    tokenCount: tokenResult.tokens.length,
    tokenQueryReason: tokenResult.reason || 'ok',
  });

  if (!tokenResult.tokens.length) {
    logPushTelemetry('send_skipped', {
      notificationId: notif.id,
      userId: notif.user_id,
      notifType: notif.type,
      providerMode,
      reason: tokenResult.reason || 'no_tokens',
    });
    return { sent: 0, attempted: 0, reason: tokenResult.reason || 'no_tokens' };
  }

  const pushData = buildPushDataPayload(notif);
  let sentCount = 0;
  let attemptedCount = 0;

  for (const row of tokenResult.tokens) {
    const token = normalizePushToken(row.token);
    if (!token) continue;

    attemptedCount += 1;
    const result = provider.mode === 'fcm_v1'
      ? await sendFcmV1Message({
        token,
        title: notif.title,
        body: notif.body,
        data: pushData,
        serviceAccount: provider.serviceAccount,
      })
      : await sendFcmLegacyMessage({
        token,
        title: notif.title,
        body: notif.body,
        data: pushData,
      });

    logPushTelemetry('send_attempt', {
      notificationId: notif.id,
      userId: notif.user_id,
      providerMode,
      attempt: attemptedCount,
      platform: row.platform || 'unknown',
      locale: normalizePushLocale(row.locale, '') || null,
      token: maskPushTokenForLogs(token),
      ok: !!result.ok,
      code: result.code || 'unknown',
      message: clipForLogs(result.message || ''),
    });

    if (result.ok) {
      sentCount += 1;
      continue;
    }

    if (INVALID_PUSH_TOKEN_ERRORS.has(result.code)) {
      await deactivateInvalidPushToken({ userId: notif.user_id, token });
      logPushTelemetry('token_deactivated', {
        notificationId: notif.id,
        userId: notif.user_id,
        providerMode,
        token: maskPushTokenForLogs(token),
        reason: result.code || 'invalid_token_code',
      });
      continue;
    }

    const msg = String(result.message || '').toLowerCase();
    if (
      msg.includes('notregistered') ||
      msg.includes('invalidregistration') ||
      msg.includes('unregistered') ||
      (msg.includes('registration token') && msg.includes('not valid'))
    ) {
      await deactivateInvalidPushToken({ userId: notif.user_id, token });
      logPushTelemetry('token_deactivated', {
        notificationId: notif.id,
        userId: notif.user_id,
        providerMode,
        token: maskPushTokenForLogs(token),
        reason: 'message_contains_unregistered',
      });
      continue;
    }

    console.warn('push delivery warning:', {
      userId: notif.user_id,
      code: result.code,
      message: result.message,
      platform: row.platform,
    });
  }

  const summary = {
    sent: sentCount,
    attempted: attemptedCount,
    reason: sentCount > 0 ? 'sent' : 'failed',
  };

  logPushTelemetry('send_summary', {
    notificationId: notif.id,
    userId: notif.user_id,
    notifType: notif.type,
    providerMode,
    attempted: summary.attempted,
    sent: summary.sent,
    reason: summary.reason,
  });

  return summary;
}

async function userById(id) { return id ? await db.findById('users', id) : null; }
async function listingById(id) { return id ? await db.findById('listings', id) : null; }

function maskAnonymousListingForViewer(listing, viewerId) {
  if (!listing) return listing;
  const isOwner = !!viewerId && listing.user_id === viewerId;
  if (!listing.is_anonymous || isOwner) return listing;

  return {
    ...listing,
    user_id: `anon_${listing.id || 'listing'}`,
    user_name: null,
    user_avatar: null,
  };
}

async function generateMatchReminders({ now = new Date().toISOString(), limit = 200, userId = null } = {}) {
  const client = db.raw();
  let dueMatchesQuery = client.from('matches').select('*')
    .in('status', ['SCHEDULED', 'ONGOING'])
    .lte('scheduled_at', now)
    .is('completed_at', null);

  if (userId) {
    dueMatchesQuery = dueMatchesQuery.or(`user1_id.eq.${userId},user2_id.eq.${userId}`);
  }

  const { data: dueMatches } = await dueMatchesQuery.limit(limit);

  let reminderNotifications = 0;
  if ((dueMatches || []).length === 0) return reminderNotifications;

  const userIds = [...new Set(dueMatches.flatMap(m => [m.user1_id, m.user2_id]))];
  const matchIds = dueMatches.map(m => m.id);
  const [{ data: users }, { data: existingReminders }] = await Promise.all([
    client.from('users').select('id,name,avatar_url').in('id', userIds),
    client.from('notifications').select('related_id,user_id')
      .eq('type', 'MATCH_REMINDER')
      .in('related_id', matchIds),
  ]);
  const usersMap = new Map((users || []).map(user => [user.id, user]));
  const remindedPairs = new Set(
    (existingReminders || []).map(notification => `${notification.related_id}:${notification.user_id}`),
  );

  for (const match of dueMatches) {
    const user1 = usersMap.get(match.user1_id);
    const user2 = usersMap.get(match.user2_id);
    const recipients = [
      {
        userId: match.user1_id,
        sender: user2,
        alreadyApproved: !!match.u1_approved,
      },
      {
        userId: match.user2_id,
        sender: user1,
        alreadyApproved: !!match.u2_approved,
      },
    ];

    for (const recipient of recipients) {
      const key = `${match.id}:${recipient.userId}`;
      if (recipient.alreadyApproved || remindedPairs.has(key)) continue;
      await pushNotification({
        userId: recipient.userId,
        type: 'MATCH_REMINDER',
        title: 'MaÃ§ oynandÄ± mÄ±?',
        body: `${recipient.sender?.name || 'Rakibin'} ile planlanan maÃ§ zamanÄ± geÃ§ti. OynandÄ±ysa maÃ§Ä± onaylayÄ±n.`,
        relatedId: match.id,
        senderId: recipient.sender?.id,
        senderName: recipient.sender?.name,
        senderAvatar: recipient.sender?.avatar_url,
      });
      remindedPairs.add(key);
      reminderNotifications++;
    }
  }

  return reminderNotifications;
}

function safeUser(row) {
  if (!row) return null;
  const u = toCamel(row);
  delete u.password;
  if ('level' in u) { u.userLevel = u.level; delete u.level; }
  u.followersCount = u.followerCount || 0;
  u.avgRating = u.averageRating || 0;
  return u;
}

function formatNameList(names) {
  const uniqueNames = [...new Set((names || []).map(name => String(name || '').trim()).filter(Boolean))];
  if (uniqueNames.length === 0) return '';
  if (uniqueNames.length === 1) return uniqueNames[0];
  if (uniqueNames.length === 2) return `${uniqueNames[0]} ve ${uniqueNames[1]}`;
  return `${uniqueNames.slice(0, -1).join(', ')} ve ${uniqueNames[uniqueNames.length - 1]}`;
}

function isPartnerGroupListing(listing) {
  if (!listing) return false;
  const listingType = String(listing.type || '').toUpperCase();
  const maxParticipants = Number(listing.max_participants || 0);
  return listingType === 'PARTNER' && maxParticipants > 2;
}

function isGroupMatchRecord(match, listing = null) {
  const source = String(match?.source || '').toUpperCase();
  if (source === 'GROUP_LISTING') return true;
  return isPartnerGroupListing(listing);
}

let hasMatchParticipantsTable = true;
let hasMatchLocationVerificationsTable = true;

const MATCH_GPS_RADIUS_METERS = 600;
const MATCH_GPS_TRUST_REWARD = 20;

function toFiniteNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function isValidLatitude(value) {
  return typeof value === 'number' && value >= -90 && value <= 90;
}

function isValidLongitude(value) {
  return typeof value === 'number' && value >= -180 && value <= 180;
}

function haversineDistanceMeters(lat1, lon1, lat2, lon2) {
  const toRad = deg => (deg * Math.PI) / 180;
  const R = 6371000;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function getListingCoordinates(listing) {
  if (!listing) return { latitude: null, longitude: null };
  const latitude = toFiniteNumber(listing.latitude);
  const longitude = toFiniteNumber(listing.longitude);
  if (!isValidLatitude(latitude) || !isValidLongitude(longitude)) {
    return { latitude: null, longitude: null };
  }
  return { latitude, longitude };
}

function buildGpsQualificationByUser(rows = [], listing = null) {
  const byUser = new Map();
  const validRows = (rows || []).filter(row => row?.user_id);
  const listingCoords = getListingCoordinates(listing);

  for (const row of validRows) {
    const rowLat = toFiniteNumber(row.latitude);
    const rowLon = toFiniteNumber(row.longitude);
    if (!isValidLatitude(rowLat) || !isValidLongitude(rowLon)) continue;

    let distanceToListingM = null;
    if (listingCoords.latitude !== null && listingCoords.longitude !== null) {
      distanceToListingM = Math.round(haversineDistanceMeters(
        rowLat,
        rowLon,
        listingCoords.latitude,
        listingCoords.longitude
      ));
    }

    const nearVenue = distanceToListingM !== null && distanceToListingM <= MATCH_GPS_RADIUS_METERS;

    let nearParticipant = false;
    for (const other of validRows) {
      if (!other?.user_id || other.user_id === row.user_id) continue;
      const otherLat = toFiniteNumber(other.latitude);
      const otherLon = toFiniteNumber(other.longitude);
      if (!isValidLatitude(otherLat) || !isValidLongitude(otherLon)) continue;
      const distanceBetweenUsers = haversineDistanceMeters(rowLat, rowLon, otherLat, otherLon);
      if (distanceBetweenUsers <= MATCH_GPS_RADIUS_METERS) {
        nearParticipant = true;
        break;
      }
    }

    byUser.set(row.user_id, {
      nearVenue,
      nearParticipant,
      distanceToListingM,
      qualifies: nearVenue || nearParticipant,
    });
  }

  return byUser;
}

function isMissingRelationError(error, relationName) {
  const message = String(error?.message || '').toLowerCase();
  const details = String(error?.details || '').toLowerCase();
  const relation = String(relationName || '').toLowerCase();
  return error?.code === '42P01'
    || message.includes('does not exist')
    || details.includes('does not exist')
    || message.includes(relation)
    || details.includes(relation);
}

async function getPersistedParticipantsByMatch(matchIds = []) {
  const ids = [...new Set((matchIds || []).filter(Boolean))];
  const byMatch = new Map();
  if (ids.length === 0 || !hasMatchParticipantsTable) return byMatch;

  try {
    const client = db.raw();
    const { data } = await client.from('match_participants').select('match_id,user_id')
      .in('match_id', ids);

    for (const row of (data || [])) {
      if (!row?.match_id || !row.user_id) continue;
      if (!byMatch.has(row.match_id)) byMatch.set(row.match_id, new Set());
      byMatch.get(row.match_id).add(row.user_id);
    }
    return byMatch;
  } catch (error) {
    if (isMissingRelationError(error, 'match_participants')) {
      hasMatchParticipantsTable = false;
      return new Map();
    }
    console.error('match_participants read error:', error.message || error);
    return new Map();
  }
}

async function getMatchLocationVerificationRows(matchIds = []) {
  const ids = [...new Set((matchIds || []).filter(Boolean))];
  const byMatch = new Map();
  if (ids.length === 0 || !hasMatchLocationVerificationsTable) return byMatch;

  try {
    const client = db.raw();
    const { data } = await client.from('match_location_verifications')
      .select('id,match_id,user_id,latitude,longitude,verified_at,rewarded_at,distance_to_listing_m')
      .in('match_id', ids);

    for (const row of (data || [])) {
      if (!row?.match_id) continue;
      if (!byMatch.has(row.match_id)) byMatch.set(row.match_id, []);
      byMatch.get(row.match_id).push(row);
    }
    return byMatch;
  } catch (error) {
    if (isMissingRelationError(error, 'match_location_verifications')) {
      hasMatchLocationVerificationsTable = false;
      return new Map();
    }
    console.error('match_location_verifications read error:', error.message || error);
    return new Map();
  }
}

async function persistMatchParticipants({ matchId, participantIds, ownerId = null }) {
  const targetMatchId = String(matchId || '').trim();
  const uniqueParticipantIds = [...new Set((participantIds || []).filter(Boolean))];
  if (!targetMatchId || uniqueParticipantIds.length === 0 || !hasMatchParticipantsTable) return false;

  try {
    const client = db.raw();
    await client.from('match_participants').delete().eq('match_id', targetMatchId);
    await client.from('match_participants').insert(
      uniqueParticipantIds.map(userId => ({
        id: 'mp_' + uuid(),
        match_id: targetMatchId,
        user_id: userId,
        role: userId === ownerId ? 'OWNER' : 'PARTICIPANT',
      }))
    );
    return true;
  } catch (error) {
    if (isMissingRelationError(error, 'match_participants')) {
      hasMatchParticipantsTable = false;
      return false;
    }
    console.error('match_participants write error:', error.message || error);
    return false;
  }
}

async function getListingAcceptedParticipantIds(listing) {
  if (!listing || !listing.id) return [];
  const client = db.raw();
  const { data } = await client.from('interests').select('user_id')
    .eq('listing_id', listing.id)
    .eq('status', 'ACCEPTED');

  const ids = new Set();
  if (listing.user_id) ids.add(listing.user_id);
  for (const row of (data || [])) {
    if (row.user_id) ids.add(row.user_id);
  }
  return [...ids];
}

async function getMatchParticipantIds(match, listing = null) {
  const base = new Set([match?.user1_id, match?.user2_id].filter(Boolean));
  if (!match) return [...base];

  const persistedByMatch = await getPersistedParticipantsByMatch([match.id]);
  const persisted = persistedByMatch.get(match.id);
  if (persisted) {
    for (const userId of persisted) {
      if (userId) base.add(userId);
    }
  }

  const targetListing = listing || (match.listing_id ? await listingById(match.listing_id) : null);
  if (!isGroupMatchRecord(match, targetListing)) return [...base];
  if (persisted && persisted.size > 0) return [...base];
  if (!targetListing) return [...base];

  const listingParticipants = await getListingAcceptedParticipantIds(targetListing);
  for (const participantId of listingParticipants) {
    if (participantId) base.add(participantId);
  }
  return [...base];
}

function pickDisplayUser2IdForViewer({ match, participantIds, viewerId }) {
  if (!viewerId) return match.user2_id;
  const participantSet = new Set((participantIds || []).filter(Boolean));
  if (!participantSet.has(viewerId)) return match.user2_id;
  if (viewerId === match.user1_id) {
    return participantIds.find(id => id && id !== match.user1_id) || match.user2_id;
  }
  return viewerId;
}

const REACTION_TYPES = ['LIKE','LOVE','FIRE','STRONG','WOW','CLAP'];

async function enrichPostReactions(postId, currentUserId) {
  const reactions = await db.query('post_reactions', { filters: { post_id: postId } });
  const userReaction = reactions.find(r => r.user_id === currentUserId)?.type || null;
  const reactionCounts = {};
  REACTION_TYPES.forEach(t => {
    const c = reactions.filter(r => r.type === t).length;
    if (c > 0) reactionCounts[t] = c;
  });
  return { userReaction, reactionCounts, likeCount: reactions.length, isLiked: !!userReaction };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HEALTH
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/health', (_req, res) => res.json({
  status: 'ok', env: 'vercel', database: 'supabase', timestamp: new Date().toISOString()
}));
app.get('/', (_req, res) => res.json({
  name: 'Sports Partner API', version: '2.0.0', status: 'running', database: 'supabase'
}));

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  GEO (public)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/api/geo/cities', async (_req, res) => {
  try {
    const data = await db.query('cities');
    res.json({ data: data.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/geo/districts', async (req, res) => {
  try {
    const { cityId } = req.query;
    const filters = cityId ? { city_id: cityId } : {};
    const data = await db.query('districts', { filters });
    res.json({ data: data.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/sports', async (_req, res) => {
  try {
    await ensureRequiredListingSports();
    await ensureSportIcons();
    const data = await db.query('sports');
    res.json({ data: data.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/countries', async (_req, res) => {
  try {
    const data = await db.query('countries');
    res.json({ data: data.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/cities', async (req, res) => {
  try {
    const { countryCode, country_code } = req.query;
    const cc = countryCode || country_code;
    const filters = cc ? { country_code: cc } : {};
    const data = await db.query('cities', { filters });
    res.json({ data: data.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  AUTH
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const authRouter = express.Router();

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email ve ÅŸifre gerekli.' });

    // Brute force protection
    const ip = req.headers['x-forwarded-for'] || req.ip;
    const now = Date.now();
    let att = loginAttempts.get(ip);
    if (!att || now - att.start > LOGIN_WINDOW) {
      att = { start: now, count: 0 };
      loginAttempts.set(ip, att);
    }
    if (att.count >= LOGIN_MAX) {
      return res.status(429).json({ message: 'Ã‡ok fazla baÅŸarÄ±sÄ±z giriÅŸ. 15 dk bekleyin.' });
    }

    const user = await db.findOne('users', { email: email.toLowerCase() });
    if (!user) { att.count++; return res.status(401).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' }); }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) { att.count++; return res.status(401).json({ message: 'HatalÄ± ÅŸifre.' }); }

    loginAttempts.delete(ip);
    const tokens = generateTokens(user.id);
    await db.insert('refresh_tokens', {
      token: tokens.refreshToken, user_id: user.id,
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    }).catch(() => {});

    res.json({ ...tokens, user: safeUser(user) });
  } catch (e) { console.error('login error:', e); res.status(500).json({ message: 'Sunucu hatasÄ±.' }); }
});

authRouter.post('/register', contentFilter('name'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Ad, email ve ÅŸifre gerekli.' });
    if (password.length < 6) return res.status(400).json({ message: 'Åifre en az 6 karakter olmalÄ±.' });

    const existing = await db.findOne('users', { email: email.toLowerCase() });
    if (existing) return res.status(409).json({ message: 'Bu email zaten kayÄ±tlÄ±.' });

    const hashed = await bcrypt.hash(password, 10);
    const userId = 'user_' + uuid();
    const userRow = {
      id: userId, email: email.toLowerCase(), name, username: email.split('@')[0],
      password: hashed, avatar_url: null, cover_url: null, phone: null,
      is_admin: false, onboarding_done: false, user_type: 'USER',
      city: null, city_id: null, district: null, district_id: null, bio: null,
      instagram: null, tiktok: null, facebook: null, twitter: null,
      youtube: null, linkedin: null, discord: null, twitch: null,
      snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
      sports: [], level: 'BEGINNER', gender: null,
      preferred_time: null, preferred_style: null, birth_date: null,
      total_matches: 0, current_streak: 0, longest_streak: 0, total_points: 0,
      follower_count: 0, following_count: 0, average_rating: 0, rating_count: 0,
      is_banned: false, no_show_count: 0,
      referral_code: `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
      referred_by: req.body.referralCode || null, country_code: null,
    };

    const inserted = await db.insert('users', userRow);
    const tokens = generateTokens(userId);
    await db.insert('refresh_tokens', {
      token: tokens.refreshToken, user_id: userId,
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    }).catch(() => {});

    res.status(201).json({ ...tokens, user: safeUser(inserted) });
  } catch (e) { console.error('register error:', e); res.status(500).json({ message: 'Sunucu hatasÄ±.' }); }
});

authRouter.post('/token/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'GeÃ§ersiz refresh token.' });

    const stored = await db.findOne('refresh_tokens', { token: refreshToken });
    if (!stored) return res.status(401).json({ message: 'GeÃ§ersiz refresh token.' });

    const payload = verifyRefreshToken(refreshToken);
    await db.removeWhere('refresh_tokens', { token: refreshToken }).catch(() => {});

    const tokens = generateTokens(payload.sub);
    await db.insert('refresh_tokens', {
      token: tokens.refreshToken, user_id: payload.sub,
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    }).catch(() => {});

    res.json(tokens);
  } catch { res.status(401).json({ message: 'Refresh token sÃ¼resi dolmuÅŸ.' }); }
});

authRouter.post('/logout', authMiddleware, async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) await db.removeWhere('refresh_tokens', { token: refreshToken }).catch(() => {});
  res.json({ message: 'Ã‡Ä±kÄ±ÅŸ yapÄ±ldÄ±.' });
});

// Password reset tokens stored in Supabase DB (NOT in-memory â€” serverless safe)
// Table: password_reset_tokens (id, user_id, code, token, expires_at, created_at)

authRouter.post('/forgot-password', async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  try {
    const ip = getRequestIp(req);

    const ipRate = consumeRateLimitBucket(passwordResetRequestBucketsByIp, `forgot:${ip}`, {
      windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
      max: PASSWORD_RESET_MAX_PER_IP,
    });
    if (!ipRate.allowed) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_FORGOT_RATE_LIMITED',
        email,
        success: false,
        reason: 'ip_limit',
        metadata: { bucket: 'ip', count: ipRate.count },
      });
      return res.status(429).json({ message: 'Cok fazla sifre sifirlama istegi. Lutfen daha sonra tekrar deneyin.' });
    }

    if (email) {
      const emailRate = consumeRateLimitBucket(passwordResetRequestBucketsByEmail, `forgot:${email}`, {
        windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
        max: PASSWORD_RESET_MAX_PER_EMAIL,
      });
      if (!emailRate.allowed) {
        await writeAuthAuditLog(req, {
          eventType: 'AUTH_FORGOT_RATE_LIMITED',
          email,
          success: false,
          reason: 'email_limit',
          metadata: { bucket: 'email', count: emailRate.count },
        });
        return res.status(429).json({ message: 'Cok fazla sifre sifirlama istegi. Lutfen daha sonra tekrar deneyin.' });
      }
    }

    if (!isPasswordResetEmailConfigured()) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_FORGOT_CONFIG_ERROR',
        email,
        success: false,
        reason: 'smtp_not_configured',
      });
      return res.status(503).json({ message: 'Sifre sifirlama servisi su anda kullanilamiyor.' });
    }

    if (!email) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_FORGOT_INVALID_EMAIL',
        success: false,
        reason: 'missing_email',
      });
      return res.json({ message: 'Eger hesap mevcutsa sifirlama kodu gonderildi.' });
    }

    const user = await db.findOne('users', { email });
    if (!user) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_FORGOT_REQUESTED',
        email,
        success: true,
        reason: 'user_not_found',
      });
      return res.json({ message: 'Eger hesap mevcutsa sifirlama kodu gonderildi.' });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const token = uuid();

    await db.removeWhere('password_reset_tokens', { user_id: user.id }).catch(() => {});
    await db.insert('password_reset_tokens', {
      id: uuid(),
      user_id: user.id,
      code,
      token,
      expires_at: new Date(Date.now() + PASSWORD_RESET_CODE_TTL_MS).toISOString(),
    });

    const mailResult = await sendPasswordResetEmail({
      email: user.email,
      name: user.name,
      token,
      code,
    });

    if (!mailResult.ok) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_FORGOT_MAIL_FAILED',
        userId: user.id,
        email: user.email,
        success: false,
        reason: mailResult.code,
        metadata: { message: mailResult.message },
      });
      return res.status(503).json({ message: 'Sifre sifirlama e-postasi gonderilemedi. Lutfen daha sonra tekrar deneyin.' });
    }

    await writeAuthAuditLog(req, {
      eventType: 'AUTH_FORGOT_EMAIL_SENT',
      userId: user.id,
      email: user.email,
      success: true,
      reason: 'ok',
    });

    return res.json({ message: 'Sifirlama kodu gonderildi.' });
  } catch (e) {
    console.error('forgot-password error:', e);
    await writeAuthAuditLog(req, {
      eventType: 'AUTH_FORGOT_ERROR',
      email,
      success: false,
      reason: e?.message || 'server_error',
    });
    return res.status(500).json({ message: 'Sifre sifirlama islemi tamamlanamadi.' });
  }
});

authRouter.post('/reset-password', async (req, res) => {
  const token = maybeString(req.body?.token, 128) || '';
  const code = maybeString(req.body?.code, 32) || '';
  const newPassword = String(req.body?.newPassword || '');

  try {
    const ip = getRequestIp(req);

    const ipRate = consumeRateLimitBucket(passwordResetVerifyBucketsByIp, `reset:${ip}`, {
      windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
      max: PASSWORD_RESET_VERIFY_MAX_PER_IP,
    });
    if (!ipRate.allowed) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_RATE_LIMITED',
        success: false,
        reason: 'ip_limit',
        metadata: { bucket: 'ip', count: ipRate.count },
      });
      return res.status(429).json({ message: 'Cok fazla sifre sifirlama denemesi. Lutfen daha sonra tekrar deneyin.' });
    }

    if (token) {
      const tokenRate = consumeRateLimitBucket(passwordResetVerifyBucketsByToken, `reset:${token}`, {
        windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
        max: PASSWORD_RESET_VERIFY_MAX_PER_TOKEN,
      });
      if (!tokenRate.allowed) {
        await writeAuthAuditLog(req, {
          eventType: 'AUTH_RESET_RATE_LIMITED',
          success: false,
          reason: 'token_limit',
          metadata: { bucket: 'token', count: tokenRate.count },
        });
        return res.status(429).json({ message: 'Cok fazla sifre sifirlama denemesi. Lutfen daha sonra tekrar deneyin.' });
      }
    }

    if (!token || !code || !newPassword) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_INVALID_REQUEST',
        success: false,
        reason: 'missing_fields',
        metadata: {
          hasToken: !!token,
          hasCode: !!code,
          hasPassword: !!newPassword,
        },
      });
      return res.status(400).json({ message: 'Gecersiz veya suresi dolmus token.' });
    }

    if (newPassword.length < PASSWORD_RESET_MIN_PASSWORD_LENGTH) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_WEAK_PASSWORD',
        success: false,
        reason: 'password_too_short',
      });
      return res.status(400).json({ message: `Sifre en az ${PASSWORD_RESET_MIN_PASSWORD_LENGTH} karakter olmali.` });
    }

    const entry = await db.findOne('password_reset_tokens', { token });
    if (!entry) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_INVALID_TOKEN',
        success: false,
        reason: 'not_found',
      });
      return res.status(400).json({ message: 'Gecersiz veya suresi dolmus token.' });
    }

    if (new Date(entry.expires_at) < new Date()) {
      await db.removeWhere('password_reset_tokens', { token }).catch(() => {});
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_EXPIRED_TOKEN',
        userId: entry.user_id,
        success: false,
        reason: 'expired',
      });
      return res.status(400).json({ message: 'Kodun suresi dolmus.' });
    }

    if (String(entry.code) !== code) {
      await writeAuthAuditLog(req, {
        eventType: 'AUTH_RESET_INVALID_CODE',
        userId: entry.user_id,
        success: false,
        reason: 'mismatch',
      });
      return res.status(400).json({ message: 'Hatali sifirlama kodu.' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.update('users', entry.user_id, { password: hashed });
    await db.removeWhere('password_reset_tokens', { user_id: entry.user_id }).catch(() => {});
    await db.removeWhere('refresh_tokens', { user_id: entry.user_id }).catch(() => {});

    await writeAuthAuditLog(req, {
      eventType: 'AUTH_RESET_SUCCESS',
      userId: entry.user_id,
      success: true,
      reason: 'password_changed',
    });

    return res.json({ message: 'Sifre basariyla sifirlandi.' });
  } catch (e) {
    console.error('reset-password error:', e);
    await writeAuthAuditLog(req, {
      eventType: 'AUTH_RESET_ERROR',
      success: false,
      reason: e?.message || 'server_error',
      metadata: { hasToken: !!token },
    });
    return res.status(500).json({ message: 'Sifre sifirlama islemi tamamlanamadi.' });
  }
});

// Delete account â€” requires password confirmation
authRouter.delete('/delete-account', authMiddleware, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ message: 'Åifre gerekli.' });

    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'HatalÄ± ÅŸifre.' });

    // Cascade delete user data
    await db.removeWhere('refresh_tokens', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('password_reset_tokens', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('notifications', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('follows', { follower_id: req.userId }).catch(() => {});
    await db.removeWhere('follows', { following_id: req.userId }).catch(() => {});
    await db.removeWhere('blocked_users', { blocker_id: req.userId }).catch(() => {});
    await db.removeWhere('blocked_users', { blocked_id: req.userId }).catch(() => {});
    await db.removeWhere('interests', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('ratings', { rater_id: req.userId }).catch(() => {});
    await db.removeWhere('post_reactions', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('comment_likes', { user_id: req.userId }).catch(() => {});
    await db.removeWhere('user_privacy', { user_id: req.userId }).catch(() => {});

    // Anonymize posts and comments (don't delete â€” preserve thread integrity)
    const userPosts = await db.query('posts', { filters: { user_id: req.userId } });
    for (const p of userPosts) {
      await db.update('posts', p.id, { user_id: null, content: '[Silinen kullanÄ±cÄ±]' }).catch(() => {});
    }
    const userComments = await db.query('comments', { filters: { user_id: req.userId } });
    for (const c of userComments) {
      await db.update('comments', c.id, { user_id: null, content: '[Silinen kullanÄ±cÄ±]' }).catch(() => {});
    }

    // Delete listings (cascade: matches, messages related will be orphaned but safe)
    const userListings = await db.query('listings', { filters: { user_id: req.userId } });
    for (const li of userListings) {
      await db.removeWhere('listings', { id: li.id }).catch(() => {});
    }

    // Finally delete user
    await db.removeWhere('users', { id: req.userId });

    res.json({ message: 'Hesap baÅŸarÄ±yla silindi.' });
  } catch (e) {
    console.error('delete-account error:', e);
    res.status(500).json({ message: 'Hesap silme hatasÄ±.' });
  }
});

app.use('/api/auth', authRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  PROFILE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const profileRouter = express.Router();
profileRouter.use(authMiddleware);

profileRouter.get('/', async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });
    res.json({ data: { user: safeUser(user), myListings: [] } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

profileRouter.patch('/', contentFilter('name', 'bio', 'username'), async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });

    const body = sanitize(req.body);

    // â”€â”€ Block inappropriate social media links â”€â”€
    const socialFields = ['instagram','tiktok','facebook','twitter','youtube','linkedin','discord','twitch','snapchat','telegram','whatsapp','vk','litmatch'];
    const blockedDomains = ['pornhub','xvideos','xhamster','xnxx','redtube','youporn','brazzers','onlyfans','chaturbate','livejasmin','stripchat','cam4','bongacams','myfreecams','fansly','manyvids'];
    for (const f of socialFields) {
      if (body[f] && typeof body[f] === 'string') {
        const lower = body[f].toLowerCase();
        if (blockedDomains.some(d => lower.includes(d))) {
          return res.status(400).json({ message: 'Uygunsuz iÃ§erik baÄŸlantÄ±sÄ± eklenemez.' });
        }
      }
    }

    const changes = {};
    // cityId, districtId handled specially below â€” not in auto-map list
    const allowed = [
      'name','bio','gender','instagram','tiktok','facebook','twitter',
      'youtube','linkedin','discord','twitch','snapchat','telegram',
      'whatsapp','vk','litmatch','city','district',
      'level','preferredTime','preferredStyle','phone','birthDate',
      'onboardingDone','username','avatarUrl','coverUrl','countryCode'
    ];
    for (const key of allowed) {
      if (body[key] !== undefined) {
        const snakeKey = key.replace(/[A-Z]/g, c => '_' + c.toLowerCase());
        changes[snakeKey] = body[key];
      }
    }

    // â”€â”€ cityId / cityName handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Flutter geo picker sends local state IDs ("34", "6" ...), but users.city_id
    // is a FK to the backend cities table. Only persist a city_id when it actually
    // resolves in the DB; otherwise store the display name and keep the FK null.
    if (body.cityId !== undefined || body.cityName !== undefined) {
      let resolved = false;
      if (body.cityId) {
        try {
          const city = await db.findById('cities', body.cityId);
          if (city) {
            changes.city_id = city.id;
            changes.city = city.name;
            resolved = true;
          }
        } catch { /* not found */ }
      }
      if (!resolved) {
        changes.city_id = null;
        if (body.cityName) changes.city = body.cityName;
        else if (body.city) changes.city = body.city;
      }
    }

    // Store country_code
    if (body.countryCode !== undefined) {
      changes.country_code = body.countryCode;
    }

    // â”€â”€ districtId / districtName handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (body.districtId !== undefined || body.districtName !== undefined) {
      let resolved = false;
      if (body.districtId) {
        try {
          const dist = await db.findById('districts', body.districtId);
          if (dist) { changes.district_id = dist.id; changes.district = dist.name; resolved = true; }
        } catch { /* not found */ }
        if (!resolved) {
          try {
            const dist = await db.findById('districts', 'd' + body.districtId);
            if (dist) { changes.district_id = dist.id; changes.district = dist.name; resolved = true; }
          } catch { /* not found */ }
        }
      }
      if (!resolved) {
        changes.district_id = null;
        if (body.districtName) changes.district = body.districtName;
        else if (body.district) changes.district = body.district;
      }
    }

    // Special: sportIds â†’ sports JSONB
    if (body.sportIds !== undefined) {
      const requestedSportIds = Array.isArray(body.sportIds)
        ? body.sportIds
          .filter(id => typeof id === 'string')
          .map(id => id.trim())
          .filter(Boolean)
        : [];

      if (requestedSportIds.length === 0) {
        changes.sports = [];
      } else {
        try {
          const allSports = await db.query('sports');
          const selectedSports = requestedSportIds
            .map(id => allSports.find(s => s.id === id))
            .filter(Boolean);
          changes.sports = (selectedSports.length > 0 ? selectedSports : requestedSportIds.map(id => ({ id, name: id, icon: 'ğŸ…', category: null })))
            .map(s => ({ id: s.id, name: s.name, icon: s.icon, category: s.category }));
        } catch {
          changes.sports = requestedSportIds.map(id => ({ id, name: id, icon: 'ğŸ…', category: null }));
        }
      }
    }

    if (Object.keys(changes).length > 0) {
      const updated = await db.update('users', req.userId, changes);
      return res.json({ data: { user: safeUser(updated) } });
    }
    res.json({ data: { user: safeUser(user) } });
  } catch (e) {
    console.error('profile patch error:', e);
    res.status(500).json({ message: e.message || 'Profil gÃ¼ncellenemedi.' });
  }
});

app.use('/api/profile', profileRouter);

// â”€â”€ Upload with Supabase Storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const multer = require('multer');
const uploadMiddleware = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/api/upload', authMiddleware, uploadMiddleware.single('file'), async (req, res) => {
  try {
    const type = req.body?.type || 'avatar'; // avatar | cover
    const file = req.file;
    if (!file) {
      // Fallback for clients that send without actual file (placeholder)
      return res.json({ url: `https://placehold.co/400x400/png?text=SP&t=${Date.now()}` });
    }

    const ext = (file.originalname || 'image.jpg').split('.').pop() || 'jpg';
    const filename = `${type}/${req.userId}_${Date.now()}.${ext}`;
    const client = db.raw();

    // Upload to Supabase Storage (bucket: avatars)
    const { data, error } = await client.storage
      .from('avatars')
      .upload(filename, file.buffer, {
        contentType: file.mimetype || 'image/jpeg',
        upsert: true,
      });

    if (error) {
      console.error('Storage upload error:', error);
      // Fallback to placeholder
      return res.json({ url: `https://placehold.co/400x400/png?text=SP&t=${Date.now()}` });
    }

    // Get public URL
    const { data: urlData } = client.storage.from('avatars').getPublicUrl(filename);
    const url = urlData?.publicUrl;

    if (!url) {
      return res.json({ url: `https://placehold.co/400x400/png?text=SP&t=${Date.now()}` });
    }

    // Update user record
    if (type === 'avatar') {
      await db.update('users', req.userId, { avatar_url: url });
    } else if (type === 'cover') {
      await db.update('users', req.userId, { cover_url: url });
    }

    res.json({ url });
  } catch (e) {
    console.error('Upload error:', e);
    res.json({ url: `https://placehold.co/400x400/png?text=SP&t=${Date.now()}` });
  }
});

// â”€â”€ Delete photo (avatar or cover) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.delete('/api/upload', authMiddleware, async (req, res) => {
  try {
    const type = req.query.type || 'avatar'; // avatar | cover
    if (type !== 'avatar' && type !== 'cover') {
      return res.status(400).json({ message: 'type must be avatar or cover' });
    }
    const client = db.raw();

    // Get current user to find the file path
    const user = await db.findOne('users', { id: req.userId });
    const currentUrl = type === 'avatar' ? user?.avatar_url : user?.cover_url;

    if (currentUrl && currentUrl.includes('supabase')) {
      // Extract storage path from public URL
      // URL format: https://xxx.supabase.co/storage/v1/object/public/avatars/<path>
      const marker = '/object/public/avatars/';
      const idx = currentUrl.indexOf(marker);
      if (idx !== -1) {
        const filePath = currentUrl.slice(idx + marker.length);
        await client.storage.from('avatars').remove([filePath]).catch((e) => {
          console.warn('Storage remove warning:', e);
        });
      }
    }

    // Clear the URL in DB
    const updateData = type === 'avatar' ? { avatar_url: null } : { cover_url: null };
    await db.update('users', req.userId, updateData);

    res.json({ success: true });
  } catch (e) {
    console.error('Delete upload error:', e);
    res.status(500).json({ message: 'Sunucu hatasÄ±.' });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  LISTINGS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const listingsRouter = express.Router();
listingsRouter.use(authMiddleware);

listingsRouter.get('/', async (req, res) => {
  try {
    const { sport, city, district, type, level, gender, userId, countryCode, country_code, latitude, longitude, radiusM, page = 1, pageSize = 20 } = req.query;
    const pg = Number(page);
    const ps = Math.min(50, Number(pageSize));
    const skip = (pg - 1) * ps;
    const nowIso = new Date().toISOString();
    const userLatitude = toFiniteNumber(latitude);
    const userLongitude = toFiniteNumber(longitude);
    const hasUserCoordinates = isValidLatitude(userLatitude) && isValidLongitude(userLongitude);
    const nearbyRadiusMeters = toFiniteNumber(radiusM);
    const hasNearbyRadiusFilter = Number.isFinite(nearbyRadiusMeters) && nearbyRadiusMeters > 0;
    const countryFilter = typeof countryCode === 'string'
      ? countryCode
      : (typeof country_code === 'string' ? country_code : null);
    const normalizedCountry = countryFilter ? String(countryFilter).trim().toUpperCase() : '';
    const hasCountryFilter = /^[A-Z]{2,3}$/.test(normalizedCountry);

    const client = db.raw();
    let q = client.from('listings').select('*')
      .in('status', ['ACTIVE', 'MATCHED'])
      .gte('expires_at', nowIso)
      .order('created_at', { ascending: false });

    q = q.or(`date.is.null,date.gte.${nowIso}`);
    if (sport) q = q.or(`sport_id.eq.${sport},sport_name.eq.${sport}`);
    if (city) {
      const cityText = String(city).trim();
      if (cityText) q = q.ilike('city_name', `%${cityText}%`);
    }
    if (district) {
      const districtText = String(district).trim();
      if (districtText) q = q.ilike('district_name', `%${districtText}%`);
    }
    if (type)  q = q.eq('type', type);
    if (level) q = q.eq('level', level);
    if (gender && gender !== 'ANY') q = q.or(`gender.eq.${gender},gender.eq.ANY`);
    if (userId) q = q.eq('user_id', userId);
    q = q.range(skip, skip + ps - 1);

    const { data, error } = await q;
    if (error) return res.status(500).json({ message: error.message });

    let rows = data || [];
    if (hasCountryFilter && rows.length > 0) {
      const userIdsByRows = [...new Set(
        rows
          .filter(r => r.user_id)
          .map(r => r.user_id)
      )];

      const userCountryById = new Map();
      if (userIdsByRows.length > 0) {
        const { data: userRows } = await client
          .from('users')
          .select('id,country_code')
          .in('id', userIdsByRows);
        for (const u of (userRows || [])) {
          userCountryById.set(u.id, String(u.country_code || '').toUpperCase());
        }
      }

      rows = rows.filter(row => {
        const direct = String(row.country_code || '').toUpperCase();
        if (direct) return direct === normalizedCountry;
        const fromOwner = userCountryById.get(row.user_id) || '';
        return fromOwner === normalizedCountry;
      });
    }

    if (hasUserCoordinates) {
      rows = rows
        .map(row => {
          const rowLat = toFiniteNumber(row.latitude);
          const rowLon = toFiniteNumber(row.longitude);
          if (!isValidLatitude(rowLat) || !isValidLongitude(rowLon)) {
            return { ...row, distance_to_user_m: null };
          }
          const distanceToUserM = Math.round(haversineDistanceMeters(
            userLatitude,
            userLongitude,
            rowLat,
            rowLon
          ));
          return { ...row, distance_to_user_m: distanceToUserM };
        })
        .sort((a, b) => {
          const aDistance = Number.isFinite(a.distance_to_user_m)
            ? a.distance_to_user_m
            : Number.MAX_SAFE_INTEGER;
          const bDistance = Number.isFinite(b.distance_to_user_m)
            ? b.distance_to_user_m
            : Number.MAX_SAFE_INTEGER;
          return aDistance - bDistance;
        });

      if (hasNearbyRadiusFilter) {
        rows = rows.filter(row => (
          Number.isFinite(row.distance_to_user_m) && row.distance_to_user_m <= nearbyRadiusMeters
        ));
      }
    }

    const visibleRows = rows.map(row => maskAnonymousListingForViewer(row, req.userId));

    res.json({
      success: true,
      data: visibleRows.map(toCamel),
      pagination: { page: pg, hasNext: (data || []).length >= ps }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.get('/nearby', async (req, res) => {
  try {
    const {
      latitude,
      longitude,
      radiusM = 30000,
      sport,
      type,
      level,
      gender,
      countryCode,
      country_code,
      page = 1,
      pageSize = 20,
    } = req.query;

    const userLatitude = toFiniteNumber(latitude);
    const userLongitude = toFiniteNumber(longitude);
    if (!isValidLatitude(userLatitude) || !isValidLongitude(userLongitude)) {
      return res.status(400).json({ message: 'GeÃ§erli latitude ve longitude gÃ¶nderilmeli.' });
    }

    const radiusMeters = toFiniteNumber(radiusM);
    const effectiveRadius = Number.isFinite(radiusMeters) && radiusMeters > 0
      ? Math.min(radiusMeters, 200000)
      : 30000;
    const pg = Math.max(1, Number(page) || 1);
    const ps = Math.min(50, Math.max(1, Number(pageSize) || 20));
    const nowIso = new Date().toISOString();

    const countryFilter = typeof countryCode === 'string'
      ? countryCode
      : (typeof country_code === 'string' ? country_code : null);
    const normalizedCountry = countryFilter ? String(countryFilter).trim().toUpperCase() : '';
    const hasCountryFilter = /^[A-Z]{2,3}$/.test(normalizedCountry);

    const client = db.raw();
    let q = client.from('listings').select('*')
      .in('status', ['ACTIVE', 'MATCHED'])
      .gte('expires_at', nowIso)
      .or(`date.is.null,date.gte.${nowIso}`)
      .range(0, 499);

    if (sport) q = q.or(`sport_id.eq.${sport},sport_name.eq.${sport}`);
    if (type) q = q.eq('type', type);
    if (level) q = q.eq('level', level);
    if (gender && gender !== 'ANY') q = q.or(`gender.eq.${gender},gender.eq.ANY`);

    const { data, error } = await q;
    if (error) return res.status(500).json({ message: error.message });

    let rows = data || [];
    if (hasCountryFilter && rows.length > 0) {
      const userIdsByRows = [...new Set(
        rows
          .filter(r => r.user_id)
          .map(r => r.user_id)
      )];

      const userCountryById = new Map();
      if (userIdsByRows.length > 0) {
        const { data: userRows } = await client
          .from('users')
          .select('id,country_code')
          .in('id', userIdsByRows);
        for (const u of (userRows || [])) {
          userCountryById.set(u.id, String(u.country_code || '').toUpperCase());
        }
      }

      rows = rows.filter(row => {
        const direct = String(row.country_code || '').toUpperCase();
        if (direct) return direct === normalizedCountry;
        const fromOwner = userCountryById.get(row.user_id) || '';
        return fromOwner === normalizedCountry;
      });
    }

    const withDistance = rows
      .map(row => {
        const rowLat = toFiniteNumber(row.latitude);
        const rowLon = toFiniteNumber(row.longitude);
        if (!isValidLatitude(rowLat) || !isValidLongitude(rowLon)) {
          return null;
        }

        const distanceToUserM = Math.round(haversineDistanceMeters(
          userLatitude,
          userLongitude,
          rowLat,
          rowLon
        ));

        if (distanceToUserM > effectiveRadius) return null;
        return { ...row, distance_to_user_m: distanceToUserM };
      })
      .filter(Boolean)
      .sort((a, b) => a.distance_to_user_m - b.distance_to_user_m);

    const start = (pg - 1) * ps;
    const pageRows = withDistance.slice(start, start + ps);
    const visibleRows = pageRows.map(row => maskAnonymousListingForViewer(row, req.userId));

    res.json({
      success: true,
      data: visibleRows.map(toCamel),
      pagination: {
        page: pg,
        hasNext: start + ps < withDistance.length,
      },
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.get('/:id', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });

    // Enrich with applicants (visible to everyone)
    const allInterests = await db.query('interests', { filters: { listing_id: listing.id } });
    const applicants = [];
    for (const interest of allInterests) {
      const u = await userById(interest.user_id);
      applicants.push({
        id: interest.id,
        userId: interest.user_id,
        userName: u?.name || interest.user_name,
        userAvatar: u?.avatar_url || interest.user_avatar,
        status: interest.status,
        createdAt: interest.created_at,
        // Only listing owner sees messages
        message: listing.user_id === req.userId ? interest.message : null,
      });
    }

    const result = toCamel(maskAnonymousListingForViewer(listing, req.userId));
    result.applicants = applicants;
    result.acceptedUsers = applicants.filter(a => a.status === 'ACCEPTED');
    result.pendingUsers = applicants.filter(a => a.status === 'PENDING');
    result.rejectedCount = applicants.filter(a => a.status === 'REJECTED').length;

    res.json(result);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.post('/', contentFilter('title', 'description'), async (req, res) => {
  try {
    await ensureRequiredListingSports();
    const user = await userById(req.userId);
    const body = sanitize(req.body);
    if (!body.title || body.title.trim().length < 3)
      return res.status(400).json({ message: 'BaÅŸlÄ±k en az 3 karakter olmalÄ±.' });
    if (!body.sportId)
      return res.status(400).json({ message: 'Spor dalÄ± seÃ§ilmeli.' });

    // â”€â”€ Ä°lan tarih validasyonu: max 3 gÃ¼n sonrasÄ± â”€â”€
    const MAX_LISTING_DAYS = 3;
    if (body.dateTime || body.date) {
      const listingDate = new Date(body.dateTime || body.date);
      if (isNaN(listingDate.getTime()))
        return res.status(400).json({ message: 'GeÃ§ersiz tarih formatÄ±.' });
      const now = new Date();
      // GeÃ§miÅŸ tarih kontrolÃ¼ (1 saat tolerans)
      if (listingDate.getTime() < now.getTime() - 3600000)
        return res.status(400).json({ message: 'GeÃ§miÅŸ bir tarih iÃ§in ilan aÃ§Ä±lamaz.' });
      const maxDate = new Date(now.getTime() + MAX_LISTING_DAYS * 24 * 3600 * 1000);
      if (listingDate > maxDate)
        return res.status(400).json({ message: `Ä°lan tarihi en fazla ${MAX_LISTING_DAYS} gÃ¼n sonrasÄ± olabilir.` });
    }

    const sport = await db.findById('sports', body.sportId);
    const hasLatitudeInput = body.latitude !== undefined
      && body.latitude !== null
      && String(body.latitude).trim() !== '';
    const hasLongitudeInput = body.longitude !== undefined
      && body.longitude !== null
      && String(body.longitude).trim() !== '';

    if (hasLatitudeInput !== hasLongitudeInput) {
      return res.status(400).json({ message: 'latitude ve longitude birlikte gÃ¶nderilmeli.' });
    }

    const latitude = hasLatitudeInput ? toFiniteNumber(body.latitude) : null;
    const longitude = hasLongitudeInput ? toFiniteNumber(body.longitude) : null;
    if (hasLatitudeInput && (!isValidLatitude(latitude) || !isValidLongitude(longitude))) {
      return res.status(400).json({ message: 'GeÃ§ersiz konum koordinatlarÄ±.' });
    }
    // NOTE: city_id and district_id have FK constraints to cities/districts tables
    // Flutter sends numeric IDs from states.json (e.g. "2170") but DB has "c1" format
    // So we store null for IDs and rely on city_name/district_name for display

    // expires_at: tarih varsa tarih + 1 gÃ¼n, yoksa 3 gÃ¼n sonra
    const dateVal = body.dateTime || body.date || null;
    const expiresAt = body.expiresAt
      || (dateVal ? new Date(new Date(dateVal).getTime() + 24 * 3600 * 1000).toISOString()
                  : new Date(Date.now() + MAX_LISTING_DAYS * 24 * 3600 * 1000).toISOString());

    const listingRow = {
      id: 'listing_' + uuid(),
      type: body.type || 'RIVAL',
      title: body.title.trim(),
      description: body.description || null,
      sport_id: body.sportId,
      sport_name: sport?.name || null,
      city_id: null,
      city_name: body.cityName || null,
      district_id: null,
      district_name: body.districtName || null,
      latitude,
      longitude,
      venue_id: body.venueId || null,
      venue_name: null,
      level: body.level || 'INTERMEDIATE',
      gender: body.gender || 'ANY',
      date: dateVal,
      image_urls: [],
      max_participants: body.maxParticipants || 0,
      accepted_count: 0,
      status: 'ACTIVE',
      age_min: body.ageMin || null,
      age_max: body.ageMax || null,
      is_recurring: body.isRecurring || false,
      is_anonymous: body.isAnonymous || false,
      is_urgent: body.isUrgent || false,
      is_quick: body.isQuick || false,
      response_count: 0,
      user_id: req.userId,
      user_name: user?.name || null,
      user_avatar: user?.avatar_url || null,
      expires_at: expiresAt,
    };

    const inserted = await db.insert('listings', listingRow);
    res.status(201).json({ listing: toCamel(inserted) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.post('/:id/interest', contentFilter('message'), async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });
    if (listing.user_id === req.userId)
      return res.status(400).json({ message: 'Kendi ilanÄ±nÄ±za baÅŸvuramazsÄ±nÄ±z.' });

    const already = await db.findOne('interests', { listing_id: listing.id, user_id: req.userId });
    if (already)
      return res.json({ interested: true, count: listing.response_count, responseId: already.id });

    const me = await userById(req.userId);
    const interest = {
      id: uuid(), listing_id: listing.id, user_id: req.userId,
      user_name: me?.name || null, user_avatar: me?.avatar_url || null,
      message: req.body.message || null, status: 'PENDING',
    };
    await db.insert('interests', interest);
    await db.update('listings', listing.id, { response_count: (listing.response_count || 0) + 1 });

    await pushNotification({
      userId: listing.user_id, type: 'NEW_INTEREST',
      title: 'Yeni baÅŸvuru',
      body: `${me?.name || 'Birisi'} ilanÄ±nÄ±za baÅŸvurdu.`,
      relatedId: listing.id, senderId: req.userId,
    });

    res.json({ interested: true, count: (listing.response_count || 0) + 1, responseId: interest.id });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.get('/:id/interests', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });

    const pending = await db.query('interests', { filters: { listing_id: listing.id, status: 'PENDING' } });
    const result = [];
    for (const i of pending) {
      const u = await userById(i.user_id);
      result.push({
        id: i.id, userId: i.user_id,
        userName: u?.name || i.user_name,
        userAvatar: u?.avatar_url || i.user_avatar,
        message: listing.user_id === req.userId ? i.message : null,
        status: i.status, createdAt: i.created_at,
      });
    }
    res.json({ interests: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.patch('/:id', contentFilter('description'), async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });
    if (listing.user_id !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });

    const body = sanitize(req.body);
    const changes = {};
    const allowed = {
      level: 'level', gender: 'gender', allowedGender: 'gender',
      date: 'date', dateTime: 'date', description: 'description',
      maxParticipants: 'max_participants', cityId: 'city_id', cityName: 'city_name',
      districtId: 'district_id', districtName: 'district_name',
    };
    for (const [k, col] of Object.entries(allowed)) {
      if (body[k] !== undefined) changes[col] = body[k];
    }

    if (Object.keys(changes).length > 0) {
      const updated = await db.update('listings', listing.id, changes);
      return res.json({ listing: toCamel(updated) });
    }
    res.json({ listing: toCamel(listing) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.patch('/:id/interests/:responseId', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });
    if (listing.user_id !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });

    const interest = await db.findById('interests', req.params.responseId);
    if (!interest) return res.status(404).json({ message: 'BaÅŸvuru bulunamadÄ±.' });
    if (interest.listing_id !== listing.id) {
      return res.status(400).json({ message: 'BaÅŸvuru bu ilana ait deÄŸil.' });
    }

    const { action } = req.body;
    if (action !== 'ACCEPTED' && action !== 'REJECTED')
      return res.status(400).json({ message: "action 'ACCEPTED' veya 'REJECTED' olmalÄ±." });

    const currentStatus = String(interest.status || 'PENDING').toUpperCase();

    if (action === 'REJECTED') {
      if (currentStatus !== 'REJECTED') {
        await db.update('interests', interest.id, { status: action });
        await pushNotification({
          userId: interest.user_id, type: 'RESPONSE_REJECTED',
          title: 'BaÅŸvurunuz reddedildi',
          body: 'BaÅŸvurunuz reddedildi.',
          relatedId: listing.id, senderId: req.userId,
        });
      }
      return res.json({ data: { interest: toCamel({ ...interest, status: action }) } });
    }

    if (currentStatus !== 'PENDING') {
      return res.status(409).json({ message: 'Bu baÅŸvuru zaten iÅŸlendi.' });
    }

    const currentAccepted = listing.accepted_count || 0;
    const slotsNeeded = Math.max(1, (listing.max_participants || 2) - 1);
    if (listing.status === 'MATCHED' || currentAccepted >= slotsNeeded) {
      await db.update('interests', interest.id, { status: 'REJECTED' }).catch(() => {});
      await pushNotification({
        userId: interest.user_id,
        type: 'QUOTA_FULL',
        title: 'Kontenjan doldu',
        body: 'Ä°lanÄ±n kontenjanÄ± dolduÄŸu iÃ§in baÅŸvurunuz otomatik reddedildi.',
        relatedId: listing.id,
        senderId: req.userId,
      });
      return res.status(409).json({ message: 'Ä°lan kontenjanÄ± doldu.' });
    }

    if (listing.date) {
      const client = db.raw();
      const scheduledAt = new Date(listing.date);
      if (!Number.isNaN(scheduledAt.getTime())) {
        const windowStart = new Date(scheduledAt.getTime() - 60000).toISOString();
        const windowEnd = new Date(scheduledAt.getTime() + 60000).toISOString();
        const [ownerConflict, applicantConflict] = await Promise.all([
          client.from('matches').select('id', { count: 'exact', head: true })
            .or(`user1_id.eq.${listing.user_id},user2_id.eq.${listing.user_id}`)
            .in('status', ['SCHEDULED', 'ONGOING'])
            .neq('listing_id', listing.id)
            .gte('scheduled_at', windowStart)
            .lte('scheduled_at', windowEnd),
          client.from('matches').select('id', { count: 'exact', head: true })
            .or(`user1_id.eq.${interest.user_id},user2_id.eq.${interest.user_id}`)
            .in('status', ['SCHEDULED', 'ONGOING'])
            .neq('listing_id', listing.id)
            .gte('scheduled_at', windowStart)
            .lte('scheduled_at', windowEnd),
        ]);

        if ((ownerConflict.count || 0) > 0 || (applicantConflict.count || 0) > 0) {
          return res.status(409).json({
            message: 'Bu tarih ve saatte mevcut bir eÅŸleÅŸme var. LÃ¼tfen farklÄ± bir zaman seÃ§in.',
          });
        }
      }
    }

    if (action === 'ACCEPTED') {
      await db.update('interests', interest.id, { status: action });
      const u1 = await userById(listing.user_id);
      const u2 = await userById(interest.user_id);
      const sport = listing.sport_id ? await db.findById('sports', listing.sport_id) : null;
      const isGroupListing = isPartnerGroupListing(listing);

      let match = null;
      let groupMatch = null;
      if (!isGroupListing) {
        match = {
          id: 'match_' + uuid(), listing_id: listing.id, source: 'LISTING',
          user1_id: listing.user_id, user2_id: interest.user_id,
          status: 'SCHEDULED', u1_approved: false, u2_approved: false,
          scheduled_at: listing.date || null, completed_at: null,
        };
        await db.insert('matches', match);
        await persistMatchParticipants({
          matchId: match.id,
          participantIds: [listing.user_id, interest.user_id],
          ownerId: listing.user_id,
        });
      }

      // Update listing capacity
      const newAccepted = currentAccepted + 1;
      const isFull = newAccepted >= slotsNeeded;
      const updates = { accepted_count: newAccepted };
      let acceptedInterests = [];
      let groupParticipantIds = [];
      let groupParticipantNames = [];
      let groupParticipantUsers = [];
      if (isFull) {
        const client = db.raw();
        const [{ data: remainingPending }, { data: acceptedRows }] = await Promise.all([
          client.from('interests').select('*')
            .eq('listing_id', listing.id)
            .eq('status', 'PENDING'),
          client.from('interests').select('user_id')
            .eq('listing_id', listing.id)
            .eq('status', 'ACCEPTED'),
        ]);
        acceptedInterests = acceptedRows || [];
        updates.status = 'MATCHED';
        await db.updateWhere('interests',
          { listing_id: listing.id, status: 'PENDING' },
          { status: 'REJECTED' }
        );

        if (isGroupListing) {
          groupParticipantIds = [listing.user_id, ...acceptedInterests.map(row => row.user_id)];
          const uniqueParticipantIds = [...new Set(groupParticipantIds.filter(Boolean))];
          const { data: participantUsers } = await client.from('users').select('id,name,avatar_url')
            .in('id', uniqueParticipantIds);
          groupParticipantUsers = participantUsers || [];
          const participantMap = new Map((participantUsers || []).map(user => [user.id, user.name]));
          groupParticipantNames = uniqueParticipantIds
            .map(userId => participantMap.get(userId))
            .filter(Boolean);
          groupParticipantIds = uniqueParticipantIds;

          const existingGroupMatch = await db.findOne('matches', {
            listing_id: listing.id,
          });
          if (existingGroupMatch) {
            groupMatch = existingGroupMatch;
          } else {
            const anchorParticipantId = groupParticipantIds.find(pid => pid && pid !== listing.user_id) || interest.user_id;
            groupMatch = {
              id: 'match_' + uuid(),
              listing_id: listing.id,
              source: 'LISTING',
              user1_id: listing.user_id,
              user2_id: anchorParticipantId,
              status: 'SCHEDULED',
              u1_approved: false,
              u2_approved: false,
              scheduled_at: listing.date || null,
              completed_at: null,
            };
            await db.insert('matches', groupMatch);
          }

          if (groupMatch && groupParticipantIds.length > 0) {
            await persistMatchParticipants({
              matchId: groupMatch.id,
              participantIds: groupParticipantIds,
              ownerId: listing.user_id,
            });
          }
        }

        for (const pending of (remainingPending || [])) {
          await pushNotification({
            userId: pending.user_id,
            type: 'QUOTA_FULL',
            title: 'Kontenjan doldu',
            body: 'Ä°lan kontenjanÄ± dolduÄŸu iÃ§in baÅŸvurunuz otomatik reddedildi.',
            relatedId: listing.id,
            senderId: req.userId,
          });
        }
      }
      await db.update('listings', listing.id, updates);

      if (match) {
        await pushNotification({
          userId: interest.user_id, type: 'RESPONSE_ACCEPTED',
          title: 'BaÅŸvurunuz kabul edildi!',
          body: `${u1?.name || 'Ä°lan sahibi'} baÅŸvurunuzu kabul etti.`,
          relatedId: match.id, senderId: req.userId,
        });
      } else if (isGroupListing && isFull && groupMatch) {
        const matchLink = `/matches/${groupMatch.id}`;
        const notifiedIds = new Set();
        const participantLabel = formatNameList(groupParticipantNames);
        const sportLabel = sport?.name || listing.sport_name || 'spor etkinliÄŸi';

        for (const participantId of groupParticipantIds) {
          if (!participantId || notifiedIds.has(participantId)) continue;
          notifiedIds.add(participantId);
          await pushNotification({
            userId: participantId,
            type: 'NEW_MATCH',
            title: 'Ä°lanÄ±n kotasÄ± tamamlandÄ±',
            body: participantLabel
              ? `${participantLabel} ${sportLabel} iÃ§in eÅŸleÅŸtiler.`
              : `Ä°lanÄ±n kontenjanÄ± doldu. ${sportLabel} iÃ§in grup eÅŸleÅŸmesi tamamlandÄ±.`,
            relatedId: groupMatch.id,
            link: matchLink,
            senderId: req.userId,
            senderName: u1?.name,
            senderAvatar: u1?.avatar_url,
          });
        }
      } else {
        await pushNotification({
          userId: interest.user_id,
          type: 'RESPONSE_ACCEPTED',
          title: 'BaÅŸvurunuz onaylandÄ±',
          body: `${u1?.name || 'Ä°lan sahibi'} baÅŸvurunuzu onayladÄ±. Kontenjan dolunca grup eÅŸleÅŸmesi tamamlanacak.`,
          relatedId: null,
          link: `/listings/${listing.id}`,
          senderId: req.userId,
        });
      }

      const response = { interest: toCamel({ ...interest, status: action }) };
      if (match) {
        response.match = {
          ...toCamel(match), user1: safeUser(u1), user2: safeUser(u2),
          listing: { id: listing.id, type: listing.type, sportId: listing.sport_id, sport: sport ? toCamel(sport) : null },
        };
      } else if (groupMatch) {
        const displayUser2Id = pickDisplayUser2IdForViewer({
          match: groupMatch,
          participantIds: groupParticipantIds,
          viewerId: req.userId,
        });
        const participantMap = new Map(groupParticipantUsers.map(user => [user.id, user]));
        const displayUser2 = participantMap.get(displayUser2Id) || u2;

        response.match = {
          ...toCamel(groupMatch),
          user2Id: displayUser2Id,
          isGroupMatch: true,
          participantCount: groupParticipantIds.length,
          participants: groupParticipantIds
            .map(userId => safeUser(participantMap.get(userId)))
            .filter(Boolean),
          user1: safeUser(u1),
          user2: safeUser(displayUser2),
          listing: { id: listing.id, type: listing.type, sportId: listing.sport_id, sport: sport ? toCamel(sport) : null },
        };
      }
      return res.json({ data: response });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.delete('/:id', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'Ä°lan bulunamadÄ±.' });
    if (listing.user_id !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });
    await db.removeWhere('interests', { listing_id: listing.id });
    await db.remove('listings', listing.id);
    res.json({ message: 'Ä°lan silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.delete('/:id/interest', async (req, res) => {
  try {
    await db.removeWhere('interests', { listing_id: req.params.id, user_id: req.userId });
    res.json({ message: 'BaÅŸvuru geri Ã§ekildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/listings', listingsRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  MATCHES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const matchesRouter = express.Router();
matchesRouter.use(authMiddleware);

matchesRouter.get('/', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;

    const client = db.raw();
    const [directMatchesRes, acceptedListingsRes] = await Promise.all([
      client.from('matches').select('*')
        .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
        .order('created_at', { ascending: false }),
      client.from('interests').select('listing_id')
        .eq('user_id', req.userId)
        .eq('status', 'ACCEPTED'),
    ]);

    const allMatches = [];
    const seenMatchIds = new Set();
    for (const row of (directMatchesRes.data || [])) {
      if (!row?.id || seenMatchIds.has(row.id)) continue;
      seenMatchIds.add(row.id);
      allMatches.push(row);
    }

    const acceptedListingIds = [...new Set((acceptedListingsRes.data || [])
      .map(row => row.listing_id)
      .filter(Boolean))];

    if (acceptedListingIds.length > 0) {
      const { data: groupListingRows } = await client.from('listings').select('id,type,max_participants')
        .in('id', acceptedListingIds)
        .eq('type', 'PARTNER')
        .gt('max_participants', 2);

      const eligibleGroupListingIds = [...new Set((groupListingRows || []).map(row => row.id).filter(Boolean))];
      const { data: groupListingMatches } = eligibleGroupListingIds.length > 0
        ? await client.from('matches').select('*')
          .in('listing_id', eligibleGroupListingIds)
          .order('created_at', { ascending: false })
        : { data: [] };

      const latestByListing = new Map();
      for (const row of (groupListingMatches || [])) {
        if (!row?.listing_id) continue;
        if (!latestByListing.has(row.listing_id)) latestByListing.set(row.listing_id, row);
      }

      for (const row of latestByListing.values()) {
        if (!row?.id || seenMatchIds.has(row.id)) continue;
        seenMatchIds.add(row.id);
        allMatches.push(row);
      }
    }

    const sortedMatches = allMatches.sort((a, b) =>
      new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
    );
    const total = sortedMatches.length;
    const matches = sortedMatches.slice(offset, offset + limit);
    if (matches.length === 0) {
      return res.json({ data: [], pagination: { page, hasNext: false, total } });
    }

    const listingIds = [...new Set(matches.map(m => m.listing_id).filter(Boolean))];
    const listingsArr = listingIds.length > 0
      ? (await client.from('listings').select('*').in('id', listingIds)).data || []
      : [];

    const listingsMap = new Map(listingsArr.map(l => [l.id, l]));
    const groupListingIds = [...new Set(matches
      .map(m => m.listing_id)
      .filter(listingId => {
        if (!listingId) return false;
        return isPartnerGroupListing(listingsMap.get(listingId));
      }))];

    const persistedByMatch = await getPersistedParticipantsByMatch(
      matches.map(m => m.id).filter(Boolean)
    );

    const acceptedByListingArr = groupListingIds.length > 0
      ? (await client.from('interests').select('listing_id,user_id')
        .in('listing_id', groupListingIds)
        .eq('status', 'ACCEPTED')).data || []
      : [];

    const acceptedByListingMap = new Map();
    for (const row of acceptedByListingArr) {
      if (!row?.listing_id || !row.user_id) continue;
      if (!acceptedByListingMap.has(row.listing_id)) acceptedByListingMap.set(row.listing_id, new Set());
      acceptedByListingMap.get(row.listing_id).add(row.user_id);
    }

    const userIds = new Set();
    const participantIdsByMatch = new Map();
    for (const m of matches) {
      const listing = m.listing_id ? listingsMap.get(m.listing_id) : null;
      const isGroupMatch = isGroupMatchRecord(m, listing);

      const participantIds = new Set([m.user1_id, m.user2_id].filter(Boolean));
      const persisted = persistedByMatch.get(m.id);
      if (persisted && persisted.size > 0) {
        for (const userId of persisted) participantIds.add(userId);
      } else if (isGroupMatch && listing?.id) {
        if (listing.user_id) participantIds.add(listing.user_id);
        const acceptedSet = acceptedByListingMap.get(listing.id);
        if (acceptedSet) {
          for (const userId of acceptedSet) participantIds.add(userId);
        }
      }

      const participantList = [...participantIds];
      participantIdsByMatch.set(m.id, participantList);
      for (const userId of participantList) userIds.add(userId);
    }

    const ratedByMeByMatch = new Map();
    const matchIds = matches.map(m => m.id).filter(Boolean);
    if (matchIds.length > 0) {
      const { data: ratedRows } = await client.from('ratings')
        .select('match_id,ratee_id')
        .eq('rater_id', req.userId)
        .in('match_id', matchIds);

      for (const row of (ratedRows || [])) {
        if (!row?.match_id || !row.ratee_id) continue;
        if (!ratedByMeByMatch.has(row.match_id)) ratedByMeByMatch.set(row.match_id, new Set());
        ratedByMeByMatch.get(row.match_id).add(row.ratee_id);
      }
    }

    const gpsVerificationsByMatch = await getMatchLocationVerificationRows(matchIds);

    const usersArr = userIds.size > 0
      ? (await client.from('users').select('*').in('id', [...userIds])).data || []
      : [];
    const usersMap = new Map(usersArr.map(u => [u.id, u]));

    const sportIds = new Set(listingsArr.filter(l => l.sport_id).map(l => l.sport_id));
    const sportsArr = sportIds.size > 0
      ? (await client.from('sports').select('*').in('id', [...sportIds])).data || []
      : [];
    const sportsMap = new Map(sportsArr.map(s => [s.id, s]));

    const enriched = matches.map(m => {
      const listing = m.listing_id ? listingsMap.get(m.listing_id) : null;
      const sport = listing?.sport_id ? sportsMap.get(listing.sport_id) : null;
      const participantIds = participantIdsByMatch.get(m.id) || [m.user1_id, m.user2_id].filter(Boolean);
      const displayUser2Id = pickDisplayUser2IdForViewer({
        match: m,
        participantIds,
        viewerId: req.userId,
      });
      const u1 = usersMap.get(m.user1_id);
      const u2 = usersMap.get(displayUser2Id) || usersMap.get(m.user2_id);

      return {
        ...toCamel(m),
        user2Id: displayUser2Id,
        isGroupMatch: isGroupMatchRecord(m, listing),
        participantCount: participantIds.length,
        ratedByMeUserIds: [...(ratedByMeByMatch.get(m.id) || new Set())],
        gpsVerifiedByMe: (gpsVerificationsByMatch.get(m.id) || [])
          .some(row => row.user_id === req.userId && !!row.rewarded_at),
        participants: participantIds
          .map(userId => safeUser(usersMap.get(userId)))
          .filter(Boolean),
        user1: safeUser(u1),
        user2: safeUser(u2),
        listing: listing ? { id: listing.id, type: listing.type, sport: sport ? toCamel(sport) : null } : null,
      };
    });

    res.json({
      data: enriched,
      pagination: { page, hasNext: offset + limit < total, total },
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.get('/:id', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });
    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    if (!participantIds.includes(req.userId)) {
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });
    }

    const displayUser2Id = pickDisplayUser2IdForViewer({
      match: m,
      participantIds,
      viewerId: req.userId,
    });

    const client = db.raw();
    const userIds = [...new Set([...participantIds, m.user1_id, m.user2_id, displayUser2Id].filter(Boolean))];
    const usersArr = userIds.length > 0
      ? (await client.from('users').select('*').in('id', userIds)).data || []
      : [];
    const usersMap = new Map(usersArr.map(u => [u.id, u]));

    const u1 = usersMap.get(m.user1_id) || await userById(m.user1_id);
    const u2 = usersMap.get(displayUser2Id) || usersMap.get(m.user2_id) || await userById(m.user2_id);
    const sport = listing?.sport_id ? await db.findById('sports', listing.sport_id) : null;
    const { data: ratedRows } = await client.from('ratings')
      .select('ratee_id')
      .eq('match_id', m.id)
      .eq('rater_id', req.userId);

    const ratedByMeUserIds = [...new Set((ratedRows || []).map(row => row.ratee_id).filter(Boolean))];
    const gpsRows = (await getMatchLocationVerificationRows([m.id])).get(m.id) || [];
    const gpsVerifiedByMe = gpsRows.some(row => row.user_id === req.userId && !!row.rewarded_at);

    res.json({
      data: {
        ...toCamel(m),
        user2Id: displayUser2Id,
        isGroupMatch: isGroupMatchRecord(m, listing),
        participantCount: participantIds.length,
        ratedByMeUserIds,
        gpsVerifiedByMe,
        participants: participantIds
          .map(userId => safeUser(usersMap.get(userId)))
          .filter(Boolean),
        user1: safeUser(u1),
        user2: safeUser(u2),
        listing: listing ? { id: listing.id, type: listing.type, sport: sport ? toCamel(sport) : null } : null,
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/complete', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    if (!participantIds.includes(req.userId)) {
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });
    }

    const updated = await db.update('matches', m.id, { status: 'COMPLETED', completed_at: new Date().toISOString() });
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.patch('/:id/approve', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });
    if (m.status === 'COMPLETED' || m.status === 'CANCELLED') return res.json({ data: toCamel(m) });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    const participantSet = new Set(participantIds);
    if (!participantSet.has(req.userId)) {
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });
    }

    const isGroupMatch = isGroupMatchRecord(m, listing);

    const changes = {};
    if (m.user1_id === req.userId) changes.u1_approved = true;
    else changes.u2_approved = true;

    const bothApproved =
      (m.user1_id === req.userId ? true : m.u1_approved) &&
      (m.user1_id === req.userId ? m.u2_approved : true);

    if (bothApproved) {
      changes.status = 'COMPLETED';
      changes.completed_at = new Date().toISOString();

      const rewardUserIds = isGroupMatch
        ? participantIds
        : [m.user1_id, m.user2_id].filter(Boolean);

      const users = await Promise.all([...new Set(rewardUserIds)].map(userById));
      for (const user of users) {
        if (!user) continue;
        await db.update('users', user.id, {
          total_matches: (user.total_matches || 0) + 1,
          total_points: (user.total_points || 0) + 10,
        });
      }

      const approver = await userById(req.userId);
      for (const user of users) {
        if (!user) continue;
        await pushNotification({
          userId: user.id,
          type: 'MATCH_COMPLETED',
          title: 'â­ DeÄŸerlendirme ZamanÄ±!',
          body: isGroupMatch
            ? 'Grup maÃ§Ä± tamamlandÄ±. Partnerlerini deÄŸerlendirebilirsin.'
            : `${approver?.name || 'Rakibin'} maÃ§Ä± oynadÄ±ÄŸÄ±nÄ± onayladÄ±`,
          relatedId: m.id,
          senderId: req.userId,
          senderName: approver?.name,
          senderAvatar: approver?.avatar_url,
        });
      }
    } else {
      const approver = await userById(req.userId);
      const awaitingIds = [];

      if (isGroupMatch) {
        if (req.userId === m.user1_id) {
          for (const participantId of participantIds) {
            if (participantId && participantId !== m.user1_id) awaitingIds.push(participantId);
          }
        } else {
          awaitingIds.push(m.user1_id);
        }
      } else {
        awaitingIds.push(req.userId === m.user1_id ? m.user2_id : m.user1_id);
      }

      for (const awaitingId of [...new Set(awaitingIds.filter(Boolean))]) {
        await pushNotification({
          userId: awaitingId,
          type: 'MATCH_STATUS_CHANGED',
          title: 'âš½ MaÃ§Ä± OynadÄ±nÄ±z mÄ±?',
          body: `${approver?.name || 'Rakibin'} maÃ§Ä± oynadÄ±ÄŸÄ±nÄ± onayladÄ±`,
          relatedId: m.id,
          senderId: req.userId,
          senderName: approver?.name,
          senderAvatar: approver?.avatar_url,
        });
      }
    }

    const updated = await db.update('matches', m.id, changes);
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/otp/request', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    const participantSet = new Set(participantIds);
    if (!participantSet.has(req.userId))
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });

    if (m.status === 'COMPLETED' || m.status === 'CANCELLED') {
      return res.status(400).json({ message: 'Bu maÃ§ iÃ§in OTP gÃ¶nderilemez.' });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await db.insert('otps', {
      id: uuid(), match_id: m.id, requester_id: req.userId,
      code, expires_at: expiresAt, used_at: null,
    });

    let otherId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    if (req.userId === m.user1_id && isGroupMatchRecord(m, listing)) {
      otherId = participantIds.find(userId => userId && userId !== m.user1_id) || m.user2_id;
    }

    const requester = await userById(req.userId);
    if (otherId) {
      await pushNotification({
        userId: otherId, type: 'MATCH_OTP_REQUESTED',
        title: 'ğŸ” DoÄŸrulama Kodu Ä°stendi',
        body: `${requester?.name || 'Rakibin'} maÃ§ doÄŸrulamasÄ± iÃ§in kod istedi.`,
        relatedId: m.id, senderId: req.userId,
      });
    }

    res.json({ message: 'DoÄŸrulama kodu oluÅŸturuldu.', devCode: code, expiresAt });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/otp/verify', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: 'DoÄŸrulama kodu gerekli.' });

    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    if (!participantIds.includes(req.userId)) {
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });
    }

    const client = db.raw();
    const { data: otps } = await client.from('otps').select('*')
      .eq('match_id', m.id).eq('code', String(code))
      .is('used_at', null).gt('expires_at', new Date().toISOString())
      .limit(1);

    const otp = otps?.[0];
    if (!otp) return res.status(400).json({ message: 'GeÃ§ersiz veya sÃ¼resi dolmuÅŸ doÄŸrulama kodu.' });

    await db.update('otps', otp.id, { used_at: new Date().toISOString() });
    const newTrust = Math.min(100, (m.trust_score || 0) + 40);
    await db.update('matches', m.id, { trust_score: newTrust });
    res.json({ message: 'MaÃ§ doÄŸrulandÄ±.', trustScore: newTrust });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/gps/verify', async (req, res) => {
  try {
    const latitude = toFiniteNumber(req.body?.latitude);
    const longitude = toFiniteNumber(req.body?.longitude);

    if (!isValidLatitude(latitude) || !isValidLongitude(longitude)) {
      return res.status(400).json({ message: 'GeÃ§erli enlem ve boylam gerekli.' });
    }

    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    if (!participantIds.includes(req.userId)) {
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });
    }

    if (!hasMatchLocationVerificationsTable) {
      return res.status(503).json({ message: 'GPS doÄŸrulama altyapÄ±sÄ± hazÄ±r deÄŸil. Migration Ã§alÄ±ÅŸtÄ±rÄ±lmalÄ±.' });
    }

    const nowIso = new Date().toISOString();

    let verificationRows = (await getMatchLocationVerificationRows([m.id])).get(m.id) || [];
    if (!hasMatchLocationVerificationsTable) {
      return res.status(503).json({ message: 'GPS doÄŸrulama altyapÄ±sÄ± hazÄ±r deÄŸil. Migration Ã§alÄ±ÅŸtÄ±rÄ±lmalÄ±.' });
    }

    const existing = verificationRows.find(row => row.user_id === req.userId);
    if (existing) {
      await db.update('match_location_verifications', existing.id, {
        latitude,
        longitude,
        verified_at: nowIso,
      });
    } else {
      await db.insert('match_location_verifications', {
        id: 'mlv_' + uuid(),
        match_id: m.id,
        user_id: req.userId,
        latitude,
        longitude,
        verified_at: nowIso,
        rewarded_at: null,
        distance_to_listing_m: null,
      });
    }

    verificationRows = (await getMatchLocationVerificationRows([m.id])).get(m.id) || [];
    const qualificationByUser = buildGpsQualificationByUser(verificationRows, listing);

    const newlyRewardedUserIds = [];
    for (const row of verificationRows) {
      if (!row?.id || !row.user_id || row.rewarded_at) continue;
      const qualification = qualificationByUser.get(row.user_id);
      if (!qualification?.qualifies) continue;

      await db.update('match_location_verifications', row.id, {
        rewarded_at: nowIso,
        distance_to_listing_m: qualification.distanceToListingM,
      });
      newlyRewardedUserIds.push(row.user_id);
    }

    let trustScore = Number(m.trust_score || 0);
    if (newlyRewardedUserIds.length > 0) {
      trustScore = Math.min(100, trustScore + (newlyRewardedUserIds.length * MATCH_GPS_TRUST_REWARD));
      await db.update('matches', m.id, { trust_score: trustScore });
    }

    verificationRows = (await getMatchLocationVerificationRows([m.id])).get(m.id) || [];
    const myVerification = verificationRows.find(row => row.user_id === req.userId);
    const myQualification = qualificationByUser.get(req.userId);
    const myVerified = !!myVerification?.rewarded_at;

    res.json({
      message: myVerified
        ? 'Konum doÄŸrulandÄ±.'
        : 'Konum kaydedildi. KarÅŸÄ± taraf doÄŸrulamasÄ± bekleniyor.',
      trustScore,
      gpsVerified: myVerified,
      waitingForOthers: !myVerified,
      distanceToListingM: myQualification?.distanceToListingM ?? null,
    });
  } catch (e) {
    if (isMissingRelationError(e, 'match_location_verifications')) {
      hasMatchLocationVerificationsTable = false;
      return res.status(503).json({ message: 'GPS doÄŸrulama altyapÄ±sÄ± hazÄ±r deÄŸil. Migration Ã§alÄ±ÅŸtÄ±rÄ±lmalÄ±.' });
    }
    res.status(500).json({ message: e.message });
  }
});

matchesRouter.post('/:id/noshow', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });

    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const participantIds = await getMatchParticipantIds(m, listing);
    if (!participantIds.includes(req.userId))
      return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });

    const already = await db.findOne('noshows', { match_id: m.id, reporter_id: req.userId });
    if (already) return res.status(409).json({ message: 'Bu maÃ§ iÃ§in zaten rapor ettiniz.' });

    let reportedId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    if (req.userId === m.user1_id && isGroupMatchRecord(m, listing)) {
      reportedId = participantIds.find(userId => userId && userId !== m.user1_id) || m.user2_id;
    }

    await db.insert('noshows', { id: uuid(), match_id: m.id, reporter_id: req.userId, reported_id: reportedId });

    const reported = await userById(reportedId);
    if (reported) await db.update('users', reportedId, { no_show_count: (reported.no_show_count || 0) + 1 });

    const reporter = await userById(req.userId);
    await pushNotification({
      userId: reportedId, type: 'NO_SHOW_WARNING',
      title: 'âš ï¸ Gelmedi Raporu',
      body: `${reporter?.name || 'Rakibin'} maÃ§a gelmediÄŸinizi bildirdi.`,
      relatedId: m.id, senderId: req.userId,
    });
    res.json({ message: 'Rapor kaydedildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/matches', matchesRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CONVERSATIONS & MESSAGES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const convsRouter = express.Router();
convsRouter.use(authMiddleware);

function normalizeJsonObject(raw) {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try { return JSON.parse(raw); } catch { return {}; }
  }
  return typeof raw === 'object' ? raw : {};
}

function getUnreadCountForUser(conversation, userId) {
  const unreadFor = normalizeJsonObject(conversation.unread_for);
  const rawCount = unreadFor[userId];
  return typeof rawCount === 'number' ? rawCount : parseInt(rawCount || '0', 10) || 0;
}

async function findOrCreateConv(u1, u2) {
  const client = db.raw();
  const { data } = await client.from('conversations').select('*')
    .or(`and(user1_id.eq.${u1},user2_id.eq.${u2}),and(user1_id.eq.${u2},user2_id.eq.${u1})`)
    .limit(1);
  if (data?.[0]) {
    await db.update('conversations', data[0].id, { updated_at: new Date().toISOString() });
    return data[0];
  }
  return db.insert('conversations', {
    id: uuid(), user1_id: u1, user2_id: u2, type: 'direct',
    updated_at: new Date().toISOString(),
  });
}

convsRouter.post('/', async (req, res) => {
  try {
    const { targetUserId } = req.body;
    if (!targetUserId) return res.status(400).json({ message: 'targetUserId gerekli.' });
    const conv = await findOrCreateConv(req.userId, targetUserId);
    res.status(201).json({ data: { id: conv.id } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

convsRouter.get('/', async (req, res) => {
  try {
    const client = db.raw();
    const { data } = await client.from('conversations').select('*')
      .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
      .order('updated_at', { ascending: false });

    const convs = data || [];
    const otherIds = [...new Set(convs.map(c => (c.user1_id === req.userId ? c.user2_id : c.user1_id)))];
    const others = otherIds.length > 0
      ? (await client.from('users').select('id,name,avatar_url').in('id', otherIds)).data || []
      : [];
    const othersMap = new Map(others.map(u => [u.id, u]));

    const result = convs.map(c => {
      const otherId = c.user1_id === req.userId ? c.user2_id : c.user1_id;
      const other = othersMap.get(otherId);
      const lastMsgRaw = c.last_message;
      const lastMsgObj = normalizeJsonObject(lastMsgRaw);
      const lastMessage = lastMsgRaw
        ? {
            content: typeof lastMsgRaw === 'string' ? lastMsgRaw : (lastMsgObj.content || String(lastMsgRaw)),
            createdAt: lastMsgObj.createdAt || c.updated_at || c.created_at,
            isMine: lastMsgObj.senderId === req.userId,
          }
        : null;
      const convData = toCamel(c);
      delete convData.lastMessage;
      return {
        ...convData,
        type: c.type || 'direct',
        hasUnread: getUnreadCountForUser(c, req.userId) > 0,
        lastMessage,
        partner: other
          ? { id: other.id, name: other.name, avatarUrl: other.avatar_url || null }
          : { id: otherId, name: 'Bilinmeyen', avatarUrl: null },
      };
    });
    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

convsRouter.patch('/:id/read', async (req, res) => {
  try {
    const conv = await db.findById('conversations', req.params.id);
    if (!conv) return res.status(404).json({ message: 'KonuÅŸma bulunamadÄ±.' });
    if (conv.user1_id !== req.userId && conv.user2_id !== req.userId) {
      return res.status(403).json({ message: 'Bu konuÅŸmaya eriÅŸiminiz yok.' });
    }
    const unreadFor = normalizeJsonObject(conv.unread_for);
    unreadFor[req.userId] = 0;
    await db.update('conversations', conv.id, { unread_for: unreadFor });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

convsRouter.get('/:id/messages', async (req, res) => {
  try {
    const msgs = await db.query('messages', {
      filters: { conversation_id: req.params.id },
      order: 'created_at', ascending: true,
    });
    res.json({ data: { messages: msgs.map(toCamel), nextCursor: null } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

convsRouter.post('/:id/messages', contentFilter('content'), async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || content.trim().length < 1)
      return res.status(400).json({ message: 'Mesaj iÃ§eriÄŸi gerekli.' });
    const conv = await db.findById('conversations', req.params.id);
    if (!conv) return res.status(404).json({ message: 'KonuÅŸma bulunamadÄ±.' });
    if (conv.user1_id !== req.userId && conv.user2_id !== req.userId) {
      return res.status(403).json({ message: 'Bu konuÅŸmaya eriÅŸiminiz yok.' });
    }

    const trimmedContent = content.trim();
    const createdAt = new Date().toISOString();
    const msg = await db.insert('messages', {
      id: uuid(), conversation_id: req.params.id,
      sender_id: req.userId, content: trimmedContent,
    });
    const otherUserId = conv.user1_id === req.userId ? conv.user2_id : conv.user1_id;
    const unreadFor = normalizeJsonObject(conv.unread_for);
    unreadFor[req.userId] = 0;
    unreadFor[otherUserId] = getUnreadCountForUser({ unread_for: unreadFor }, otherUserId) + 1;
    await db.update('conversations', req.params.id, {
      last_message: { content: trimmedContent, senderId: req.userId, createdAt },
      unread_for: unreadFor,
      updated_at: createdAt,
    }).catch(() => {});

    const sender = await userById(req.userId);
    await pushNotification({
      userId: otherUserId,
      type: 'NEW_MESSAGE',
      title: 'Yeni mesaj',
      body: `${sender?.name || 'Birisi'} size mesaj gÃ¶nderdi.`,
      relatedId: req.params.id,
      senderId: req.userId,
      senderName: sender?.name,
      senderAvatar: sender?.avatar_url,
    });

    res.status(201).json({ data: toCamel(msg) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/conversations', convsRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  USERS (profile, follow, block)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const usersRouter = express.Router();
usersRouter.use(authMiddleware);

usersRouter.get('/me/referral', async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });
    const code = user.referral_code || `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    if (!user.referral_code) await db.update('users', user.id, { referral_code: code });
    const referred = await db.query('users', { filters: { referred_by: code } });
    res.json({
      referralCode: code, referralCount: referred.length,
      referralPoints: referred.length * 50,
      referredUsers: referred.map(u => ({
        id: u.id, name: u.name, avatarUrl: u.avatar_url, createdAt: u.created_at
      })),
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.get('/:id', async (req, res) => {
  try {
    const user = await userById(req.params.id);
    if (!user) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });

    const follow = await db.findOne('follows', { follower_id: req.userId, following_id: user.id });
    const isBlockedByMe = !!(await db.findOne('blocked_users', { blocker_id: req.userId, blocked_id: user.id }));
    const privacy = await getPrivacy(user.id);
    const canSeeProfile = await canViewerSee(req.userId, user.id, privacy.profileVisibility);

    if (req.userId !== user.id && !canSeeProfile) {
      return res.json({
        data: {
          id: user.id, name: user.name, username: user.username,
          avatarUrl: user.avatar_url, coverUrl: user.cover_url,
          followerCount: user.follower_count || 0, followersCount: user.follower_count || 0,
          followingCount: user.following_count || 0, totalMatches: user.total_matches || 0,
          sports: user.sports || [],
          avgRating: user.average_rating || 0,
          averageRating: user.average_rating || 0,
          ratingCount: user.rating_count || 0,
          isPrivateProfile: true, isRestricted: true,
          isFollowing: follow?.status === 'accepted', isPending: follow?.status === 'pending',
          isBlockedByMe: false,
        }
      });
    }

    const safe = safeUser(user);
    const socialClickableByPlatform = {};
    const platformVisibility = privacy.socialPlatformVisibility || {};
    let hasSocialLink = false;
    let hasLockedSocial = false;

    for (const p of SOCIAL_PLATFORMS) {
      const value = safe[p];
      const hasValue = typeof value === 'string' ? value.trim().length > 0 : !!value;
      if (!hasValue) continue;

      hasSocialLink = true;
      let canClick = await canViewerSee(req.userId, user.id, platformVisibility[p]);

      // Bot social links are visible for realism but never clickable for other users.
      if (user.is_bot && req.userId !== user.id) canClick = false;

      socialClickableByPlatform[p] = canClick;
      if (!canClick) hasLockedSocial = true;
    }

    res.json({
      data: {
        ...safe,
        followersCount: user.follower_count || 0,
        avgRating: user.average_rating || 0,
        averageRating: user.average_rating || 0,
        ratingCount: user.rating_count || 0,
        socialLinksVisible: hasSocialLink,
        socialLinksClickable: hasSocialLink ? !hasLockedSocial : true,
        socialClickableByPlatform,
        isFollowing: follow?.status === 'accepted',
        isPending: follow?.status === 'pending',
        isBlockedByMe,
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.get('/:id/interests', async (req, res) => {
  try {
    const interests = await db.query('interests', { filters: { user_id: req.params.id } });
    res.json({ data: interests.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.post('/:id/follow', async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.userId) return res.status(400).json({ message: 'Kendini takip edemezsin.' });

    const existing = await db.findOne('follows', { follower_id: req.userId, following_id: targetId });
    if (existing) {
      // Unfollow
      await db.remove('follows', existing.id);
      if (existing.status === 'accepted') {
        const target = await userById(targetId);
        const me = await userById(req.userId);
        if (target) await db.update('users', targetId, { follower_count: Math.max(0, (target.follower_count || 1) - 1) });
        if (me) await db.update('users', req.userId, { following_count: Math.max(0, (me.following_count || 1) - 1) });
      }
      return res.json({ following: false, pending: false });
    }

    const target = await userById(targetId);
    if (!target) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });

    const status = target.is_private ? 'pending' : 'accepted';
    await db.insert('follows', { id: uuid(), follower_id: req.userId, following_id: targetId, status });

    if (status === 'accepted') {
      await db.update('users', targetId, { follower_count: (target.follower_count || 0) + 1 });
      const me = await userById(req.userId);
      if (me) await db.update('users', req.userId, { following_count: (me.following_count || 0) + 1 });
    }

    const me = await userById(req.userId);
    await pushNotification({
      userId: targetId,
      type: status === 'pending' ? 'FOLLOW_REQUEST' : 'NEW_FOLLOWER',
      title: status === 'pending' ? 'Yeni takip isteÄŸi' : 'Seni takip etmeye baÅŸladÄ±',
      body: `${me?.name || 'Birisi'} ${status === 'pending' ? 'seni takip etmek istiyor' : 'seni takip etmeye baÅŸladÄ±'}.`,
      relatedId: req.userId, senderId: req.userId,
      senderName: me?.name, senderAvatar: me?.avatar_url,
    });
    res.json({ following: status === 'accepted', pending: status === 'pending' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.get('/:id/followers', async (req, res) => {
  try {
    const targetUser = await userById(req.params.id);
    if (!targetUser) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });
    if (targetUser.is_bot && req.userId !== targetUser.id) {
      return res.status(403).json({ message: 'Bot takip listesi gizlidir.' });
    }

    const accepted = await db.query('follows', { filters: { following_id: req.params.id, status: 'accepted' } });
    const result = [];
    for (const f of accepted) {
      const follower = await userById(f.follower_id);
      if (!follower) continue;
      const rev = await db.findOne('follows', { follower_id: req.userId, following_id: f.follower_id });
      result.push({
        id: f.id, user: safeUser(follower),
        isFollowingBack: rev?.status === 'accepted',
        pendingFollow: rev?.status === 'pending',
        createdAt: f.created_at,
      });
    }
    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.get('/:id/following', async (req, res) => {
  try {
    const targetUser = await userById(req.params.id);
    if (!targetUser) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });
    if (targetUser.is_bot && req.userId !== targetUser.id) {
      return res.status(403).json({ message: 'Bot takip listesi gizlidir.' });
    }

    const accepted = await db.query('follows', { filters: { follower_id: req.params.id, status: 'accepted' } });
    const result = [];
    for (const f of accepted) {
      const followed = await userById(f.following_id);
      if (!followed) continue;
      const rev = await db.findOne('follows', { follower_id: req.userId, following_id: f.following_id });
      result.push({
        id: f.id, user: safeUser(followed),
        isFollowingBack: rev?.status === 'accepted',
        pendingFollow: rev?.status === 'pending',
        createdAt: f.created_at,
      });
    }
    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.delete('/:id/followers', async (req, res) => {
  try {
    const f = await db.findOne('follows', { follower_id: req.params.id, following_id: req.userId, status: 'accepted' });
    if (!f) return res.status(404).json({ message: 'TakipÃ§i bulunamadÄ±.' });
    await db.remove('follows', f.id);
    const me = await userById(req.userId);
    const follower = await userById(req.params.id);
    if (me) await db.update('users', req.userId, { follower_count: Math.max(0, (me.follower_count || 1) - 1) });
    if (follower) await db.update('users', req.params.id, { following_count: Math.max(0, (follower.following_count || 1) - 1) });
    res.json({ message: 'TakipÃ§i kaldÄ±rÄ±ldÄ±.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.post('/:id/block', async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.userId) return res.status(400).json({ message: 'Kendini engelleyemezsin.' });
    const already = await db.findOne('blocked_users', { blocker_id: req.userId, blocked_id: targetId });
    if (!already) await db.insert('blocked_users', { id: uuid(), blocker_id: req.userId, blocked_id: targetId });
    // Remove follow relationships
    await db.removeWhere('follows', { follower_id: req.userId, following_id: targetId }).catch(() => {});
    await db.removeWhere('follows', { follower_id: targetId, following_id: req.userId }).catch(() => {});
    res.json({ message: 'KullanÄ±cÄ± engellendi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.delete('/:id/block', async (req, res) => {
  try {
    await db.removeWhere('blocked_users', { blocker_id: req.userId, blocked_id: req.params.id });
    res.json({ message: 'Engel kaldÄ±rÄ±ldÄ±.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.post('/:id/report', async (req, res) => {
  res.json({ message: 'Åikayet alÄ±ndÄ±.' });
});

usersRouter.get('/:id/ratings', async (req, res) => {
  try {
    const ratings = await db.query('ratings', {
      filters: { ratee_id: req.params.id }, order: 'created_at', ascending: false, limit: 20,
    });
    const result = [];
    for (const r of ratings) {
      const rater = await userById(r.rater_id);
      const sport = r.sport_id ? await db.findById('sports', r.sport_id) : null;
      result.push({
        id: r.id, score: r.score, comment: r.comment, createdAt: r.created_at,
        raterName: rater?.name || null, raterAvatar: rater?.avatar_url || null,
        sportName: sport?.name || null, sportIcon: sport?.icon || null,
      });
    }
    const user = await userById(req.params.id);
    res.json({ data: result, averageRating: user?.average_rating || 0, ratingCount: user?.rating_count || 0 });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/users', usersRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FOLLOWS (requests)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const followsRouter = express.Router();
followsRouter.use(authMiddleware);

followsRouter.get('/requests', async (req, res) => {
  try {
    const pending = await db.query('follows', { filters: { following_id: req.userId, status: 'pending' } });
    const result = [];
    for (const f of pending) {
      const sender = await userById(f.follower_id);
      if (sender) result.push({ id: f.id, follower: safeUser(sender), createdAt: f.created_at });
    }
    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

followsRouter.patch('/:id', async (req, res) => {
  try {
    const { action } = req.body;
    const follow = await db.findById('follows', req.params.id);
    if (!follow) return res.status(404).json({ message: 'Ä°stek bulunamadÄ±.' });
    if (follow.following_id !== req.userId) return res.status(403).json({ message: 'Bu isteÄŸi yanÄ±tlama yetkiniz yok.' });

    if (action === 'ACCEPTED') {
      await db.update('follows', follow.id, { status: 'accepted' });
      const target = await userById(follow.following_id);
      const follower = await userById(follow.follower_id);
      if (target) await db.update('users', target.id, { follower_count: (target.follower_count || 0) + 1 });
      if (follower) await db.update('users', follower.id, { following_count: (follower.following_count || 0) + 1 });
      await pushNotification({
        userId: follow.follower_id, type: 'FOLLOW_ACCEPTED',
        title: 'Takip isteÄŸin kabul edildi',
        body: `${target?.name || 'Birisi'} takip isteÄŸini kabul etti.`,
        relatedId: req.userId,
      });
      res.json({ message: 'Ä°stek kabul edildi.', follow: toCamel({ ...follow, status: 'accepted' }) });
    } else {
      await db.remove('follows', follow.id);
      res.json({ message: 'Ä°stek reddedildi.' });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// Respond to follow request by follower user ID (used from notification inline action)
followsRouter.post('/respond-by-user', async (req, res) => {
  try {
    const { followerId, action } = req.body;
    if (!followerId) return res.status(400).json({ message: 'followerId gerekli.' });
    const pending = await db.query('follows', { filters: { follower_id: followerId, following_id: req.userId, status: 'pending' } });
    if (!pending.length) return res.status(404).json({ message: 'Bekleyen istek bulunamadÄ±.' });
    const follow = pending[0];
    if (action === 'ACCEPTED') {
      await db.update('follows', follow.id, { status: 'accepted' });
      const target = await userById(req.userId);
      const follower = await userById(followerId);
      if (target) await db.update('users', target.id, { follower_count: (target.follower_count || 0) + 1 });
      if (follower) await db.update('users', follower.id, { following_count: (follower.following_count || 0) + 1 });
      await pushNotification({
        userId: followerId, type: 'FOLLOW_ACCEPTED',
        title: 'Takip isteÄŸin kabul edildi',
        body: `${target?.name || 'Birisi'} takip isteÄŸini kabul etti.`,
        relatedId: req.userId, senderId: req.userId,
        senderName: target?.name, senderAvatar: target?.avatar_url,
      });
      res.json({ message: 'Ä°stek kabul edildi.' });
    } else {
      await db.remove('follows', follow.id);
      res.json({ message: 'Ä°stek reddedildi.' });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/follows', followsRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CHALLENGES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const challengesRouter = express.Router();
challengesRouter.use(authMiddleware);

async function enrichChallenge(c) {
  const challenger = await userById(c.sender_id);
  const target = await userById(c.target_id);
  const sport = c.sport_id ? await db.findById('sports', c.sport_id) : null;
  let district = null;
  if (c.district_id) {
    const d = await db.findById('districts', c.district_id);
    if (d) district = { id: d.id, name: d.name, city: { name: d.city_name || '' } };
  }
  return {
    id: c.id, challengeType: c.challenge_type || 'RIVAL',
    status: c.status || 'PENDING', message: c.message,
    proposedDateTime: c.proposed_date_time, createdAt: c.created_at,
    expiresAt: c.expires_at,
    challenger: challenger ? { id: challenger.id, name: challenger.name, avatarUrl: challenger.avatar_url, userLevel: challenger.level } : null,
    target: target ? { id: target.id, name: target.name, avatarUrl: target.avatar_url, userLevel: target.level } : null,
    sport: sport ? toCamel(sport) : null,
    district,
  };
}

challengesRouter.get('/', async (req, res) => {
  try {
    const { direction } = req.query;
    let data;
    if (direction === 'sent') {
      data = await db.query('challenges', { filters: { sender_id: req.userId }, order: 'created_at', ascending: false });
    } else if (direction === 'received') {
      const client = db.raw();
      const { data: d } = await client.from('challenges').select('*')
        .eq('target_id', req.userId).eq('status', 'PENDING')
        .gt('expires_at', new Date().toISOString())
        .order('created_at', { ascending: false });
      data = d || [];
    } else {
      const client = db.raw();
      const { data: d } = await client.from('challenges').select('*')
        .eq('status', 'PENDING')
        .gt('expires_at', new Date().toISOString())
        .order('created_at', { ascending: false });
      data = d || [];
    }
    const enriched = [];
    for (const c of data) enriched.push(await enrichChallenge(c));
    res.json({ data: enriched });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

challengesRouter.post('/', contentFilter('message'), async (req, res) => {
  try {
    const { targetId, sportId } = req.body;
    if (!targetId || !sportId) return res.status(400).json({ message: 'Hedef kullanÄ±cÄ± ve spor gerekli.' });
    if (targetId === req.userId) return res.status(400).json({ message: 'Kendinize teklif gÃ¶nderemezsiniz.' });

    const target = await userById(targetId);
    if (!target) return res.status(404).json({ message: 'KullanÄ±cÄ± bulunamadÄ±.' });

    const dup = await db.findOne('challenges', { sender_id: req.userId, target_id: targetId, sport_id: sportId, status: 'PENDING' });
    if (dup) return res.status(409).json({ message: 'Bu spor iÃ§in zaten bekleyen bir teklifiniz var.' });

    const challenge = {
      id: uuid(), sender_id: req.userId, target_id: targetId,
      sport_id: sportId, challenge_type: req.body.challengeType === 'PARTNER' ? 'PARTNER' : 'RIVAL',
      message: req.body.message || null,
      proposed_date_time: req.body.proposedDateTime || null,
      district_id: req.body.districtId || null,
      status: 'PENDING',
      expires_at: new Date(Date.now() + 48 * 3600 * 1000).toISOString(),
    };
    await db.insert('challenges', challenge);

    const me = await userById(req.userId);
    const sport = await db.findById('sports', sportId);
    const targetLocale = await resolveUserPreferredPushLocale(targetId, 'tr');
    const localizedSportName = localizeSportNameForPush({
      sportId: sport?.id || sportId,
      rawName: sport?.name || 'sport',
      locale: targetLocale,
    });
    const challengeCopy = buildDirectChallengePushCopy({
      locale: targetLocale,
      challengeType: challenge.challenge_type,
      senderName: me?.name || '',
      sportName: localizedSportName,
    });

    await pushNotification({
      userId: targetId,
      type: 'DIRECT_CHALLENGE',
      title: challengeCopy.title,
      body: challengeCopy.body,
      relatedId: challenge.id, link: '/challenges',
      senderId: req.userId, senderName: me?.name, senderAvatar: me?.avatar_url,
    });

    res.status(201).json({ data: await enrichChallenge(challenge) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

challengesRouter.patch('/:id', async (req, res) => {
  try {
    const c = await db.findById('challenges', req.params.id);
    if (!c) return res.status(404).json({ message: 'Teklif bulunamadÄ±.' });
    if (c.target_id !== req.userId) return res.status(403).json({ message: 'Bu teklif size ait deÄŸil.' });
    if (c.status !== 'PENDING') return res.status(400).json({ message: 'Bu teklif zaten yanÄ±tlandÄ±.' });

    const action = String(req.body.action || '').toUpperCase();
    if (action !== 'ACCEPTED' && action !== 'REJECTED')
      return res.status(400).json({ message: 'GeÃ§ersiz iÅŸlem.' });

    await db.update('challenges', c.id, { status: action });

    if (action === 'ACCEPTED') {
      const sport = c.sport_id ? await db.findById('sports', c.sport_id) : null;
      const matchId = 'match_' + uuid();
      const listingId = 'listing_' + uuid();
      const challenger = await userById(c.sender_id);
      const accepter = await userById(req.userId);

      await db.insert('listings', {
        id: listingId, type: c.challenge_type,
        title: `${sport?.name || 'Spor'} teklifi`,
        description: c.message, sport_id: c.sport_id, sport_name: sport?.name,
        status: 'MATCHED', user_id: c.sender_id,
        user_name: challenger?.name, user_avatar: challenger?.avatar_url,
        date: c.proposed_date_time, response_count: 1, accepted_count: 1,
      });

      await db.insert('matches', {
        id: matchId, listing_id: listingId,
        user1_id: c.sender_id, user2_id: c.target_id,
        status: 'SCHEDULED', source: 'CHALLENGE',
        u1_approved: false, u2_approved: false,
        scheduled_at: c.proposed_date_time,
      });

      await persistMatchParticipants({
        matchId,
        participantIds: [c.sender_id, c.target_id],
        ownerId: c.sender_id,
      });

      await pushNotification({
        userId: c.sender_id, type: 'NEW_MATCH',
        title: 'ğŸ® EÅŸleÅŸme SaÄŸlandÄ±!',
        body: `${accepter?.name || 'Birisi'} teklifinizi kabul etti.`,
        relatedId: matchId, senderId: req.userId,
        senderName: accepter?.name, senderAvatar: accepter?.avatar_url,
      });

      return res.json({
        data: {
          challenge: await enrichChallenge({ ...c, status: action }),
          matchId, matchCreated: true, action,
        }
      });
    }

    // REJECTED
    const rejecter = await userById(req.userId);
    await pushNotification({
      userId: c.sender_id, type: 'DIRECT_CHALLENGE',
      title: 'âŒ Teklif Reddedildi',
      body: `${rejecter?.name || 'Birisi'} teklifinizi reddetti.`,
      relatedId: c.target_id, senderId: req.userId,
    });
    res.json({ data: { challenge: await enrichChallenge({ ...c, status: action }), matchCreated: false, action } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

challengesRouter.delete('/:id', async (req, res) => {
  try {
    const c = await db.findById('challenges', req.params.id);
    if (!c || c.sender_id !== req.userId) return res.status(404).json({ message: 'Teklif bulunamadÄ±.' });
    if (c.status !== 'PENDING') return res.status(400).json({ message: 'YalnÄ±zca beklemedeki teklifler silinebilir.' });
    await db.remove('challenges', c.id);
    res.json({ message: 'Teklif silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/challenges', challengesRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  POSTS (gÃ¶nderi, reaksiyon, yorum)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const postsRouter = express.Router();
postsRouter.use(authMiddleware);

postsRouter.get('/', async (req, res) => {
  try {
    const { page = 1, pageSize = 20, postType, cityId, cityName, countryCode, userId } = req.query;
    const pg = Number(page);
    const ps = Math.min(50, Number(pageSize));
    const skip = (pg - 1) * ps;
    const normalizedCountry = countryCode ? String(countryCode).trim().toUpperCase() : '';
    const hasCountryFilter = /^[A-Z]{2,3}$/.test(normalizedCountry);

    const client = db.raw();
    let q = client.from('posts').select('*').order('created_at', { ascending: false });
    if (postType) q = q.eq('post_type', postType);
    if (cityId) q = q.eq('city_id', cityId);
    if (cityName) q = q.ilike('city_name', `%${cityName}%`);
    if (userId) q = q.eq('user_id', userId);
    q = q.range(skip, skip + ps - 1);

    const { data } = await q;
    let posts = data || [];
    if (hasCountryFilter && posts.length > 0) {
      const userIdsByPosts = [...new Set(
        posts
          .filter(p => p.user_id)
          .map(p => p.user_id)
      )];
      const userCountryById = new Map();
      if (userIdsByPosts.length > 0) {
        const { data: userRows } = await client
          .from('users')
          .select('id,country_code')
          .in('id', userIdsByPosts);
        for (const u of (userRows || [])) {
          userCountryById.set(u.id, String(u.country_code || '').toUpperCase());
        }
      }
      posts = posts.filter(post => {
        const direct = String(post.country_code || '').toUpperCase();
        if (direct) return direct === normalizedCountry;
        const fromOwner = userCountryById.get(post.user_id) || '';
        return fromOwner === normalizedCountry;
      });
    }
    if (posts.length === 0) {
      return res.json({ success: true, data: [], pagination: { page: pg, hasNext: false } });
    }

    // Batch: collect unique IDs
    const postIds = posts.map(p => p.id);
    const userIds = [...new Set(posts.map(p => p.user_id).filter(Boolean))];
    const sportIds = [...new Set(posts.map(p => p.sport_id).filter(Boolean))];

    // Batch queries in parallel (replaces N+1 per-post queries)
    const [usersData, sportsData, reactionsData, commentsData] = await Promise.all([
      // Batch users
      userIds.length > 0
        ? client.from('users').select('id,name,avatar_url').in('id', userIds).then(r => r.data || [])
        : [],
      // Batch sports
      sportIds.length > 0
        ? client.from('sports').select('id,name').in('id', sportIds).then(r => r.data || [])
        : [],
      // Batch reactions for all posts
      client.from('post_reactions').select('post_id,user_id,type').in('post_id', postIds).then(r => r.data || []),
      // Batch comment counts â€” get all comments for these posts and count in-memory
      client.from('comments').select('post_id').in('post_id', postIds).then(r => r.data || []),
    ]);

    // Build lookup maps
    const userMap = Object.fromEntries(usersData.map(u => [u.id, u]));
    const sportMap = Object.fromEntries(sportsData.map(s => [s.id, s]));

    // Group reactions by post_id
    const reactionsByPost = {};
    for (const r of reactionsData) {
      (reactionsByPost[r.post_id] = reactionsByPost[r.post_id] || []).push(r);
    }

    // Count comments by post_id
    const commentCountByPost = {};
    for (const c of commentsData) {
      commentCountByPost[c.post_id] = (commentCountByPost[c.post_id] || 0) + 1;
    }

    const enriched = posts.map(p => {
      const author = userMap[p.user_id];
      const sport = sportMap[p.sport_id];
      const reactions = reactionsByPost[p.id] || [];
      const userReaction = reactions.find(r => r.user_id === req.userId)?.type || null;
      const reactionCounts = {};
      REACTION_TYPES.forEach(t => {
        const cnt = reactions.filter(r => r.type === t).length;
        if (cnt > 0) reactionCounts[t] = cnt;
      });
      return {
        ...toCamel(p),
        user: author ? { id: author.id, name: author.name, avatarUrl: author.avatar_url } : null,
        commentCount: commentCountByPost[p.id] || 0,
        userReaction, reactionCounts, likeCount: reactions.length, isLiked: !!userReaction,
        sportName: sport?.name ?? null,
      };
    });

    res.json({ success: true, data: enriched, pagination: { page: pg, hasNext: posts.length >= ps } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.post('/', contentFilter('content', 'title'), async (req, res) => {
  try {
    const body = sanitize(req.body);
    const postType = body.postType === 'SOCIAL_LISTING' ? 'SOCIAL_LISTING' : 'POST';
    if (!body.content || body.content.trim().length < 1)
      return res.status(400).json({ message: 'Ä°Ã§erik gerekli.' });

    const user = await userById(req.userId);
    const sport = body.sportId ? await db.findById('sports', body.sportId) : null;

    // NOTE: city_id and district_id have FK constraints to cities/districts tables
    // Flutter sends numeric IDs from states.json but DB has "c1" format â†’ FK violation
    // Store null for IDs, rely on city_name for display
    const post = await db.insert('posts', {
      id: uuid(), user_id: req.userId, post_type: postType,
      content: body.content.trim(),
      title: postType === 'SOCIAL_LISTING' ? (body.title || '').trim() : null,
      image_url: body.imageUrl || null,
      sport_id: body.sportId || null,
      city_id: null, city_name: body.cityName || null,
      district_id: null,
    });

    res.status(201).json({
      data: {
        ...toCamel(post),
        sportName: sport?.name || null,
        countryName: body.countryName || null,
        districtName: body.districtName || null,
        updatedAt: post.created_at || new Date().toISOString(),
        user: user ? { id: user.id, name: user.name, avatarUrl: user.avatar_url } : null,
        likeCount: 0, commentCount: 0, isLiked: false,
        userReaction: null, reactionCounts: {},
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.get('/user/:userId', async (req, res) => {
  try {
    const pg = parseInt(req.query.page) || 1;
    const ps = parseInt(req.query.pageSize) || 20;
    const client = db.raw();
    const { data, count } = await client.from('posts').select('*', { count: 'exact' })
      .eq('user_id', req.params.userId)
      .order('created_at', { ascending: false })
      .range((pg - 1) * ps, pg * ps - 1);

    const posts = data || [];
    if (posts.length === 0) {
      return res.json({ data: [], pagination: { page: pg, pageSize: ps, total: count || 0, hasNext: false } });
    }

    const postIds = posts.map(p => p.id);
    const user = await userById(req.params.userId); // Single user â€” just one query

    const [reactionsData, commentsData] = await Promise.all([
      client.from('post_reactions').select('post_id,user_id,type').in('post_id', postIds).then(r => r.data || []),
      client.from('comments').select('post_id').in('post_id', postIds).then(r => r.data || []),
    ]);

    const reactionsByPost = {};
    for (const r of reactionsData) (reactionsByPost[r.post_id] = reactionsByPost[r.post_id] || []).push(r);
    const commentCountByPost = {};
    for (const c of commentsData) commentCountByPost[c.post_id] = (commentCountByPost[c.post_id] || 0) + 1;

    const enriched = posts.map(p => {
      const reactions = reactionsByPost[p.id] || [];
      const userReaction = reactions.find(r => r.user_id === req.userId)?.type || null;
      const reactionCounts = {};
      REACTION_TYPES.forEach(t => { const cnt = reactions.filter(r => r.type === t).length; if (cnt > 0) reactionCounts[t] = cnt; });
      return {
        ...toCamel(p),
        user: user ? { id: user.id, name: user.name, avatarUrl: user.avatar_url } : null,
        commentCount: commentCountByPost[p.id] || 0,
        userReaction, reactionCounts, likeCount: reactions.length, isLiked: !!userReaction,
      };
    });

    res.json({ data: enriched, pagination: { page: pg, pageSize: ps, total: count || 0, hasNext: pg * ps < (count || 0) } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.get('/:id', async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    const author = await userById(post.user_id);
    const commentCount = await db.count('comments', { post_id: post.id });
    const rd = await enrichPostReactions(post.id, req.userId);
    const sport = post.sport_id ? await db.findById('sports', post.sport_id) : null;
    res.json({
      data: {
        ...toCamel(post),
        user: author ? { id: author.id, name: author.name, avatarUrl: author.avatar_url } : null,
        commentCount, ...rd, sportName: sport?.name ?? null,
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.delete('/:id', async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    if (post.user_id !== req.userId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    await db.removeWhere('post_reactions', { post_id: post.id });
    const comments = await db.query('comments', { filters: { post_id: post.id } });
    for (const c of comments) await db.removeWhere('comment_likes', { comment_id: c.id });
    await db.removeWhere('comments', { post_id: post.id });
    await db.remove('posts', post.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.put('/:id', contentFilter('content'), async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    if (post.user_id !== req.userId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    const { content } = req.body;
    if (!content || content.trim().length === 0)
      return res.status(400).json({ message: 'Ä°Ã§erik boÅŸ olamaz.' });
    const updated = await db.update('posts', post.id, { content: content.trim(), updated_at: new Date().toISOString() });
    const user = await userById(post.user_id);
    const commentCount = await db.count('comments', { post_id: post.id });
    const rd = await enrichPostReactions(post.id, req.userId);
    res.json({
      data: {
        ...toCamel(updated),
        user: user ? { id: user.id, name: user.name, avatarUrl: user.avatar_url } : null,
        commentCount, ...rd,
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.post('/:id/react', async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    const { type = 'LIKE' } = req.body;
    if (!REACTION_TYPES.includes(type)) return res.status(400).json({ message: 'GeÃ§ersiz reaksiyon tipi.' });

    const existing = await db.findOne('post_reactions', { post_id: post.id, user_id: req.userId });
    if (existing) {
      if (existing.type === type) await db.remove('post_reactions', existing.id);
      else await db.update('post_reactions', existing.id, { type });
    } else {
      await db.insert('post_reactions', { id: uuid(), post_id: post.id, user_id: req.userId, type });
      if (post.user_id !== req.userId) {
        const reactor = await userById(req.userId);
        await pushNotification({
          userId: post.user_id, type: 'POST_REACT',
          title: 'GÃ¶nderi Reaksiyonu',
          body: `${reactor?.name || 'Birisi'} gÃ¶nderinize tepki verdi.`,
          relatedId: post.id, senderId: req.userId,
          senderName: reactor?.name, senderAvatar: reactor?.avatar_url,
        });
      }
    }
    res.json(await enrichPostReactions(post.id, req.userId));
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.post('/:id/like', async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    const existing = await db.findOne('post_reactions', { post_id: post.id, user_id: req.userId });
    if (existing) { await db.remove('post_reactions', existing.id); }
    else { await db.insert('post_reactions', { id: uuid(), post_id: post.id, user_id: req.userId, type: 'LIKE' }); }
    const rd = await enrichPostReactions(post.id, req.userId);
    res.json({ liked: rd.isLiked, likeCount: rd.likeCount, ...rd });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.get('/:id/likes', async (req, res) => {
  try {
    const reactions = await db.query('post_reactions', { filters: { post_id: req.params.id } });
    const users = [];
    for (const r of reactions) {
      const u = await userById(r.user_id);
      if (u) users.push({ id: u.id, name: u.name, avatarUrl: u.avatar_url, likedAt: r.created_at, reactionType: r.type });
    }
    res.json({ data: users });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.get('/:id/comments', async (req, res) => {
  try {
    const postComments = await db.query('comments', {
      filters: { post_id: req.params.id }, order: 'created_at', ascending: true,
    });
    // Batch: fetch all users and comment likes in parallel
    const commentIds = postComments.map(c => c.id);
    const userIds = [...new Set(postComments.map(c => c.user_id).filter(Boolean))];
    const client = db.raw();

    const [usersData, likesData] = await Promise.all([
      userIds.length > 0
        ? client.from('users').select('id,name,avatar_url').in('id', userIds).then(r => r.data || [])
        : [],
      client.from('comment_likes').select('comment_id,user_id').in('comment_id', commentIds).then(r => r.data || []),
    ]);

    const userMap = Object.fromEntries(usersData.map(u => [u.id, u]));
    const likesByComment = {};
    for (const l of likesData) (likesByComment[l.comment_id] = likesByComment[l.comment_id] || []).push(l);

    function enrichComment(c) {
      const author = userMap[c.user_id];
      const likes = likesByComment[c.id] || [];
      return {
        ...toCamel(c),
        user: author ? { id: author.id, name: author.name, avatarUrl: author.avatar_url } : null,
        likeCount: likes.length, isLiked: likes.some(l => l.user_id === req.userId),
      };
    }

    // Build full recursive tree (supports unlimited nesting depth)
    const commentMap = {};
    for (const c of postComments) {
      commentMap[c.id] = { ...enrichComment(c), replies: [] };
    }
    const roots = [];
    for (const c of postComments) {
      const enriched = commentMap[c.id];
      if (c.parent_id && commentMap[c.parent_id]) {
        commentMap[c.parent_id].replies.push(enriched);
      } else {
        roots.push(enriched);
      }
    }

    res.json({ data: roots });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.post('/:id/comments', contentFilter('content'), async (req, res) => {
  try {
    const post = await db.findById('posts', req.params.id);
    if (!post) return res.status(404).json({ message: 'GÃ¶nderi bulunamadÄ±.' });
    const body = sanitize(req.body);
    if (!body.content || body.content.trim().length < 1)
      return res.status(400).json({ message: 'Yorum iÃ§eriÄŸi gerekli.' });
    if (body.content.length > 2000)
      return res.status(400).json({ message: 'Yorum en fazla 2000 karakter olabilir.' });

    // Validate parentId
    if (body.parentId) {
      const parent = await db.findById('comments', body.parentId);
      if (!parent || parent.post_id !== post.id) return res.status(404).json({ message: 'Ãœst yorum bulunamadÄ±.' });
    }

    const user = await userById(req.userId);
    const comment = await db.insert('comments', {
      id: uuid(), post_id: post.id, user_id: req.userId,
      parent_id: body.parentId || null, content: body.content.trim(),
    });

    // Notification
    const notifyUserId = body.parentId
      ? (await db.findById('comments', body.parentId))?.user_id
      : post.user_id;
    if (notifyUserId && notifyUserId !== req.userId) {
      await pushNotification({
        userId: notifyUserId,
        type: body.parentId ? 'COMMENT_REPLY' : 'POST_COMMENT',
        title: body.parentId ? 'Yorumunuza yanÄ±t' : 'Yeni yorum',
        body: `${user?.name || 'Birisi'} ${body.parentId ? 'yorumunuza yanÄ±t verdi.' : 'gÃ¶nderinize yorum yaptÄ±.'}`,
        relatedId: post.id, senderId: req.userId,
      });
    }

    res.status(201).json({
      data: {
        ...toCamel(comment),
        user: user ? { id: user.id, name: user.name, avatarUrl: user.avatar_url } : null,
        likeCount: 0, isLiked: false, replies: [],
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.delete('/:postId/comments/:commentId', async (req, res) => {
  try {
    const comment = await db.findById('comments', req.params.commentId);
    if (!comment || comment.post_id !== req.params.postId)
      return res.status(404).json({ message: 'Yorum bulunamadÄ±.' });
    const post = await db.findById('posts', req.params.postId);
    if (comment.user_id !== req.userId && post?.user_id !== req.userId)
      return res.status(403).json({ message: 'Yetkiniz yok.' });

    // Delete children
    const children = await db.query('comments', { filters: { parent_id: comment.id } });
    for (const child of children) {
      await db.removeWhere('comment_likes', { comment_id: child.id });
      await db.remove('comments', child.id);
    }
    await db.removeWhere('comment_likes', { comment_id: comment.id });
    await db.remove('comments', comment.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.put('/:postId/comments/:commentId', contentFilter('content'), async (req, res) => {
  try {
    const comment = await db.findById('comments', req.params.commentId);
    if (!comment || comment.post_id !== req.params.postId)
      return res.status(404).json({ message: 'Yorum bulunamadÄ±.' });
    if (comment.user_id !== req.userId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    const { content } = req.body;
    if (!content || content.trim().length === 0)
      return res.status(400).json({ message: 'Ä°Ã§erik boÅŸ olamaz.' });
    const updated = await db.update('comments', comment.id, { content: content.trim(), updated_at: new Date().toISOString() });
    const user = await userById(comment.user_id);
    const likeCount = await db.count('comment_likes', { comment_id: comment.id });
    const isLiked = !!(await db.findOne('comment_likes', { comment_id: comment.id, user_id: req.userId }));
    res.json({
      data: {
        ...toCamel(updated),
        user: user ? { id: user.id, name: user.name, avatarUrl: user.avatar_url } : null,
        likeCount, isLiked, replies: [],
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.post('/:postId/comments/:commentId/like', async (req, res) => {
  try {
    const existing = await db.findOne('comment_likes', { comment_id: req.params.commentId, user_id: req.userId });
    if (existing) { await db.remove('comment_likes', existing.id); }
    else { await db.insert('comment_likes', { id: uuid(), comment_id: req.params.commentId, user_id: req.userId }); }
    const count = await db.count('comment_likes', { comment_id: req.params.commentId });
    res.json({ liked: !existing, likeCount: count });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

postsRouter.get('/:postId/comments/:commentId/likes', async (req, res) => {
  try {
    const likes = await db.query('comment_likes', { filters: { comment_id: req.params.commentId } });
    const users = [];
    for (const l of likes) {
      const u = await userById(l.user_id);
      if (u) users.push({ id: u.id, name: u.name, avatarUrl: u.avatar_url, likedAt: l.created_at });
    }
    res.json({ data: users });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/posts', postsRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  NOTIFICATIONS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const skip = (page - 1) * limit;
    const shouldRefreshReminders = req.query.refreshReminders === '1' && page === 1;

    if (shouldRefreshReminders) {
      await generateMatchReminders({ now: new Date().toISOString(), userId: req.userId }).catch(() => 0);
    }

    const client = db.raw();
    const { data, count } = await client.from('notifications').select('*', { count: 'exact' })
      .eq('user_id', req.userId)
      .order('created_at', { ascending: false })
      .range(skip, skip + limit - 1);

    const unread = await db.count('notifications', { user_id: req.userId, is_read: false });
    const mapped = (data || []).map(n => ({ ...toCamel(n), read: !!n.is_read }));
    res.json({ data: mapped, unreadCount: unread, total: count || 0, hasMore: page * limit < (count || 0), page });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.patch('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const { ids, all } = req.body;
    if (all) {
      await db.updateWhere('notifications', { user_id: req.userId }, { is_read: true });
    } else if (ids && Array.isArray(ids)) {
      for (const id of ids) await db.update('notifications', id, { is_read: true }).catch(() => {});
    }
    res.json({ message: 'Okundu olarak iÅŸaretlendi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const unreadCount = await db.count('notifications', {
      user_id: req.userId,
      is_read: false,
    });
    res.json({ unreadCount: unreadCount || 0 });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

app.get('/api/badges', authMiddleware, async (req, res) => {
  try {
    const nowIso = new Date().toISOString();
    const client = db.raw();

    const [convsRes, myListingsRes, myPendingResponsesRes, pendingChallengesRes, unreadNotifRes] = await Promise.all([
      client.from('conversations').select('id,unread_for,user1_id,user2_id')
        .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`),
      client.from('listings').select('id,status,date')
        .eq('user_id', req.userId)
        .in('status', ['ACTIVE', 'MATCHED']),
      client.from('interests').select('id', { count: 'exact', head: true })
        .eq('user_id', req.userId)
        .eq('status', 'PENDING'),
      client.from('challenges').select('id', { count: 'exact', head: true })
        .eq('target_id', req.userId)
        .eq('status', 'PENDING')
        .gt('expires_at', nowIso),
      client.from('notifications').select('id', { count: 'exact', head: true })
        .eq('user_id', req.userId)
        .eq('is_read', false),
    ]);

    const conversations = convsRes.data || [];
    let unreadMessages = 0;
    for (const conv of conversations) {
      const unreadFor = normalizeJsonObject(conv.unread_for);
      const rawCount = unreadFor[req.userId];
      const count = typeof rawCount === 'number' ? rawCount : parseInt(rawCount || '0', 10) || 0;
      if (count > 0) unreadMessages++;
    }

    const myListings = (myListingsRes.data || []).filter((listing) => {
      if (String(listing.status || '').toUpperCase() === 'EXPIRED') return false;
      if (!listing.date) return true;
      return new Date(listing.date) >= new Date(nowIso);
    });

    let incomingPendingCount = 0;
    if (myListings.length > 0) {
      const listingIds = myListings.map((listing) => listing.id);
      const pendingIncoming = await client.from('interests')
        .select('id', { count: 'exact', head: true })
        .in('listing_id', listingIds)
        .eq('status', 'PENDING');
      incomingPendingCount = pendingIncoming.count || 0;
    }

    const outgoingPendingCount = myPendingResponsesRes.count || 0;
    const challengePendingCount = pendingChallengesRes.count || 0;
    const unreadNotifications = unreadNotifRes.count || 0;

    res.json({
      data: {
        unreadMessages,
        activityCount:
          incomingPendingCount +
          outgoingPendingCount +
          challengePendingCount,
        unreadNotifications,
      },
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SETTINGS / PRIVACY
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const settingsRouter = express.Router();
settingsRouter.use(authMiddleware);

settingsRouter.get('/privacy', async (req, res) => {
  try {
    const settings = await getPrivacy(req.userId);
    res.json({ data: settings });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

settingsRouter.put('/privacy', async (req, res) => {
  try {
    const current = await getPrivacy(req.userId);
    const merged = normalizePrivacy({ ...current, ...req.body });
    const existing = await db.findOne('user_privacy', { user_id: req.userId });
    const legacyPatch = buildLegacyPrivacyPatch(merged);

    if (existing) {
      let saved = false;
      if (Object.prototype.hasOwnProperty.call(existing, 'settings')) {
        try {
          await db.updateWhere(
            'user_privacy',
            { user_id: req.userId },
            { settings: merged, updated_at: new Date().toISOString() }
          );
          saved = true;
        } catch (settingsErr) {
          const msg = String(settingsErr?.message || '').toLowerCase();
          if (!msg.includes('settings')) throw settingsErr;
        }
      }
      if (!saved) {
        await db.updateWhere('user_privacy', { user_id: req.userId }, legacyPatch);
      }
    } else {
      try {
        await db.insert('user_privacy', { user_id: req.userId, settings: merged });
      } catch (insertErr) {
        const msg = String(insertErr?.message || '').toLowerCase();
        if (!msg.includes('settings')) throw insertErr;
        await db.insert('user_privacy', {
          user_id: req.userId,
          ...legacyPatch,
          show_last_seen: true,
          show_statistics: true,
          show_age: true,
        });
      }
    }
    if (merged.isPrivateProfile !== undefined) {
      await db.update('users', req.userId, { is_private: merged.isPrivateProfile }).catch(() => {});
    }
    res.json({ data: merged });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

settingsRouter.get('/blocked-users', async (req, res) => {
  try {
    const blocked = await db.query('blocked_users', { filters: { blocker_id: req.userId } });
    const result = [];
    for (const b of blocked) {
      const user = await userById(b.blocked_id);
      if (user) result.push({ id: b.id, blockedAt: b.created_at, user: safeUser(user) });
    }
    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/settings', settingsRouter);

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  HOME-BOOTSTRAP â€” Tek istek ile ana sayfa verisi (4â†’1 API call)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/api/home-feed', authMiddleware, async (req, res) => {
  try {
    const client = db.raw();
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;

    // Parallel: user profile + listings + sports catalog + unread notifications
    const [userRow, listingsResult, sports, unreadResult] = await Promise.all([
      db.findById('users', req.userId),
      client.from('listings').select('*', { count: 'exact' })
        .eq('status', 'ACTIVE')
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1),
      db.query('sports', { order: 'name', ascending: true }),
      client.from('notifications').select('id', { count: 'exact', head: true })
        .eq('user_id', req.userId).eq('is_read', false),
    ]);

    const listings = (listingsResult.data || []).map(l => ({
      id: l.id, type: 'listing', listing: toCamel(l), createdAt: l.created_at,
    }));

    res.json({
      user: safeUser(userRow),
      feed: listings,
      sports: sports.map(toCamel),
      unreadNotifications: unreadResult.count || 0,
      pagination: {
        page, hasNext: offset + limit < (listingsResult.count || 0),
        total: listingsResult.count || 0,
      },
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

async function pruneHistoricalMatches({ keepPerUser = 3 } = {}) {
  const client = db.raw();
  const terminalStatuses = ['COMPLETED', 'NO_SHOW'];
  const { data: terminalMatches } = await client.from('matches').select('*')
    .in('status', terminalStatuses)
    .order('completed_at', { ascending: false, nullsFirst: false })
    .order('created_at', { ascending: false });

  const matches = terminalMatches || [];
  if (matches.length === 0) {
    return {
      keptMatches: 0,
      deletedMatches: 0,
      deletedRatings: 0,
      deletedOtps: 0,
      deletedNoShows: 0,
      deletedNotifications: 0,
    };
  }

  const listingIds = [...new Set(matches.map(m => m.listing_id).filter(Boolean))];
  const listingsArr = listingIds.length > 0
    ? (await client.from('listings').select('id,type,max_participants,user_id').in('id', listingIds)).data || []
    : [];
  const listingsMap = new Map(listingsArr.map(row => [row.id, row]));

  const participantsByMatch = new Map();
  await Promise.all(matches.map(async (match) => {
    const listing = match.listing_id ? listingsMap.get(match.listing_id) : null;
    const participantIds = await getMatchParticipantIds(match, listing);
    participantsByMatch.set(match.id, participantIds);
  }));

  const keepCounts = new Map();
  const keepIds = new Set();

  for (const match of matches) {
    const participantIds = participantsByMatch.get(match.id) || [];
    const shouldKeep = participantIds.some(userId => (keepCounts.get(userId) || 0) < keepPerUser);
    if (!shouldKeep) continue;

    keepIds.add(match.id);
    for (const userId of participantIds) {
      keepCounts.set(userId, (keepCounts.get(userId) || 0) + 1);
    }
  }

  const pruneIds = matches.map(m => m.id).filter(id => !keepIds.has(id));
  if (pruneIds.length === 0) {
    return {
      keptMatches: keepIds.size,
      deletedMatches: 0,
      deletedRatings: 0,
      deletedOtps: 0,
      deletedNoShows: 0,
      deletedNotifications: 0,
    };
  }

  const [deletedRatings, deletedOtps, deletedNoShows, deletedNotifications, deletedMatches] = await Promise.all([
    client.from('ratings').delete({ count: 'exact' }).in('match_id', pruneIds),
    client.from('otps').delete({ count: 'exact' }).in('match_id', pruneIds),
    client.from('noshows').delete({ count: 'exact' }).in('match_id', pruneIds),
    client.from('notifications').delete({ count: 'exact' }).in('related_id', pruneIds),
    client.from('matches').delete({ count: 'exact' }).in('id', pruneIds),
  ]);

  return {
    keptMatches: keepIds.size,
    deletedMatches: deletedMatches.count || 0,
    deletedRatings: deletedRatings.count || 0,
    deletedOtps: deletedOtps.count || 0,
    deletedNoShows: deletedNoShows.count || 0,
    deletedNotifications: deletedNotifications.count || 0,
  };
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CRON JOBS â€” Hobby plan uyumlu bakÄ±m endpoint'leri
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/api/cron/cleanup-expired', async (req, res) => {
  // Vercel Cron Authorization header kontrolÃ¼
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const client = db.raw();
    const now = new Date().toISOString();

    // 1. SÃ¼resi dolan ilanlarÄ± sil (expires_at < now)
    const { data: expired } = await client.from('listings').select('id,user_id,title')
      .lt('expires_at', now).eq('status', 'ACTIVE');
    const expiredIds = (expired || []).map(l => l.id);
    const listingById = new Map((expired || []).map(l => [l.id, l]));

    let deletedListings = 0;
    let autoRejectedInterests = 0;
    if (expiredIds.length > 0) {
      const { data: pendingInterests } = await client.from('interests')
        .select('id,listing_id,user_id,status')
        .in('listing_id', expiredIds)
        .eq('status', 'PENDING');

      for (const interest of (pendingInterests || [])) {
        const targetListing = listingById.get(interest.listing_id);
        await pushNotification({
          userId: interest.user_id,
          type: 'RESPONSE_REJECTED',
          title: 'BaÅŸvuru otomatik reddedildi',
          body: targetListing?.title
            ? `"${targetListing.title}" ilanÄ±nÄ±n sÃ¼resi dolduÄŸu iÃ§in baÅŸvurunuz otomatik reddedildi.`
            : 'Ä°lanÄ±n sÃ¼resi dolduÄŸu iÃ§in baÅŸvurunuz otomatik reddedildi.',
          relatedId: interest.listing_id,
          senderId: targetListing?.user_id || null,
        }).catch(() => {});
        autoRejectedInterests++;
      }

      // Ä°lgili interests'leri kalÄ±cÄ± sil
      await client.from('interests').delete().in('listing_id', expiredIds);
      const { count } = await client.from('listings').delete({ count: 'exact' }).in('id', expiredIds);
      deletedListings = count || 0;
    }

    // 2. SÃ¼resi dolmuÅŸ password reset token'larÄ±nÄ± temizle
    const { count: deletedTokens } = await client.from('password_reset_tokens')
      .delete({ count: 'exact' }).lt('expires_at', now);

    // 3. SÃ¼resi dolmuÅŸ refresh token'larÄ±nÄ± temizle
    const { count: deletedRefresh } = await client.from('refresh_tokens')
      .delete({ count: 'exact' }).lt('expires_at', now);

    // 4. ZamanÄ± geÃ§miÅŸ ama henÃ¼z tamamlanmamÄ±ÅŸ maÃ§lar iÃ§in tek seferlik hatÄ±rlatma Ã¼ret
    const reminderNotifications = await generateMatchReminders({ now });

    // 5. Her kullanÄ±cÄ± iÃ§in yalnÄ±zca son 3 tarihsel maÃ§Ä± tut, eskileri kalÄ±cÄ± sil
    const matchPruneStats = await pruneHistoricalMatches({ keepPerUser: 3 });

    res.json({
      message: 'Cleanup completed',
      deletedListings, deletedTokens: deletedTokens || 0,
      deletedRefreshTokens: deletedRefresh || 0,
      autoRejectedInterests,
      reminderNotifications,
      matchPruneStats,
      timestamp: now,
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/cron/match-reminders', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const now = new Date().toISOString();
    const reminderNotifications = await generateMatchReminders({ now });
    res.json({
      message: 'Match reminders completed',
      reminderNotifications,
      timestamp: now,
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/cron/ecosystem-tick', async (req, res) => {
  // Vercel Cron Authorization header kontrolÃ¼
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    // Ecosystem tick-all mantÄ±ÄŸÄ±nÄ± Ã§aÄŸÄ±r
    const ecosystems = await db.query('bot_ecosystems', { filters: { status: 'ACTIVE' } });
    let tickedCount = 0;
    const results = [];
    for (const eco of ecosystems) {
      try {
        const r = await runEcosystemTick(eco);
        results.push({ ecoId: eco.id, cityName: eco.city_name, ...r });
        tickedCount++;
      } catch (err) {
        results.push({ ecoId: eco.id, cityName: eco.city_name, error: err.message });
      }
    }
    res.json({ message: 'Ecosystem tick completed', tickedCount, activeEcosystems: ecosystems.length, results, timestamp: new Date().toISOString() });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FEED, SEARCH, LEADERBOARD, RECOMMENDATIONS, ACTIVITIES, RATINGS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
app.get('/api/feed', authMiddleware, async (req, res) => {
  try {
    const listings = await db.query('listings', {
      filters: { status: 'ACTIVE' }, order: 'created_at', ascending: false, limit: 20,
    });
    const items = listings.map(l => ({
      id: uuid(), type: 'listing', listing: toCamel(l), createdAt: l.created_at,
    }));
    res.json({ data: items, pagination: { page: 1, hasNext: false } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/recommendations', authMiddleware, async (req, res) => {
  try {
    const listings = await db.query('listings', {
      filters: { status: 'ACTIVE' }, order: 'created_at', ascending: false, limit: 5,
    });
    const items = listings.map(l => ({
      id: uuid(), type: 'listing', listing: toCamel(l), createdAt: l.created_at,
    }));
    res.json({ data: items, reason: 'Spor tercihlerinize gÃ¶re' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/search', authMiddleware, async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    if (!q) return res.json({ data: { listings: [], users: [], sports: [], clubs: [], groups: [] } });
    const listings = await db.search('listings', 'title', q, { limit: 20 });
    const users = await db.search('users', 'name', q, { limit: 20 });
    const sports = await db.search('sports', 'name', q, { limit: 20 });
    res.json({
      data: {
        listings: listings.map(toCamel), users: users.map(safeUser),
        sports: sports.map(toCamel), clubs: [], groups: [],
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/leaderboard', authMiddleware, async (req, res) => {
  try {
    const client = db.raw();
    const { data } = await client.from('users').select('*')
      .eq('is_banned', false)
      .order('total_points', { ascending: false })
      .limit(20);
    const ranked = (data || []).map((u, i) => {
      const safe = safeUser(u);
      const cityName = typeof safe.city === 'string' ? safe.city : safe.city?.name;
      return {
        ...safe,
        city: cityName ? { name: cityName } : null,
        rank: i + 1,
      };
    });
    res.json({ ranked });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/aktivitelerim', authMiddleware, async (req, res) => {
  try {
    const client = db.raw();

    // â”€â”€ 1. My listings (last 20) â”€â”€
    const myListings = await db.query('listings', {
      filters: { user_id: req.userId }, order: 'created_at', ascending: false, limit: 20,
    });

    // Batch: interests + sports for my listings
    const listingIds = myListings.map(l => l.id);
    const sportIdsSet = new Set(myListings.filter(l => l.sport_id).map(l => l.sport_id));

    const [pendingInterests, sportsArr] = await Promise.all([
      listingIds.length > 0
        ? client.from('interests').select('*').in('listing_id', listingIds).eq('status', 'PENDING').then(r => r.data || [])
        : [],
      sportIdsSet.size > 0
        ? client.from('sports').select('*').in('id', [...sportIdsSet]).then(r => r.data || [])
        : [],
    ]);

    // Batch: users for interests
    const interestUserIds = [...new Set(pendingInterests.map(i => i.user_id))];
    const interestUsers = interestUserIds.length > 0
      ? (await client.from('users').select('*').in('id', interestUserIds)).data || []
      : [];
    const interestUsersMap = new Map(interestUsers.map(u => [u.id, u]));
    const sportsMap = new Map(sportsArr.map(s => [s.id, s]));

    // Group interests by listing_id
    const interestsByListing = new Map();
    for (const i of pendingInterests) {
      if (!interestsByListing.has(i.listing_id)) interestsByListing.set(i.listing_id, []);
      interestsByListing.get(i.listing_id).push(i);
    }

    const enrichedListings = myListings.map(l => {
      const interests = interestsByListing.get(l.id) || [];
      const sport = l.sport_id ? sportsMap.get(l.sport_id) : null;
      const responses = interests.map(i => ({
        id: i.id, message: i.message, user: safeUser(interestUsersMap.get(i.user_id)),
      }));
      return {
        ...toCamel(l), dateTime: l.date, sport: sport ? toCamel(sport) : null,
        _count: { responses: l.response_count || 0 }, responses,
      };
    });

    // â”€â”€ 2. My interests (responses to others' listings) â”€â”€
    const myInterests = await db.query('interests', { filters: { user_id: req.userId }, limit: 50 });

    // Batch: listings + owners + sports for my interests
    const intListingIds = [...new Set(myInterests.map(i => i.listing_id))];
    const intListings = intListingIds.length > 0
      ? (await client.from('listings').select('*').in('id', intListingIds)).data || []
      : [];
    const intListingsMap = new Map(intListings.map(l => [l.id, l]));

    const ownerIds = [...new Set(intListings.map(l => l.user_id))];
    const intSportIds = [...new Set(intListings.filter(l => l.sport_id).map(l => l.sport_id))];
    const [ownersArr, intSportsArr] = await Promise.all([
      ownerIds.length > 0 ? client.from('users').select('*').in('id', ownerIds).then(r => r.data || []) : [],
      intSportIds.length > 0 ? client.from('sports').select('*').in('id', intSportIds).then(r => r.data || []) : [],
    ]);
    const ownersMap = new Map(ownersArr.map(u => [u.id, u]));
    const intSportsMap = new Map(intSportsArr.map(s => [s.id, s]));

    const enrichedInterests = [];
    for (const i of myInterests) {
      const listing = intListingsMap.get(i.listing_id);
      if (!listing) continue;
      const sport = listing.sport_id ? intSportsMap.get(listing.sport_id) : null;
      const owner = ownersMap.get(listing.user_id);
      enrichedInterests.push({
        id: i.id, status: i.status, message: i.message, createdAt: i.created_at,
        listing: {
          id: listing.id, type: listing.type, status: listing.status,
          dateTime: listing.date, sport: sport ? toCamel(sport) : null,
          user: safeUser(owner),
        },
      });
    }

    // â”€â”€ 3. My matches (last 20 â€” not unlimited!) â”€â”€
    const [homeDirectMatchesRes, homeAcceptedListingsRes] = await Promise.all([
      client.from('matches').select('*')
        .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
        .order('created_at', { ascending: false }),
      client.from('interests').select('listing_id')
        .eq('user_id', req.userId)
        .eq('status', 'ACCEPTED'),
    ]);

    const mArrAll = [];
    const mSeenIds = new Set();
    for (const row of (homeDirectMatchesRes.data || [])) {
      if (!row?.id || mSeenIds.has(row.id)) continue;
      mSeenIds.add(row.id);
      mArrAll.push(row);
    }

    const homeAcceptedListingIds = [...new Set((homeAcceptedListingsRes.data || [])
      .map(row => row.listing_id)
      .filter(Boolean))];

    if (homeAcceptedListingIds.length > 0) {
      const { data: homeGroupListingRows } = await client.from('listings').select('id,type,max_participants')
        .in('id', homeAcceptedListingIds)
        .eq('type', 'PARTNER')
        .gt('max_participants', 2);

      const eligibleHomeGroupListingIds = [...new Set((homeGroupListingRows || []).map(row => row.id).filter(Boolean))];
      const { data: homeGroupMatches } = eligibleHomeGroupListingIds.length > 0
        ? await client.from('matches').select('*')
          .in('listing_id', eligibleHomeGroupListingIds)
          .order('created_at', { ascending: false })
        : { data: [] };

      const homeLatestByListing = new Map();
      for (const row of (homeGroupMatches || [])) {
        if (!row?.listing_id) continue;
        if (!homeLatestByListing.has(row.listing_id)) homeLatestByListing.set(row.listing_id, row);
      }

      for (const row of homeLatestByListing.values()) {
        if (!row?.id || mSeenIds.has(row.id)) continue;
        mSeenIds.add(row.id);
        mArrAll.push(row);
      }
    }

    const mArr = mArrAll
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
      .slice(0, 5);

    const mListingIds = [...new Set(mArr.map(m => m.listing_id).filter(Boolean))];
    const mListingsArr = mListingIds.length > 0
      ? (await client.from('listings').select('*').in('id', mListingIds)).data || []
      : [];

    const mListingsMap = new Map(mListingsArr.map(l => [l.id, l]));
    const mGroupListingIds = [...new Set(mArr
      .map(m => m.listing_id)
      .filter(listingId => {
        if (!listingId) return false;
        return isPartnerGroupListing(mListingsMap.get(listingId));
      }))];

    const persistedHomeByMatch = await getPersistedParticipantsByMatch(
      mArr.map(m => m.id).filter(Boolean)
    );

    const mAcceptedRows = mGroupListingIds.length > 0
      ? (await client.from('interests').select('listing_id,user_id')
        .in('listing_id', mGroupListingIds)
        .eq('status', 'ACCEPTED')).data || []
      : [];

    const mAcceptedByListing = new Map();
    for (const row of mAcceptedRows) {
      if (!row?.listing_id || !row.user_id) continue;
      if (!mAcceptedByListing.has(row.listing_id)) mAcceptedByListing.set(row.listing_id, new Set());
      mAcceptedByListing.get(row.listing_id).add(row.user_id);
    }

    const mUserIds = new Set();
    const mParticipantIdsByMatch = new Map();
    for (const m of mArr) {
      const listing = m.listing_id ? mListingsMap.get(m.listing_id) : null;
      const participantIds = new Set([m.user1_id, m.user2_id].filter(Boolean));
      const persisted = persistedHomeByMatch.get(m.id);
      if (persisted && persisted.size > 0) {
        for (const userId of persisted) participantIds.add(userId);
      } else if (isGroupMatchRecord(m, listing) && listing?.id) {
        if (listing.user_id) participantIds.add(listing.user_id);
        const acceptedSet = mAcceptedByListing.get(listing.id);
        if (acceptedSet) {
          for (const userId of acceptedSet) participantIds.add(userId);
        }
      }
      const list = [...participantIds];
      mParticipantIdsByMatch.set(m.id, list);
      for (const userId of list) mUserIds.add(userId);
    }

    const mUsersArr = mUserIds.size > 0
      ? (await client.from('users').select('*').in('id', [...mUserIds])).data || []
      : [];
    const mUsersMap = new Map(mUsersArr.map(u => [u.id, u]));

    const mSportIds = new Set(mListingsArr.filter(l => l.sport_id).map(l => l.sport_id));
    const mSportsArr = mSportIds.size > 0
      ? (await client.from('sports').select('*').in('id', [...mSportIds])).data || []
      : [];
    const mSportsMap = new Map(mSportsArr.map(s => [s.id, s]));

    const enrichedMatches = mArr.map(m => {
      const listing = m.listing_id ? mListingsMap.get(m.listing_id) : null;
      const sport = listing?.sport_id ? mSportsMap.get(listing.sport_id) : null;
      const participantIds = mParticipantIdsByMatch.get(m.id) || [m.user1_id, m.user2_id].filter(Boolean);
      const displayUser2Id = pickDisplayUser2IdForViewer({
        match: m,
        participantIds,
        viewerId: req.userId,
      });
      const u1 = mUsersMap.get(m.user1_id);
      const u2 = mUsersMap.get(displayUser2Id) || mUsersMap.get(m.user2_id);
      return {
        ...toCamel(m), source: m.source || 'LISTING',
        user2Id: displayUser2Id,
        isGroupMatch: isGroupMatchRecord(m, listing),
        participantCount: participantIds.length,
        participants: participantIds
          .map(userId => safeUser(mUsersMap.get(userId)))
          .filter(Boolean),
        user1: u1 ? { id: u1.id, name: u1.name, avatarUrl: u1.avatar_url } : null,
        user2: u2 ? { id: u2.id, name: u2.name, avatarUrl: u2.avatar_url } : null,
        listing: listing ? { id: listing.id, type: listing.type, sport: sport ? toCamel(sport) : null } : null,
      };
    });

    res.json({ listings: enrichedListings, responses: enrichedInterests, matches: enrichedMatches });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/ratings', authMiddleware, async (req, res) => {
  try {
    const { matchId, score, comment, rateeId: requestedRateeId } = req.body;
    if (!matchId || score == null) return res.status(400).json({ message: 'matchId ve score gerekli.' });

    const s = parseInt(score, 10);
    if (isNaN(s) || s < 1 || s > 5) return res.status(400).json({ message: 'Puan 1-5 arasÄ±nda olmalÄ±.' });

    const m = await db.findById('matches', matchId);
    if (!m) return res.status(404).json({ message: 'MaÃ§ bulunamadÄ±.' });
    if (m.status !== 'COMPLETED') return res.status(400).json({ message: 'YalnÄ±zca tamamlanan maÃ§lar deÄŸerlendirilebilir.' });

    const listing = await listingById(m.listing_id);
    const participantIds = await getMatchParticipantIds(m, listing);
    const isGroupMatch = isGroupMatchRecord(m, listing);
    if (!participantIds.includes(req.userId)) return res.status(403).json({ message: 'Bu maÃ§Ä±n katÄ±lÄ±mcÄ±sÄ± deÄŸilsiniz.' });

    let rateeId;
    if (isGroupMatch) {
      if (requestedRateeId && requestedRateeId !== req.userId && participantIds.includes(requestedRateeId)) {
        rateeId = requestedRateeId;
      } else if (req.userId === m.user1_id) {
        rateeId = participantIds.find(userId => userId && userId !== req.userId) || m.user2_id;
      } else {
        rateeId = m.user1_id;
      }
    } else {
      rateeId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    }

    if (!rateeId || rateeId === req.userId) {
      return res.status(400).json({ message: 'GeÃ§erli bir deÄŸerlendirme hedefi bulunamadÄ±.' });
    }

    const sportId = listing?.sport_id || null;

    // Check for existing rating: per sport per user pair (NOT per match)
    let existingRating = null;
    if (sportId) {
      existingRating = await db.findOne('ratings', { rater_id: req.userId, ratee_id: rateeId, sport_id: sportId });
    }
    if (!existingRating) {
      existingRating = await db.findOne('ratings', { match_id: matchId, rater_id: req.userId, ratee_id: rateeId });
    }
    if (!existingRating && !isGroupMatch) {
      // Backward compatibility for legacy single-row match ratings.
      existingRating = await db.findOne('ratings', { match_id: matchId, rater_id: req.userId });
    }

    if (existingRating) {
      // EDIT existing rating (update score + comment)
      await db.update('ratings', existingRating.id, {
        score: s,
        comment: comment || existingRating.comment,
        match_id: matchId, // update to latest match
      });

      // Recalculate ratee average
      const ratee = await userById(rateeId);
      if (ratee) {
        const allRatings = await db.query('ratings', { filters: { ratee_id: rateeId } });
        const totalScore = allRatings.reduce((sum, r) => sum + (r.score || 0), 0);
        const newAvg = allRatings.length > 0 ? parseFloat((totalScore / allRatings.length).toFixed(2)) : 0;
        await db.update('users', rateeId, { average_rating: newAvg, rating_count: allRatings.length });
      }

      return res.json({ message: 'DeÄŸerlendirme gÃ¼ncellendi.', updated: true });
    }

    // NEW rating
    const ratee = await userById(rateeId);
    if (ratee) {
      const prevTotal = (ratee.average_rating || 0) * (ratee.rating_count || 0);
      const newCount = (ratee.rating_count || 0) + 1;
      const newAvg = parseFloat(((prevTotal + s) / newCount).toFixed(2));
      await db.update('users', rateeId, { average_rating: newAvg, rating_count: newCount });
    }

    try {
      await db.insert('ratings', {
        id: uuid(), match_id: matchId, rater_id: req.userId,
        ratee_id: rateeId, score: s, comment: comment || null,
        sport_id: sportId,
      });
    } catch (insertErr) {
      const errMsg = String(insertErr?.message || '');
      if (isGroupMatch && /(ratings_match_id_rater_id_key|match_id.*rater_id)/i.test(errMsg)) {
        return res.status(409).json({
          message: 'Grup maÃ§Ä±nda birden fazla partner deÄŸerlendirebilmek iÃ§in ratings migrationÄ± gerekli (005_ratings_group_unique.sql).',
        });
      }
      throw insertErr;
    }

    const rater = await userById(req.userId);
    await pushNotification({
      userId: rateeId, type: 'NEW_RATING',
      title: 'â­ Yeni DeÄŸerlendirme',
      body: `${rater?.name || 'Birisi'} sizi deÄŸerlendirdi`,
      relatedId: matchId, senderId: req.userId,
      senderName: rater?.name, senderAvatar: rater?.avatar_url,
    });

    res.status(201).json({ message: 'DeÄŸerlendirme kaydedildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Misc â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/turnuvalar', authMiddleware, (_req, res) => res.json({ data: [] }));
app.get('/api/tournaments', authMiddleware, (_req, res) => res.json({ data: [] }));

async function handlePushToken(req, res) {
  try {
    const action = String(req.body?.action || 'register').trim().toLowerCase();
    const token = normalizePushToken(req.body?.token);
    const platform = normalizePushPlatform(req.body?.platform);
    const locale = normalizePushLocale(
      req.body?.locale || req.body?.language || req.body?.languageCode,
      '',
    );

    logPushTelemetry('token_request', {
      userId: req.userId,
      action,
      platform,
      locale: locale || null,
      token: maskPushTokenForLogs(token),
      tokenLength: token.length,
    });

    if (action !== 'register' && action !== 'unregister') {
      return res.status(400).json({ message: 'GeÃ§ersiz action. register veya unregister olmalÄ±.' });
    }

    if (action === 'register') {
      if (!token || token.length < 20) {
        return res.status(400).json({ message: 'GeÃ§ersiz push token.' });
      }

      const result = await upsertPushToken({
        userId: req.userId,
        token,
        platform,
        locale,
      });
      logPushTelemetry('token_result', {
        userId: req.userId,
        action,
        platform,
        locale: locale || null,
        localeStored: result.localeStored !== false,
        stored: !!result.stored,
        reason: result.reason || 'ok',
      });

      if (!result.stored && result.reason === 'missing_table') {
        return res.status(202).json({
          message: 'Push token alÄ±ndÄ± fakat push_tokens tablosu henÃ¼z oluÅŸturulmamÄ±ÅŸ.',
        });
      }

      return res.json({
        message: 'Push token kaydedildi.',
        locale: locale || null,
      });
    }

    const result = await deactivatePushToken({ userId: req.userId, token });
    logPushTelemetry('token_result', {
      userId: req.userId,
      action,
      platform,
      stored: !!result.stored,
      reason: result.reason || 'ok',
    });

    if (!result.stored && result.reason === 'missing_table') {
      return res.status(202).json({ message: 'Push token kaldÄ±rma isteÄŸi alÄ±ndÄ±.' });
    }

    return res.json({
      message: token ? 'Push token kaldÄ±rÄ±ldÄ±.' : 'TÃ¼m push tokenlar kaldÄ±rÄ±ldÄ±.',
    });
  } catch (e) {
    console.error('push token error:', e);
    logPushTelemetry('token_error', {
      userId: req.userId,
      error: clipForLogs(e?.message || e),
    });
    return res.status(500).json({ message: 'Push token iÅŸlenemedi.' });
  }
}

// Main endpoint
app.post('/api/push/token', authMiddleware, handlePushToken);
// Backward-compatible alias for old clients posting to /api/push
app.post('/api/push', authMiddleware, handlePushToken);

app.get('/api/clubs', authMiddleware, async (_req, res) => {
  try {
    const data = await db.query('communities', { filters: { type: 'CLUB' } });
    res.json({ data: data.map(toCamel) });
  } catch { res.json({ data: [] }); }
});
app.post('/api/reports', authMiddleware, (_req, res) => res.json({ success: true, message: 'Åikayet alÄ±ndÄ±.' }));

// â”€â”€ Communities (simplified) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/communities', authMiddleware, async (req, res) => {
  try {
    const { type, search } = req.query;
    const client = db.raw();
    let q = client.from('communities').select('*');
    if (type) q = q.eq('type', type);
    if (search) q = q.ilike('name', `%${search}%`);
    const { data } = await q;
    res.json({ data: (data || []).map(toCamel), total: (data || []).length });
  } catch { res.json({ data: [], total: 0 }); }
});

app.get('/api/groups', authMiddleware, async (_req, res) => {
  try {
    const data = await db.query('groups');
    res.json({ groups: data.map(toCamel) });
  } catch { res.json({ groups: [] }); }
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BOT ECOSYSTEM â€” Åehir/Ãœlke CanlandÄ±rma Motoru (Supabase-backed)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Lazy load: bot-automation modÃ¼lÃ¼ (LOCALIZED_NAMES 24 Ã¼lke) sadece
// ecosystem endpoint'i ilk kez Ã§aÄŸrÄ±ldÄ±ÄŸÄ±nda yÃ¼klenir â€” cold start'Ä± hÄ±zlandÄ±rÄ±r.
let _botAutomationCache = undefined;
function getBotAutomation() {
  if (_botAutomationCache !== undefined) return _botAutomationCache;
  try { _botAutomationCache = require('../lib/bot-automation'); }
  catch { _botAutomationCache = null; }
  return _botAutomationCache;
}

function buildCityIdVariants(cityId) {
  if (!cityId) return [];
  const raw = String(cityId);
  const variants = new Set([raw]);
  if (raw.startsWith('state_')) {
    variants.add(raw.slice(6));
  } else if (/^\d+$/.test(raw)) {
    variants.add(`state_${raw}`);
  }
  return [...variants].filter(Boolean);
}

function normalizeText(v) {
  return String(v || '').trim().toLowerCase();
}

function botBelongsToEcosystem(bot, eco) {
  if (!bot || !eco) return false;

  const ecoCountry = String(eco.country_code || '').toUpperCase();
  const botCountry = String(bot.country_code || '').toUpperCase();
  const countryMatches = !ecoCountry || !botCountry || ecoCountry === botCountry;
  if (!countryMatches) return false;

  const idVariants = buildCityIdVariants(eco.city_id);
  const botCityId = String(bot.city_id || '');
  if (botCityId && idVariants.includes(botCityId)) return true;

  const ecoCityName = normalizeText(eco.city_name);
  const botCityName = normalizeText(bot.city);
  return !!ecoCityName && ecoCityName === botCityName;
}

async function getBotsForEcosystem(eco) {
  const client = db.raw();
  const idVariants = buildCityIdVariants(eco.city_id);

  if (idVariants.length > 0) {
    let q = client.from('users').select('*').eq('is_bot', true).in('city_id', idVariants);
    if (eco.country_code) q = q.eq('country_code', eco.country_code);
    const { data } = await q;
    if ((data || []).length > 0) return data || [];
  }

  if (eco.city_name) {
    let q = client.from('users').select('*').eq('is_bot', true).eq('city', eco.city_name);
    if (eco.country_code) q = q.eq('country_code', eco.country_code);
    const { data } = await q;
    return data || [];
  }

  return [];
}

async function resolvePersistCityId(rawCityId) {
  if (!rawCityId) return null;
  try {
    const city = await db.findById('cities', rawCityId);
    return city ? city.id : null;
  } catch {
    return null;
  }
}

const ecosystemRouter = express.Router();
ecosystemRouter.use(authMiddleware);

// Admin guard
ecosystemRouter.use(async (req, res, next) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Yetkisiz: Admin deÄŸilsiniz.' });
  next();
});

/**
 * GET /api/admin/ecosystems â€” TÃ¼m aktif ekosistemler
 */
ecosystemRouter.get('/', async (req, res) => {
  try {
    const ecosystems = await db.query('bot_ecosystems', { order: 'created_at', ascending: false });
    if (ecosystems.length === 0) return res.json({ data: [] });

    // Batch: tÃ¼m bot kullanÄ±cÄ±larÄ±nÄ± tek sorguda Ã§ek, city_id + city_name fallback ile eÅŸleÅŸtir
    const allBotsRes = await db.raw().from('users').select('id, city_id, city, country_code').eq('is_bot', true);
    const allBots = allBotsRes.data || [];
    const allActiveListingsRes = await db.raw().from('listings').select('user_id').eq('status', 'ACTIVE');
    const allActiveListings = allActiveListingsRes.data || [];

    const result = ecosystems.map(eco => {
      const ecoBots = allBots.filter(bot => botBelongsToEcosystem(bot, eco));
      const ecoBotIdSet = new Set(ecoBots.map(b => b.id));
      let ecoListingCount = 0;
      for (const listing of allActiveListings) {
        if (ecoBotIdSet.has(listing.user_id)) ecoListingCount++;
      }

      return {
        ...toCamel(eco),
        botCount: ecoBots.length,
        activeListing: ecoListingCount,
        activeListings: ecoListingCount,
      };
    });

    res.json({ data: result });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * POST /api/admin/ecosystems â€” Yeni ekosistem oluÅŸtur (Åehir/Ãœlke CanlandÄ±r)
 *
 * Body:
 *   scope: 'CITY' | 'COUNTRY' | 'WORLD'
 *   countryCode: 'TR' (required for CITY/COUNTRY)
 *   cityId: 'state_123' (required for CITY)
 *   cityName: 'Ä°stanbul' (required for CITY)
 *   sportIds: ['sport_yoga', 'sport_pilates'] (array of sport IDs)
 *   listingType: 'PARTNER' | 'RIVAL' | 'BOTH'
 *   botsPerCity: 4-20 (default 6) â€” must be even
 *   maxParticipants: 3-6 (default 4) â€” group listing size
 *   hourlyApplications: 1-5 (default 2)
 */
ecosystemRouter.post('/', async (req, res) => {
  try {
    const botAutomation = getBotAutomation();
    if (!botAutomation) return res.status(500).json({ message: 'Bot automation module not available.' });

    const {
      scope = 'CITY',
      countryCode,
      cityId, cityName,
      sportIds = [],
      listingType = 'PARTNER',
      botsPerCity = 6,
      botsPerGroup,
      groupsPerCity = 1,
      maxParticipants = 4,
      hourlyApplications = 2,
    } = req.body;

    if (scope === 'CITY' && (!cityId || !cityName)) {
      return res.status(400).json({ message: 'Åehir seÃ§ilmeli (cityId, cityName).' });
    }
    if ((scope === 'CITY' || scope === 'COUNTRY') && !countryCode) {
      return res.status(400).json({ message: 'Ãœlke kodu gerekli (countryCode).' });
    }

    // botsPerGroup * groupsPerCity = total bots per city (if botsPerGroup sent from Flutter)
    const totalBotsPerCity = botsPerGroup ? Math.min(40, (parseInt(botsPerGroup) || 8) * (parseInt(groupsPerCity) || 1)) : (parseInt(botsPerCity) || 6);
    const perCity = Math.min(40, Math.max(4, totalBotsPerCity));
    const maxPart = listingType === 'RIVAL'
      ? 2
      : Math.min(6, Math.max(3, parseInt(maxParticipants) || 4));
    const hourlyApps = Math.min(5, Math.max(1, parseInt(hourlyApplications) || 2));

    // Determine cities to animate
    let cities = [];
    if (scope === 'CITY') {
      cities = [{ id: cityId, name: cityName }];
    } else {
      // Load from states.json
      const fs = require('fs');
      const path = require('path');
      const possiblePaths = [
        path.join(__dirname, '..', 'assets', 'i18n'),
        path.join(__dirname, '..', '..', 'assets', 'i18n'),
      ];
      for (const base of possiblePaths) {
        try {
          const statesData = JSON.parse(fs.readFileSync(path.join(base, 'states.json'), 'utf-8').replace(/^\uFEFF/, ''));
          const countriesData = JSON.parse(fs.readFileSync(path.join(base, 'countries.json'), 'utf-8').replace(/^\uFEFF/, ''));
          if (scope === 'COUNTRY') {
            const entry = countriesData.find(c => c.iso2 === countryCode);
            if (entry && statesData[String(entry.id)]) {
              cities = statesData[String(entry.id)].map(s => ({ id: `state_${s.id}`, name: s.n }));
            }
          } else { // WORLD
            for (const entry of countriesData) {
              if (statesData[String(entry.id)]) {
                const cc = entry.iso2;
                for (const s of statesData[String(entry.id)].slice(0, 3)) {
                  cities.push({ id: `state_${s.id}`, name: s.n, countryCode: cc });
                }
              }
            }
          }
          if (cities.length > 0) break;
        } catch { continue; }
      }
    }

    if (cities.length === 0) return res.status(400).json({ message: 'Åehir verisi bulunamadÄ±.' });

    // Get sports
    const allSports = await db.query('sports');
    let selectedSports = sportIds.length > 0
      ? allSports.filter(s => sportIds.includes(s.id))
      : allSports.filter(s => ['yoga','pilates','running','hiking','table_tennis','swimming','cycling','fitness'].some(k => s.id?.includes(k) || s.name?.toLowerCase().includes(k)));
    if (selectedSports.length === 0) selectedSports = allSports.slice(0, 6);

    const locale = botAutomation.mapCountryCodeToLocale(countryCode || 'EN');
    const names = botAutomation.LOCALIZED_NAMES[countryCode] || botAutomation.DEFAULT_NAMES;

    let totalBots = 0, totalListings = 0;
    const ecosystemIds = [];
    const createdEcos = [];

    for (const city of cities) {
      const cc = city.countryCode || countryCode;
      const persistCityId = await resolvePersistCityId(city.id);

      // Check if ecosystem already exists for this city
      const existing = await db.findOne('bot_ecosystems', { city_id: city.id, status: 'ACTIVE' });
      if (existing) continue;

      // Create ecosystem record
      const ecoId = 'eco_' + uuid();
      const createdEco = await db.insert('bot_ecosystems', {
        id: ecoId,
        scope,
        country_code: cc,
        city_id: city.id,
        city_name: city.name,
        sport_ids: selectedSports.map(s => s.id),
        listing_type: listingType,
        bots_per_city: perCity,
        max_participants: maxPart,
        hourly_applications: hourlyApps,
        status: 'ACTIVE',
        total_bots: 0,
        total_listings: 0,
        total_matches: 0,
      });
      createdEcos.push(createdEco);
      ecosystemIds.push(ecoId);

      // Create bots (mostly female ~70%) â€” batch insert (tek Supabase Ã§aÄŸrÄ±sÄ±)
      const femalePct = 0.7;
      const femaleCount = Math.round(perCity * femalePct);
      const botRows = [];
      const botMeta = []; // id/name/gender/sportId bilgisi listings iÃ§in

      const nowMs = Date.now();
      for (let i = 0; i < perCity; i++) {
        const isFemale = i < femaleCount;
        const gender = isFemale ? 'FEMALE' : 'MALE';
        const nameList = isFemale ? names.female : names.male;
        const bName = nameList[i % nameList.length];
        const sport = selectedSports[i % selectedSports.length];
        const botId = 'bot_' + uuid();
        const coords = botAutomation.estimateBotCoordinates({ citySeed: city.id, countryCode: cc });
        const localizedSportName = botAutomation.translateSportName
          ? botAutomation.translateSportName(sport.id, locale, sport.name)
          : sport.name;
        const botPersona = buildBotPublicPersona({
          botName: bName,
          citySeed: city.id,
          countryCode: cc,
          botIndex: i,
          botId,
        });

        botRows.push({
          id: botId,
          email: `bot_${nowMs}_${i}_${city.id.slice(0, 6)}@sporpartner.internal`,
          name: bName,
          username: `bot_${bName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_${(nowMs + i) % 100000}`,
          password: '$2a$10$BOT_NO_LOGIN_PLACEHOLDER_HASH',
          avatar_url: botAutomation.buildBotAvatarUrl({
            gender,
            seed: `${botId}-${bName}-${city.id}-${sport.id}`,
            countryCode: cc,
            locale,
          }),
          cover_url: null, phone: null,
          is_admin: false, is_bot: true, bot_persona: null,
          onboarding_done: true, user_type: 'USER',
          city: city.name, city_id: persistCityId, country_code: cc,
          district: null, district_id: null,
          bio: botAutomation.generateBotBio({ locale, sportName: localizedSportName, cityName: city.name }),
          ...botPersona.socialLinks,
          sports: [{ id: sport.id, name: sport.name, icon: sport.icon }],
          level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
          gender,
          preferred_time: null, preferred_style: null,
          birth_date: new Date(1992 + (i % 13), i % 12, 1 + (i % 28)).toISOString(),
          total_matches: 0, current_streak: 0, longest_streak: 0, total_points: 0,
          follower_count: botPersona.followerCount,
          following_count: botPersona.followingCount,
          average_rating: 0, rating_count: 0,
          is_banned: false, no_show_count: 0, is_private: false,
          latitude: coords.latitude, longitude: coords.longitude,
          referral_code: `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
        });
        botMeta.push({ id: botId, name: bName, gender, sportId: sport.id, sportName: sport.name });
      }

      // TÃ¼m botlarÄ± tek bir Supabase INSERT Ã§aÄŸrÄ±sÄ±yla ekle
      let botsCreated = [];
      try {
        await db.insertMany('users', botRows);
        botsCreated = botMeta;
        totalBots += botsCreated.length;
      } catch (err) {
        console.error(`Bot batch insert error (city: ${city.name}):`, err.message);
        // KÄ±smi baÅŸarÄ±sÄ±zlÄ±k: bireysel fallback
        for (let i = 0; i < botRows.length; i++) {
          try {
            await db.insert('users', botRows[i]);
            botsCreated.push(botMeta[i]);
            totalBots++;
          } catch (e2) {
            console.error(`Bot fallback insert error (${botMeta[i].name}):`, e2.message);
          }
        }
      }

      // Create initial group listings (female bots create listings) â€” batch insert
      const femaleBots = botsCreated.filter(b => b.gender === 'FEMALE');
      const listingRows = [];
      for (const bot of femaleBots) {
        const sport = selectedSports.find(s => s.id === bot.sportId) || selectedSports[0];
        const lType = listingType === 'BOTH' ? (Math.random() > 0.5 ? 'PARTNER' : 'RIVAL') : listingType;
        const futureDate = botAutomation.getFutureDate(1 + Math.floor(Math.random() * 6));
        const coords = botAutomation.estimateBotCoordinates({ citySeed: city.id, countryCode: cc });
        const listingId = 'listing_' + uuid();
        const localizedSportName = botAutomation.translateSportName
          ? botAutomation.translateSportName(sport.id, locale, sport.name)
          : sport.name;

        listingRows.push({
          id: listingId,
          type: lType,
          title: botAutomation.generateListingDesc({ name: bot.name, sport: localizedSportName, locale, city: city.name }),
          description: botAutomation.generateListingDesc({ name: bot.name, sport: localizedSportName, locale, city: city.name }),
          sport_id: sport.id, sport_name: localizedSportName,
          city_id: persistCityId, city_name: city.name,
          district_id: null, district_name: null,
          venue_id: null, venue_name: null,
          level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
          gender: 'ANY',
          date: futureDate.toISOString(),
          image_urls: [],
          max_participants: lType === 'RIVAL' ? 2 : maxPart,
          accepted_count: 0,
          status: 'ACTIVE',
          age_min: null, age_max: null,
          is_recurring: false, is_anonymous: false, is_urgent: false, is_quick: false,
          response_count: 0,
          user_id: bot.id, user_name: bot.name,
          user_avatar: null,
          latitude: coords.latitude, longitude: coords.longitude,
          expires_at: new Date(futureDate.getTime() + 7 * 86400000).toISOString(),
        });
      }

      // TÃ¼m ilanlarÄ± tek bir Supabase INSERT Ã§aÄŸrÄ±sÄ±yla ekle
      let cityListingsCreated = 0;
      if (listingRows.length > 0) {
        try {
          await db.insertMany('listings', listingRows);
          cityListingsCreated = listingRows.length;
          totalListings += cityListingsCreated;
        } catch (err) {
          console.error(`Listing batch insert error (city: ${city.name}):`, err.message);
          // KÄ±smi baÅŸarÄ±sÄ±zlÄ±k: bireysel fallback
          for (const row of listingRows) {
            try {
              await db.insert('listings', row);
              cityListingsCreated++;
              totalListings++;
            } catch (e2) {
              console.error(`Listing fallback insert error:`, e2.message);
            }
          }
        }
      }

      // Update ecosystem stats
      await db.update('bot_ecosystems', ecoId, {
        total_bots: botsCreated.length,
        total_listings: cityListingsCreated,
      });
    }

    // Auto-bootstrap for newly created ecosystems so they immediately join
    // both sports and social cycles without waiting for the next cron run.
    const bootstrap = [];
    if (createdEcos.length > 0 && createdEcos.length <= 3) {
      for (const eco of createdEcos) {
        try {
          const r = await runEcosystemTick(eco);
          bootstrap.push({ ecoId: eco.id, cityName: eco.city_name, ...r });
        } catch (err) {
          bootstrap.push({ ecoId: eco.id, cityName: eco.city_name, error: err.message });
        }
      }
    }

    res.json({
      success: true,
      message: `${cities.length} ÅŸehirde ${totalBots} bot + ${totalListings} ilan oluÅŸturuldu.`,
      data: {
        ecosystemIds,
        citiesAnimated: cities.length,
        totalBots,
        totalListings,
        sports: selectedSports.map(s => `${s.icon || ''} ${s.name}`),
        autoBootstrap: bootstrap,
      },
    });
  } catch (e) {
    console.error('Ecosystem create error:', e);
    res.status(500).json({ message: e.message });
  }
});

/**
 * POST /api/admin/ecosystems/:id/tick â€” Saatlik ekosistem gÃ¼ncellemesi
 * Botlar birbirlerinin ilanlarÄ±na baÅŸvurur, kabul eder, eÅŸleÅŸir, puanlar
 */
ecosystemRouter.post('/:id/tick', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadÄ±.' });
    if (eco.status !== 'ACTIVE') return res.status(400).json({ message: 'Ekosistem aktif deÄŸil.' });

    const result = await runEcosystemTick(eco);
    res.json({ success: true, data: result });
  } catch (e) {
    console.error('Ecosystem tick error:', e);
    res.status(500).json({ message: e.message });
  }
});

/**
 * POST /api/admin/ecosystems/tick-all â€” TÃ¼m aktif ekosistemlerin saatlik gÃ¼ncellemesi
 */
ecosystemRouter.post('/tick-all', async (req, res) => {
  try {
    const ecosystems = await db.query('bot_ecosystems', { filters: { status: 'ACTIVE' } });
    const results = [];
    for (const eco of ecosystems) {
      try {
        const r = await runEcosystemTick(eco);
        results.push({ ecoId: eco.id, cityName: eco.city_name, ...r });
      } catch (err) {
        results.push({ ecoId: eco.id, cityName: eco.city_name, error: err.message });
      }
    }
    res.json({ success: true, data: results, total: ecosystems.length });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * DELETE /api/admin/ecosystems/:id â€” Ekosistem sil (botlarÄ± ve verilerini temizle)
 */
ecosystemRouter.delete('/:id', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadÄ±.' });

    // Find all bots in this ecosystem (city_id/city_name fallback)
    const bots = await getBotsForEcosystem(eco);
    const botIds = bots.map(b => b.id);

    if (botIds.length > 0) {
      const client = db.raw();
      // Delete related data
      await client.from('ratings').delete().in('rater_id', botIds);
      await client.from('ratings').delete().in('ratee_id', botIds);
      await client.from('interests').delete().in('user_id', botIds);
      await client.from('matches').delete().or(botIds.map(id => `user1_id.eq.${id}`).join(','));
      await client.from('matches').delete().or(botIds.map(id => `user2_id.eq.${id}`).join(','));
      await client.from('listings').delete().in('user_id', botIds);
      await client.from('posts').delete().in('user_id', botIds);
      await client.from('notifications').delete().in('user_id', botIds);

      // Delete bots themselves
      for (const botId of botIds) {
        await db.remove('users', botId).catch(() => {});
      }
    }

    await db.remove('bot_ecosystems', eco.id);

    res.json({
      message: `${eco.city_name} ekosistemi silindi. ${botIds.length} bot temizlendi.`,
      data: { botsRemoved: botIds.length },
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * PATCH /api/admin/ecosystems/:id â€” Ekosistem gÃ¼ncelle (duraklatma, parametre deÄŸiÅŸtirme)
 */
ecosystemRouter.patch('/:id', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadÄ±.' });

    const { status, hourlyApplications, maxParticipants, sportIds, listingType } = req.body;
    const changes = {};
    const nextListingType = listingType || eco.listing_type;
    if (status && ['ACTIVE', 'PAUSED'].includes(status)) changes.status = status;
    if (hourlyApplications) changes.hourly_applications = Math.min(5, Math.max(1, parseInt(hourlyApplications)));
    if (nextListingType === 'RIVAL') {
      changes.max_participants = 2;
    } else if (maxParticipants) {
      changes.max_participants = Math.min(6, Math.max(3, parseInt(maxParticipants)));
    }
    if (sportIds) changes.sport_ids = sportIds;
    if (listingType) changes.listing_type = listingType;

    const updated = await db.update('bot_ecosystems', eco.id, changes);
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * POST /api/admin/ecosystems/:id/toggle-bots-privacy
 * BotlarÄ±n profillerini public/private yap
 */
ecosystemRouter.post('/:id/toggle-bots-privacy', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadÄ±.' });

    const { isPrivate } = req.body;
    const bots = await getBotsForEcosystem(eco);
    let updated = 0;
    for (const bot of bots) {
      await db.update('users', bot.id, { is_private: !!isPrivate });
      updated++;
    }
    res.json({ message: `${updated} bot profili ${isPrivate ? 'gizli' : 'herkese aÃ§Ä±k'} yapÄ±ldÄ±.` });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Ecosystem Tick Engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function runEcosystemTick(eco) {
  const stats = { newApplications: 0, newAcceptances: 0, newMatches: 0, newRatings: 0, newListings: 0, newPosts: 0, newReactions: 0, newComments: 0 };
  const persistEcoCityId = await resolvePersistCityId(eco.city_id);

  // Get all bots in this ecosystem (city_id format fallback + city_name fallback)
  let bots = await getBotsForEcosystem(eco);

  // If no bots exist (e.g. initial creation timed out), create them now
  if (bots.length < 2) {
    const botAutomationFill = getBotAutomation();
    if (botAutomationFill && eco.city_id && eco.country_code) {
      const allSportsForFill = await db.query('sports');
      let fillSports = (eco.sport_ids && eco.sport_ids.length > 0)
        ? allSportsForFill.filter(s => eco.sport_ids.includes(s.id))
        : allSportsForFill.filter(s => ['yoga','pilates','running','hiking','table_tennis','swimming','cycling','fitness'].includes(s.id));
      if (fillSports.length === 0) fillSports = allSportsForFill.filter(s => ['yoga','pilates','fitness','running'].includes(s.id));
      const perCity = eco.bots_per_city || 6;
      const femalePct = 0.7;
      const femaleCount = Math.round(perCity * femalePct);
      const locale = botAutomationFill.mapCountryCodeToLocale(eco.country_code || 'EN');
      const names = botAutomationFill.LOCALIZED_NAMES[eco.country_code] || botAutomationFill.DEFAULT_NAMES;
      const fillRows = [];
      const fillMeta = [];
      const nowMs = Date.now();
      for (let i = 0; i < perCity; i++) {
        const isFemale = i < femaleCount;
        const gender = isFemale ? 'FEMALE' : 'MALE';
        const nameList = isFemale ? names.female : names.male;
        const bName = nameList[i % nameList.length];
        const sport = fillSports[i % fillSports.length];
        const botId = 'bot_' + uuid();
        const coords = botAutomationFill.estimateBotCoordinates({ citySeed: eco.city_id, countryCode: eco.country_code });
        const localizedSportName = botAutomationFill.translateSportName
          ? botAutomationFill.translateSportName(sport.id, locale, sport.name)
          : sport.name;
        const botPersona = buildBotPublicPersona({
          botName: bName,
          citySeed: eco.city_id || eco.city_name || 'city',
          countryCode: eco.country_code,
          botIndex: i,
          botId,
        });
        fillRows.push({
          id: botId, email: `bot_${nowMs}_fill_${i}_${eco.city_id.slice(0,6)}@sporpartner.internal`,
          name: bName, username: `bot_${bName.replace(/[^a-zA-Z0-9]/g,'').toLowerCase()}_fill_${(nowMs+i)%100000}`,
          password: '$2a$10$BOT_NO_LOGIN_PLACEHOLDER_HASH',
          avatar_url: botAutomationFill.buildBotAvatarUrl({
            gender,
            seed: `${botId}-${bName}-${eco.city_id}-${sport.id}`,
            countryCode: eco.country_code,
            locale,
          }),
          cover_url: null, phone: null, is_admin: false, is_bot: true, bot_persona: null,
          onboarding_done: true, user_type: 'USER',
          city: eco.city_name, city_id: persistEcoCityId, country_code: eco.country_code,
          district: null, district_id: null,
          bio: botAutomationFill.generateBotBio({ locale, sportName: localizedSportName, cityName: eco.city_name }),
          ...botPersona.socialLinks,
          sports: [{ id: sport.id, name: sport.name, icon: sport.icon }],
          level: ['BEGINNER','INTERMEDIATE','ADVANCED'][Math.floor(Math.random()*3)],
          gender, preferred_time: null, preferred_style: null,
          birth_date: new Date(1992+(i%13), i%12, 1+(i%28)).toISOString(),
          total_matches: 0, current_streak: 0, longest_streak: 0, total_points: 0,
          follower_count: botPersona.followerCount,
          following_count: botPersona.followingCount,
          average_rating: 0, rating_count: 0,
          is_banned: false, no_show_count: 0, is_private: false,
          latitude: coords.latitude, longitude: coords.longitude,
          referral_code: `SP${Math.random().toString(36).slice(2,8).toUpperCase()}`,
        });
        fillMeta.push({ id: botId, name: bName, gender, sportId: sport.id });
      }
      try {
        await db.insertMany('users', fillRows);
        await db.update('bot_ecosystems', eco.id, { total_bots: perCity });
        stats.newBots = perCity;
      } catch (e) {
        console.error('Tick bot-fill error:', e.message);
      }
      bots = await getBotsForEcosystem(eco);
    }
    if (bots.length < 2) return stats;
  }

  // Keep old ecosystem bots realistic: 3 social links + 400-500 followers/following.
  for (let i = 0; i < bots.length; i++) {
    const bot = bots[i];
    const baselinePatch = buildBotBaselinePatch({ bot, eco, botIndex: i });
    if (Object.keys(baselinePatch).length === 0) continue;
    try {
      await db.update('users', bot.id, baselinePatch);
      Object.assign(bot, baselinePatch);
    } catch (baselineErr) {
      console.error(`Bot baseline patch error (${bot.id}):`, baselineErr.message);
    }
  }

  const botIds = bots.map(b => b.id);
  const botIdSet = new Set(botIds);
  const botAutomation = getBotAutomation();
  const locale = botAutomation ? botAutomation.mapCountryCodeToLocale(eco.country_code || 'EN') : 'en';

  // 1. APPLICATIONS â€” Bots apply to active listings
  const client = db.raw();
  const { data: activeListings } = await client.from('listings').select('*')
    .eq('status', 'ACTIVE')
    .in('user_id', botIds)
    .order('created_at', { ascending: false });

  for (const listing of (activeListings || [])) {
    // Find bots that haven't applied yet (not the listing owner)
    const { data: existingInterests } = await client.from('interests').select('user_id')
      .eq('listing_id', listing.id);
    const appliedIds = new Set((existingInterests || []).map(i => i.user_id));
    appliedIds.add(listing.user_id); // Owner can't apply

    const candidates = bots.filter(b => !appliedIds.has(b.id));
    const toApply = candidates.slice(0, eco.hourly_applications || 2);

    for (const bot of toApply) {
      const interest = {
        id: uuid(),
        listing_id: listing.id,
        user_id: bot.id,
        user_name: bot.name,
        user_avatar: bot.avatar_url,
        message: botAutomation ? botAutomation.generateResponseMsg(bot.name, locale) : `${bot.name} katÄ±lmak istiyor!`,
        status: 'PENDING',
      };
      try {
        await db.insert('interests', interest);
        await db.update('listings', listing.id, { response_count: (listing.response_count || 0) + 1 });
        stats.newApplications++;
      } catch { /* skip duplicates */ }
    }
  }

  // 2. ACCEPTANCES â€” Listing owners accept pending applications
  const { data: pendingInterests } = await client.from('interests').select('*')
    .in('listing_id', (activeListings || []).map(l => l.id))
    .eq('status', 'PENDING');

  for (const interest of (pendingInterests || [])) {
    const listing = (activeListings || []).find(l => l.id === interest.listing_id);
    if (!listing || !botIdSet.has(listing.user_id)) continue;

    const listingType = String(listing.type || '').toUpperCase();
    if (listingType === 'RIVAL' && (listing.max_participants || 0) !== 2) {
      try {
        await db.update('listings', listing.id, { max_participants: 2 });
        listing.max_participants = 2;
      } catch (quotaFixErr) {
        console.error(`RIVAL quota normalize error (${listing.id}):`, quotaFixErr.message);
      }
    }

    // Check capacity
    const currentAccepted = listing.accepted_count || 0;
    const effectiveMaxParticipants = listingType === 'RIVAL'
      ? 2
      : (listing.max_participants || 4);
    const slotsNeeded = Math.max(1, effectiveMaxParticipants - 1);
    if (currentAccepted >= slotsNeeded) continue;

    // Accept
    await db.update('interests', interest.id, { status: 'ACCEPTED' });
    const newAccepted = currentAccepted + 1;
    const isFull = newAccepted >= slotsNeeded;
    const listingUpdates = { accepted_count: newAccepted };
    if (isFull) {
      listingUpdates.status = 'MATCHED';
      // Reject remaining pending
      await db.updateWhere('interests',
        { listing_id: listing.id, status: 'PENDING' },
        { status: 'REJECTED' }
      );
    }
    await db.update('listings', listing.id, listingUpdates);
    listing.accepted_count = newAccepted; // Update in-memory reference

    let matchCreated = false;
    let matchedParticipantIds = [];

    if (effectiveMaxParticipants <= 2) {
      const matchId = 'match_' + uuid();
      try {
        await db.insert('matches', {
          id: matchId,
          listing_id: listing.id,
          source: 'LISTING',
          user1_id: listing.user_id,
          user2_id: interest.user_id,
          status: 'SCHEDULED',
          u1_approved: false, u2_approved: false,
          scheduled_at: listing.date || null,
          completed_at: null,
        });
        await persistMatchParticipants({
          matchId,
          participantIds: [listing.user_id, interest.user_id],
          ownerId: listing.user_id,
        });
        stats.newMatches++;
        matchCreated = true;
        matchedParticipantIds = [listing.user_id, interest.user_id].filter(Boolean);
      } catch (matchErr) {
        console.error(`Match insert error (${listing.id}/${interest.id}):`, matchErr.message);
      }
    } else if (isFull && listingType === 'PARTNER') {
      try {
        const acceptedParticipantIds = await getListingAcceptedParticipantIds(listing);
        matchedParticipantIds = acceptedParticipantIds;
        let groupMatchId = null;

        const existingGroupMatch = await db.findOne('matches', {
          listing_id: listing.id,
        });

        if (!existingGroupMatch) {
          const anchorParticipantId = acceptedParticipantIds.find(userId => userId && userId !== listing.user_id) || interest.user_id;
          groupMatchId = 'match_' + uuid();
          await db.insert('matches', {
            id: groupMatchId,
            listing_id: listing.id,
            source: 'LISTING',
            user1_id: listing.user_id,
            user2_id: anchorParticipantId,
            status: 'SCHEDULED',
            u1_approved: false,
            u2_approved: false,
            scheduled_at: listing.date || null,
            completed_at: null,
          });
          stats.newMatches++;
          matchCreated = true;
        } else {
          groupMatchId = existingGroupMatch.id;
        }

        if (groupMatchId && acceptedParticipantIds.length > 0) {
          await persistMatchParticipants({
            matchId: groupMatchId,
            participantIds: acceptedParticipantIds,
            ownerId: listing.user_id,
          });
        }
      } catch (groupMatchErr) {
        console.error(`Group match insert error (${listing.id}/${interest.id}):`, groupMatchErr.message);
      }
    }
    stats.newAcceptances++;

    // Keep user total_matches aligned with real match records only.
    if (matchCreated) {
      const rewardIds = [...new Set((matchedParticipantIds.length > 0
        ? matchedParticipantIds
        : [listing.user_id, interest.user_id]
      ).filter(Boolean))];

      for (const userId of rewardIds) {
        const user = await userById(userId);
        if (user) {
          await db.update('users', user.id, { total_matches: (user.total_matches || 0) + 1 });
        }
      }
    }
  }

  // 3. RATINGS â€” Complete scheduled matches and rate each other
  const botMatchFilters = botIds
    .flatMap(id => [`user1_id.eq.${id}`, `user2_id.eq.${id}`])
    .join(',');
  const { data: scheduledMatches } = await client.from('matches').select('*')
    .eq('status', 'SCHEDULED')
    .or(botMatchFilters);

  for (const m of (scheduledMatches || [])) {
    if (!botIdSet.has(m.user1_id) || !botIdSet.has(m.user2_id)) continue;

    // Auto-complete the match
    const completedAt = new Date().toISOString();
    await db.update('matches', m.id, {
      status: 'COMPLETED',
      u1_approved: true, u2_approved: true,
      completed_at: completedAt,
    });

    // Both bots rate each other
    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const sportId = listing?.sport_id || null;

    for (const [raterId, rateeId] of [[m.user1_id, m.user2_id], [m.user2_id, m.user1_id]]) {
      // Check if already rated (per sport per user pair)
      const existingRating = sportId
        ? await db.findOne('ratings', { rater_id: raterId, ratee_id: rateeId, sport_id: sportId })
        : await db.findOne('ratings', { rater_id: raterId, ratee_id: rateeId });

      if (existingRating) {
        // Update existing rating (edit, not duplicate)
        const newScore = 4 + Math.floor(Math.random() * 2); // 4-5
        await db.update('ratings', existingRating.id, { score: newScore, match_id: m.id });
      } else {
        const score = 4 + Math.floor(Math.random() * 2); // 4-5
        const comments = ['Harika partner! ğŸ¾', 'Ã‡ok keyifli maÃ§tÄ±!', 'Tekrar oynamak isterim', 'Great game!', 'Super Spiel!', 'ĞÑ‚Ğ»Ğ¸Ñ‡Ğ½Ğ°Ñ Ğ¸Ğ³Ñ€Ğ°!'];
        await db.insert('ratings', {
          id: uuid(),
          match_id: m.id,
          rater_id: raterId,
          ratee_id: rateeId,
          score,
          comment: comments[Math.floor(Math.random() * comments.length)],
          sport_id: sportId,
        });

        // Update ratee stats
        const ratee = await userById(rateeId);
        if (ratee) {
          const prevTotal = (ratee.average_rating || 0) * (ratee.rating_count || 0);
          const newCount = (ratee.rating_count || 0) + 1;
          const newAvg = parseFloat(((prevTotal + score) / newCount).toFixed(2));
          await db.update('users', rateeId, { average_rating: newAvg, rating_count: newCount });
        }
        stats.newRatings++;
      }
    }
  }

  // 4. NEW LISTINGS â€” Create new listings to replace matched ones
  const femaleBots = bots.filter(b => b.gender === 'FEMALE');
  const sports = eco.sport_ids ? await Promise.all(eco.sport_ids.map(id => db.findById('sports', id))) : [];
  const validSports = sports.filter(Boolean);
  if (validSports.length === 0) {
    // Fallback: use preferred ecosystem sports (not random DB order)
    const preferredIds = ['yoga','pilates','fitness','running','hiking','swimming','cycling','table_tennis'];
    const allSportsFb = await db.query('sports');
    const preferred = allSportsFb.filter(s => preferredIds.includes(s.id));
    validSports.push(...(preferred.length > 0 ? preferred : allSportsFb.slice(0, 6)));
  }

  // Each female bot should have at most 1 active listing
  for (const bot of femaleBots) {
    const { data: activeBot } = await client.from('listings').select('id')
      .eq('user_id', bot.id).eq('status', 'ACTIVE');
    if ((activeBot || []).length > 0) continue; // Already has active listing

    // Create a new listing with a different sport (weekly variety)
    const weekNumber = Math.floor(Date.now() / (7 * 86400000));
    const sportIndex = (weekNumber + femaleBots.indexOf(bot)) % validSports.length;
    const sport = validSports[sportIndex];
    const lType = eco.listing_type === 'BOTH' ? (Math.random() > 0.5 ? 'PARTNER' : 'RIVAL') : (eco.listing_type || 'PARTNER');
    const futureDate = botAutomation ? botAutomation.getFutureDate(1 + Math.floor(Math.random() * 6)) : new Date(Date.now() + 3 * 86400000);
    const coords = botAutomation ? botAutomation.estimateBotCoordinates({ citySeed: eco.city_id, countryCode: eco.country_code }) : { latitude: 0, longitude: 0 };

    const listingId = 'listing_' + uuid();
    const localizedSportName = botAutomation && botAutomation.translateSportName
      ? botAutomation.translateSportName(sport.id, locale, sport.name)
      : sport.name;
    try {
      await db.insert('listings', {
        id: listingId,
        type: lType,
        title: botAutomation ? botAutomation.generateListingDesc({ name: bot.name, sport: localizedSportName, locale, city: eco.city_name }) : `${bot.name} - ${sport.name}`,
        description: botAutomation ? botAutomation.generateListingDesc({ name: bot.name, sport: localizedSportName, locale, city: eco.city_name }) : null,
        sport_id: sport.id, sport_name: localizedSportName,
        city_id: persistEcoCityId, city_name: eco.city_name,
        district_id: null, district_name: null,
        venue_id: null, venue_name: null,
        level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
        gender: 'ANY',
        date: futureDate.toISOString ? futureDate.toISOString() : futureDate,
        image_urls: [],
        max_participants: lType === 'RIVAL' ? 2 : (eco.max_participants || 4),
        accepted_count: 0,
        status: 'ACTIVE',
        age_min: null, age_max: null,
        is_recurring: false, is_anonymous: false, is_urgent: false, is_quick: false,
        response_count: 0,
        user_id: bot.id, user_name: bot.name, user_avatar: bot.avatar_url,
        latitude: coords.latitude, longitude: coords.longitude,
        expires_at: new Date((futureDate.getTime ? futureDate.getTime() : Date.now()) + 7 * 86400000).toISOString(),
      });
      stats.newListings++;
    } catch (err) {
      console.error(`New listing error:`, err.message);
    }
  }

  // 5. SOCIAL POSTS â€” Bots create social posts (SOCIAL_LISTING) in their own language
  // ~60% of bots post per tick if they haven't posted in the last 24 hours
  if (botAutomation) {
    const oneDayAgo = new Date(Date.now() - 24 * 3600000).toISOString();
    // Fetch recent SOCIAL_LISTING posts by these bots (last 24h) to skip already-posted bots
    const { data: recentBotPosts } = await client.from('posts')
      .select('user_id')
      .eq('post_type', 'SOCIAL_LISTING')
      .in('user_id', botIds)
      .gte('created_at', oneDayAgo);
    const recentPostersSet = new Set((recentBotPosts || []).map(p => p.user_id));

    // Pick up to 4 bots that haven't posted yet today
    const postCandidates = bots.filter(b => !recentPostersSet.has(b.id));
    const botsToPost = postCandidates.slice(0, 4);

    const postRows = [];
    for (const bot of botsToPost) {
      const botLocale = botAutomation.mapCountryCodeToLocale(bot.country_code || eco.country_code || 'EN');
      const botSport = (bot.sports && bot.sports.length > 0) ? bot.sports[0] : (validSports.length > 0 ? validSports[0] : null);
      const sportName = botSport ? botAutomation.translateSportName
        ? botAutomation.translateSportName(botSport.id, botLocale, botSport.name)
        : botSport.name
        : null;
      const socialListing = botAutomation.generateBotSocialListing
        ? botAutomation.generateBotSocialListing({
            locale: botLocale,
            sportName,
            cityName: bot.city || eco.city_name,
            botName: bot.name,
          })
        : {
            kind: 'SPORT',
            title: null,
            content: botAutomation.generateBotSocialPost({
              locale: botLocale,
              sportName,
              cityName: bot.city || eco.city_name,
              botName: bot.name,
            }),
          };
      postRows.push({
        id: 'post_' + uuid(),
        user_id: bot.id,
        post_type: 'SOCIAL_LISTING',
        content: socialListing.content,
        title: socialListing.title || null,
        image_url: null,
        sport_id: socialListing.kind === 'TOPIC' ? null : (botSport ? botSport.id : null),
        city_id: null,
        city_name: bot.city || eco.city_name || null,
        district_id: null,
      });
    }
    if (postRows.length > 0) {
      try {
        await db.insertMany('posts', postRows);
        stats.newPosts += postRows.length;
      } catch (postInsertErr) {
        // Fallback: insert individually
        for (const pr of postRows) {
          try { await db.insert('posts', pr); stats.newPosts++; } catch { /* skip */ }
        }
      }
    }
  }

  // 6. REACTIONS â€” Bots react (LIKE/FIRE/CLAP) to recent posts from ANY ecosystem
  // Fetches last 30 global posts so bots from different countries can interact
  if (botAutomation) {
    const BOT_REACTION_TYPES = ['LIKE', 'FIRE', 'CLAP', 'LOVE', 'STRONG'];
    const twoDaysAgo = new Date(Date.now() - 48 * 3600000).toISOString();
    const { data: recentGlobalPosts } = await client.from('posts')
      .select('id,user_id,sport_id,city_name')
      .eq('post_type', 'SOCIAL_LISTING')
      .gte('created_at', twoDaysAgo)
      .order('created_at', { ascending: false })
      .limit(30);

    const globalPostIds = (recentGlobalPosts || []).map(p => p.id);
    if (globalPostIds.length > 0) {
      // Fetch all existing reactions from our bots on these posts to skip duplicates
      const { data: existingReactions } = await client.from('post_reactions')
        .select('post_id,user_id').in('post_id', globalPostIds).in('user_id', botIds);
      const reactedSet = new Set((existingReactions || []).map(r => `${r.user_id}_${r.post_id}`));

      const reactionRows = [];
      // Each bot reacts to up to 2 posts it hasn't reacted to yet (skip own posts)
      for (const bot of bots) {
        let reacted = 0;
        for (const post of (recentGlobalPosts || [])) {
          if (reacted >= 2) break;
          if (post.user_id === bot.id) continue; // don't react to own post
          const key = `${bot.id}_${post.id}`;
          if (reactedSet.has(key)) continue;
          const rType = BOT_REACTION_TYPES[Math.floor(Math.random() * BOT_REACTION_TYPES.length)];
          reactionRows.push({ id: uuid(), post_id: post.id, user_id: bot.id, type: rType });
          reactedSet.add(key);
          reacted++;
        }
      }
      if (reactionRows.length > 0) {
        try {
          await db.insertMany('post_reactions', reactionRows);
          stats.newReactions += reactionRows.length;
        } catch (rxErr) {
          for (const rr of reactionRows) {
            try { await db.insert('post_reactions', rr); stats.newReactions++; } catch { /* skip duplicate */ }
          }
        }
      }
    }
  }

  // 7. COMMENTS â€” Bots comment on recent global posts (40% chance per reaction)
  if (botAutomation) {
    const twoDaysAgoC = new Date(Date.now() - 48 * 3600000).toISOString();
    const { data: postsToComment } = await client.from('posts')
      .select('id,user_id,sport_id').eq('post_type', 'SOCIAL_LISTING')
      .gte('created_at', twoDaysAgoC).order('created_at', { ascending: false }).limit(20);

    if ((postsToComment || []).length > 0) {
      // Fetch existing comments for de-duplication and bot-level cooldown.
      const postIdsC = (postsToComment || []).map(p => p.id);
      const { data: existingComments } = await client.from('comments')
        .select('post_id,user_id,content').in('post_id', postIdsC);

      const authorIds = [...new Set((postsToComment || []).map(p => p.user_id).filter(Boolean))];
      const { data: postAuthors } = authorIds.length > 0
        ? await client.from('users').select('id,name,country_code').in('id', authorIds)
        : { data: [] };
      const postAuthorMap = new Map((postAuthors || []).map(u => [u.id, u]));

      const commentedSet = new Set(
        (existingComments || [])
          .filter(c => botIdSet.has(c.user_id))
          .map(c => `${c.user_id}_${c.post_id}`)
      );
      const normalizeCommentSignature = (v) => normalizeText(String(v || '').replace(/\s+/g, ' '));
      const usedCommentsByPost = new Map();
      for (const ec of (existingComments || [])) {
        const signature = normalizeCommentSignature(ec.content);
        if (!signature) continue;
        if (!usedCommentsByPost.has(ec.post_id)) usedCommentsByPost.set(ec.post_id, new Set());
        usedCommentsByPost.get(ec.post_id).add(signature);
      }

      const commentRows = [];
      for (const bot of bots) {
        // Each bot comments on at most 1 post per tick
        for (const post of (postsToComment || [])) {
          if (post.user_id === bot.id) continue; // skip own posts
          const key = `${bot.id}_${post.id}`;
          if (commentedSet.has(key)) continue;
          if (Math.random() > 0.4) continue; // 40% chance to comment

          const botLocale = botAutomation.mapCountryCodeToLocale(
            bot.country_code || eco.country_code || 'EN'
          );
          const postAuthor = postAuthorMap.get(post.user_id);
          const posterName = postAuthor?.name ? String(postAuthor.name).split(' ')[0] : '';
          const postLocale = botAutomation.mapCountryCodeToLocale(
            postAuthor?.country_code || eco.country_code || 'EN'
          );
          // Hybrid language policy: mostly post language, occasionally bot's own language.
          const commentLocale = Math.random() < 0.82 ? postLocale : botLocale;

          const sportForComment = post.sport_id
            ? (validSports.find(s => s.id === post.sport_id) || null)
            : null;
          const commentSportName = sportForComment
            ? (botAutomation.translateSportName
                ? botAutomation.translateSportName(sportForComment.id, commentLocale, sportForComment.name)
                : sportForComment.name)
            : null;

          const usedForPost = usedCommentsByPost.get(post.id) || new Set();
          if (!usedCommentsByPost.has(post.id)) usedCommentsByPost.set(post.id, usedForPost);

          let content = '';
          let pickedSignature = '';
          // Prevent clone comments on the same post by trying multiple variants.
          for (let attempt = 0; attempt < 12; attempt++) {
            const candidate = botAutomation.generateBotComment({
              locale: commentLocale,
              sportName: commentSportName,
              posterName,
              botId: bot.id,
              postId: post.id,
              attempt,
            });
            const signature = normalizeCommentSignature(candidate);
            if (!signature || usedForPost.has(signature)) continue;
            content = candidate;
            pickedSignature = signature;
            break;
          }

          if (!content) continue;

          commentRows.push({
            id: uuid(), post_id: post.id, user_id: bot.id,
            parent_id: null, content,
          });
          if (pickedSignature) usedForPost.add(pickedSignature);
          commentedSet.add(key);
          break; // max 1 comment per bot per tick
        }
      }
      if (commentRows.length > 0) {
        try {
          await db.insertMany('comments', commentRows);
          stats.newComments += commentRows.length;
        } catch (cErr) {
          for (const cr of commentRows) {
            try { await db.insert('comments', cr); stats.newComments++; } catch { /* skip */ }
          }
        }
      }
    }
  }

  // Update ecosystem stats
  await db.update('bot_ecosystems', eco.id, {
    total_matches: (eco.total_matches || 0) + stats.newMatches,
    total_listings: (eco.total_listings || 0) + stats.newListings,
    last_tick_at: new Date().toISOString(),
  });

  return stats;
}

// â”€â”€ Admin Stats (Supabase-backed â€” replaces broken in-memory admin.js) â”€â”€â”€â”€â”€â”€
const adminStatsRouter = express.Router();
adminStatsRouter.use(authMiddleware);
adminStatsRouter.use(async (req, res, next) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Yetkisiz: Admin deÄŸilsiniz.' });
  next();
});

adminStatsRouter.get('/stats', async (_req, res) => {
  try {
    const [totalUsers, totalBots, bannedUsers, totalListings, activeListings,
           totalMatches, totalPosts, totalReports] = await Promise.all([
      db.count('users', { is_bot: false }),
      db.count('users', { is_bot: true }),
      db.count('users', { is_banned: true }),
      db.count('listings'),
      db.count('listings', { status: 'ACTIVE' }),
      db.count('matches'),
      db.count('posts'),
      db.count('reports').catch(() => 0),
    ]);
    res.json({
      totalUsers, totalBots, bannedUsers,
      totalListings, activeListings,
      totalMatches, totalPosts, totalReports,
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 20, search: q } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let users;
    if (q) {
      users = await db.search('users', 'name', q, { limit: parseInt(limit) });
    } else {
      users = await db.query('users', { order: 'created_at', ascending: false, limit: parseInt(limit), offset });
    }
    const total = await db.count('users');
    res.json({ data: users.map(u => safeUser(u)), total, page: parseInt(page), limit: parseInt(limit) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.patch('/users/:id/ban', async (req, res) => {
  try {
    const updated = await db.update('users', req.params.id, { is_banned: true });
    res.json({ data: safeUser(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.patch('/users/:id/unban', async (req, res) => {
  try {
    const updated = await db.update('users', req.params.id, { is_banned: false });
    res.json({ data: safeUser(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.get('/reports', async (_req, res) => {
  try {
    const reports = await db.query('reports', { order: 'created_at', ascending: false, limit: 50 });
    res.json({ data: reports.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: PATCH /users/:id (update user) â”€â”€
adminStatsRouter.patch('/users/:id', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const updates = {};
    if (body.isBanned !== undefined) updates.is_banned = body.isBanned;
    if (body.isAdmin !== undefined) updates.is_admin = body.isAdmin;
    if (body.name !== undefined) updates.name = body.name;
    if (body.averageRating !== undefined) updates.average_rating = Number(body.averageRating);
    if (body.ratingCount !== undefined) updates.rating_count = Number(body.ratingCount);
    const updated = await db.update('users', req.params.id, updates);
    res.json({ data: safeUser(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: DELETE /users/:id â”€â”€
adminStatsRouter.delete('/users/:id', async (req, res) => {
  try {
    await db.remove('users', req.params.id);
    res.json({ message: 'KullanÄ±cÄ± silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: PATCH /reports/:id (resolve report) â”€â”€
adminStatsRouter.patch('/reports/:id', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const action = (body.action || body.status || 'RESOLVED').toUpperCase();
    const report = await db.findById('reports', req.params.id);
    if (!report) return res.status(404).json({ message: 'Rapor bulunamadÄ±.' });

    // Ban user if action is BAN
    if (action === 'BAN' && report.target_id) {
      await db.update('users', report.target_id, { is_banned: true, banned_at: new Date().toISOString(), banned_by: req.userId });
    }
    // Unban user if action is UNBAN
    if (action === 'UNBAN' && report.target_id) {
      await db.update('users', report.target_id, { is_banned: false, banned_at: null, banned_by: null });
    }

    const updated = await db.update('reports', req.params.id, {
      status: action === 'BAN' ? 'RESOLVED_BAN' : action === 'UNBAN' ? 'RESOLVED_UNBAN' : 'RESOLVED',
      resolved_by: req.userId,
    });
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: GET /posts (list all posts) â”€â”€
adminStatsRouter.get('/posts', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const posts = await db.query('posts', { order: 'created_at', ascending: false, limit: parseInt(limit), offset });
    const total = await db.count('posts');
    res.json({ data: posts.map(toCamel), total, page: parseInt(page), limit: parseInt(limit) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: DELETE /posts/:id â”€â”€
adminStatsRouter.delete('/posts/:id', async (req, res) => {
  try {
    await db.remove('posts', req.params.id);
    res.json({ message: 'GÃ¶nderi silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: GET /listings (list all listings) â”€â”€
adminStatsRouter.get('/listings', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const listings = await db.query('listings', { order: 'created_at', ascending: false, limit: parseInt(limit), offset });
    const total = await db.count('listings');
    res.json({ data: listings.map(toCamel), total, page: parseInt(page), limit: parseInt(limit) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: DELETE /listings/bulk â”€â”€
adminStatsRouter.delete('/listings/bulk', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const ids = body.ids || [];
    for (const id of ids) await db.remove('listings', id);
    res.json({ message: `${ids.length} ilan silindi.` });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: DELETE /listings/:id (individual listing delete) â”€â”€
adminStatsRouter.delete('/listings/:id', async (req, res) => {
  try {
    await db.remove('listings', req.params.id);
    res.json({ message: 'Ä°lan silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: Bots CRUD â”€â”€
adminStatsRouter.get('/bots', async (_req, res) => {
  try {
    const bots = await db.query('users', { filter: { is_bot: true }, order: 'created_at', ascending: false, limit: 100 });
    res.json({ data: bots.map(b => safeUser(b)) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.post('/bots', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const bot = await db.insert('users', {
      id: 'bot_' + uuid(), name: body.name || 'Bot', email: 'bot_' + Date.now() + '@bot.local',
      password_hash: 'BOT', is_bot: true, is_admin: false, is_banned: false,
      avatar_url: body.avatarUrl || null, bio: body.bio || null,
      city_name: body.cityName || null, country_name: body.countryName || null,
    });
    res.status(201).json({ data: safeUser(bot) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.patch('/bots/:id', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const updates = {};
    if (body.name !== undefined) updates.name = body.name;
    if (body.avatarUrl !== undefined) updates.avatar_url = body.avatarUrl;
    if (body.bio !== undefined) updates.bio = body.bio;
    const updated = await db.update('users', req.params.id, updates);
    res.json({ data: safeUser(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/bots/:id', async (req, res) => {
  try {
    await db.remove('users', req.params.id);
    res.json({ message: 'Bot silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: Countries/Cities/Districts â”€â”€
adminStatsRouter.get('/countries', async (_req, res) => {
  try {
    const cities = await db.query('cities', { limit: 100 });
    // Group by a pseudo-country (Turkey)
    res.json({ data: [{ id: 'TR', name: 'TÃ¼rkiye', cities: cities.map(toCamel) }] });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.post('/countries/:id/cities', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const city = await db.insert('cities', { id: 'c' + Date.now(), name: body.name });
    res.status(201).json({ data: toCamel(city) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.post('/countries/:id/cities/:cityId/districts', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const district = await db.insert('districts', { id: 'd' + Date.now(), name: body.name, city_id: req.params.cityId });
    res.status(201).json({ data: toCamel(district) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: Bot Tasks â”€â”€
adminStatsRouter.get('/bot-tasks', async (_req, res) => {
  try {
    const tasks = await db.query('bot_tasks', { order: 'created_at', ascending: false, limit: 50 }).catch(() => []);
    res.json({ data: tasks.map(toCamel) });
  } catch (e) { res.json({ data: [] }); }
});

adminStatsRouter.post('/bot-tasks/:id/execute', async (req, res) => {
  try {
    const updated = await db.update('bot_tasks', req.params.id, { status: 'EXECUTED' }).catch(() => null);
    res.json({ data: updated ? toCamel(updated) : null, message: 'GÃ¶rev yÃ¼rÃ¼tÃ¼ldÃ¼.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/bot-tasks', async (_req, res) => {
  try {
    // Bulk delete all completed bot tasks
    const tasks = await db.query('bot_tasks', { filter: { status: 'EXECUTED' }, limit: 200 }).catch(() => []);
    for (const t of tasks) await db.remove('bot_tasks', t.id).catch(() => {});
    res.json({ message: `${tasks.length} gÃ¶rev silindi.` });
  } catch (e) { res.json({ message: 'Temizlendi.' }); }
});

// â”€â”€ Admin: Challenges â”€â”€
adminStatsRouter.get('/challenges', async (_req, res) => {
  try {
    const challenges = await db.query('challenges', { order: 'created_at', ascending: false, limit: 50 });
    res.json({ data: challenges.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/challenges/:id', async (req, res) => {
  try {
    await db.remove('challenges', req.params.id);
    res.json({ message: 'Meydan okuma silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// â”€â”€ Admin: Matches â”€â”€
adminStatsRouter.get('/matches', async (_req, res) => {
  try {
    const matches = await db.query('matches', { order: 'created_at', ascending: false, limit: 50 });
    res.json({ data: matches.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/matches/:id', async (req, res) => {
  try {
    await db.remove('matches', req.params.id);
    res.json({ message: 'EÅŸleÅŸme silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// Mount Supabase-backed admin routes BEFORE the legacy in-memory admin.js
app.use('/api/admin/ecosystems', ecosystemRouter);
app.use('/api/admin', adminStatsRouter);

// Legacy admin routes (in-memory store â€” only works in Docker/dev)
try {
  const adminRouter = require('../routes/admin');
  app.use('/api/admin', authMiddleware, adminRouter);
} catch { /* admin routes not available */ }

// â”€â”€ Stress Monitor (auth required) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/stress-monitor', authMiddleware, async (req, res) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Admin only.' });
  const mem = process.memoryUsage();
  res.json({
    memory: {
      rss: `${(mem.rss / 1024 / 1024).toFixed(1)}MB`,
      heapUsed: `${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB`,
    },
    env: 'vercel', database: 'supabase',
    timestamp: new Date().toISOString(),
  });
});

// â”€â”€ DB Migration (admin-only, idempotent) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/admin/migrate', authMiddleware, async (req, res) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Admin only.' });

  const client = db.raw();
  const results = [];

  // 1. bot_ecosystems table
  try {
    const { error: checkErr } = await client.from('bot_ecosystems').select('id').limit(1);
    if (checkErr && checkErr.message.includes('could not find')) {
      // Table doesn't exist â€” create via raw SQL through a temp function
      results.push({ table: 'bot_ecosystems', status: 'NEEDS_MANUAL_CREATE', note: 'Run SQL in Supabase Dashboard' });
    } else {
      results.push({ table: 'bot_ecosystems', status: 'EXISTS' });
    }
  } catch (e) { results.push({ table: 'bot_ecosystems', status: 'ERROR', error: e.message }); }

  // 2. password_reset_tokens table
  try {
    const { error: checkErr } = await client.from('password_reset_tokens').select('id').limit(1);
    if (checkErr && checkErr.message.includes('could not find')) {
      results.push({ table: 'password_reset_tokens', status: 'NEEDS_MANUAL_CREATE', note: 'Run SQL in Supabase Dashboard' });
    } else {
      results.push({ table: 'password_reset_tokens', status: 'EXISTS' });
    }
  } catch (e) { results.push({ table: 'password_reset_tokens', status: 'ERROR', error: e.message }); }

  // 3. push_tokens table
  try {
    const { error: checkErr } = await client.from('push_tokens').select('id').limit(1);
    if (checkErr && checkErr.message.includes('could not find')) {
      results.push({ table: 'push_tokens', status: 'NEEDS_MANUAL_CREATE', note: 'Run SQL in Supabase Dashboard' });
    } else {
      results.push({ table: 'push_tokens', status: 'EXISTS' });
    }
  } catch (e) { results.push({ table: 'push_tokens', status: 'ERROR', error: e.message }); }

  // 4. auth_audit_logs table
  try {
    const { error: checkErr } = await client.from('auth_audit_logs').select('id').limit(1);
    if (checkErr && checkErr.message.includes('could not find')) {
      results.push({ table: 'auth_audit_logs', status: 'NEEDS_MANUAL_CREATE', note: 'Run SQL in Supabase Dashboard' });
    } else {
      results.push({ table: 'auth_audit_logs', status: 'EXISTS' });
    }
  } catch (e) { results.push({ table: 'auth_audit_logs', status: 'ERROR', error: e.message }); }

  res.json({ results, sql: `
-- Run this SQL in Supabase Dashboard > SQL Editor:

CREATE TABLE IF NOT EXISTS bot_ecosystems (
  id TEXT PRIMARY KEY,
  group_name TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'CITY',
  country_code TEXT DEFAULT 'TR',
  city_id TEXT,
  city_name TEXT,
  sport_ids TEXT[] DEFAULT '{}',
  listing_type TEXT DEFAULT 'BOTH',
  bot_count INTEGER DEFAULT 10,
  active_bot_count INTEGER DEFAULT 0,
  target_listings_per_day INTEGER DEFAULT 5,
  is_active BOOLEAN DEFAULT true,
  tick_count INTEGER DEFAULT 0,
  last_tick_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS push_tokens (
  id TEXT PRIMARY KEY DEFAULT ('pt_' || uuid_generate_v4()::TEXT),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'android',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, token)
);

CREATE TABLE IF NOT EXISTS auth_audit_logs (
  id TEXT PRIMARY KEY DEFAULT ('audit_' || uuid_generate_v4()::TEXT),
  event_type TEXT NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  email TEXT,
  ip_address TEXT,
  user_agent TEXT,
  success BOOLEAN DEFAULT true,
  reason TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_push_tokens_user_id ON push_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_push_tokens_active ON push_tokens(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_created_at ON auth_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_event_type ON auth_audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_email ON auth_audit_logs(email);
CREATE INDEX IF NOT EXISTS idx_listings_expires_at ON listings(expires_at) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_bot_ecosystems_active ON bot_ecosystems(is_active) WHERE is_active = true;
  ` });
});

// â”€â”€ 404 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use((req, res) => res.status(404).json({ message: `Endpoint bulunamadÄ±: ${req.method} ${req.path}` }));

module.exports = app;

