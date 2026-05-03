'use strict';
/**
 * Sports Partner API — Production Server (Supabase-backed)
 *
 * Vercel Serverless Function entry point.
 * ALL routes use Supabase PostgreSQL instead of in-memory store.
 * WebSocket NOT supported on Vercel — HTTP-only.
 */

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const bcrypt     = require('bcryptjs');
const { v4: uuid } = require('uuid');
const compression = require('compression');

// ── Supabase ────────────────────────────────────────────────────────────────
const db = require('../db/supabase');
const { toCamel, toSnake, toUserResponse, fromUserBody, parsePagination } = require('../db/helpers');
const { generateTokens, verifyRefreshToken, authMiddleware } = require('../middleware/auth');

let contentFilterFn;
try { contentFilterFn = require('../middleware/content-filter').contentFilter; } catch { contentFilterFn = null; }
const contentFilter = contentFilterFn || ((..._f) => (_req, _res, next) => next());

const app = express();

// ── Middleware ───────────────────────────────────────────────────────────────
// compression removed — Vercel CDN handles gzip/brotli automatically
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: false,  // CORP: same-origin Flutter web'i engelliyordu
  crossOriginOpenerPolicy: false,    // COOP: same-origin Flutter web'i engelliyordu
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 'Authorization',
    'X-API-Version', 'X-Client-Type',  // Flutter custom headers
  ],
  exposedHeaders: ['Content-Length'],
  optionsSuccessStatus: 204,
}));
// OPTIONS preflight isteklerini hemen yanıtla (helmet/cors önce ele alır)
app.options('*', cors());
app.use(express.json({ limit: '500kb' }));

// ── Rate Limiting (in-memory, per-instance) ─────────────────────────────────
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
// setInterval removed — serverless functions don't persist between invocations
// Rate buckets auto-expire via the check in the middleware above

// ── Brute Force Protection ──────────────────────────────────────────────────
const loginAttempts = new Map();
const LOGIN_MAX = 5;
const LOGIN_WINDOW = 15 * 60 * 1000;

// ── Helpers ─────────────────────────────────────────────────────────────────
function sanitize(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const r = {};
  for (const [k, v] of Object.entries(obj))
    r[k] = typeof v === 'string' ? v.replace(/[<>]/g, '') : v;
  return r;
}

const SOCIAL_PLATFORMS = [
  'instagram','tiktok','facebook','twitter','youtube','linkedin',
  'discord','twitch','snapchat','telegram','whatsapp','vk','litmatch'
];

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

function buildLegacyPrivacyPatch(input = {}) {
  return {
    profile_visibility: modernVisibilityToLegacy(input.profileVisibility, 'profile'),
    show_online_status: input.showOnlineStatus !== false,
    show_sports: input.showSports !== false,
    show_location: input.showLocation !== false,
    show_social_links: normalizeVisibility(input.socialLinksVisibility, 'EVERYONE') !== 'NOBODY',
    allow_messages_from: modernVisibilityToLegacy(input.whoCanMessage || input.allowMessages, 'generic'),
    updated_at: new Date().toISOString(),
  };
}

const privacyDefaults = () => normalizePrivacy({});

async function canViewerSee(viewerId, ownerId, visibility) {
  const rule = normalizeVisibility(visibility, 'EVERYONE');
  if (viewerId && ownerId && viewerId === ownerId) return true;
  if (rule === 'NOBODY') return false;
  if (rule === 'EVERYONE') return true;
  // FOLLOWERS — check if viewer follows owner
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

  // Legacy schema fallback: map flat columns into modern privacy shape.
  return normalizePrivacy({
    profileVisibility: legacyVisibilityToModern(row.profile_visibility, 'EVERYONE'),
    showOnlineStatus: row.show_online_status !== false,
    showLocation: row.show_location !== false,
    showSports: row.show_sports !== false,
    showOnLeaderboard: row.show_statistics !== false,
    isPrivateProfile: legacyVisibilityToModern(row.profile_visibility, 'EVERYONE') === 'NOBODY',
    socialLinksVisibility: row.show_social_links === false ? 'NOBODY' : 'EVERYONE',
    whoCanMessage: legacyVisibilityToModern(row.allow_messages_from, 'EVERYONE'),
    allowMessages: legacyVisibilityToModern(row.allow_messages_from, 'EVERYONE'),
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
  await db.insert('notifications', notif).catch(e => console.error('notif insert err:', e.message));
  return toCamel(notif);
}

async function userById(id) { return id ? await db.findById('users', id) : null; }
async function listingById(id) { return id ? await db.findById('listings', id) : null; }

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
        title: 'Maç oynandı mı?',
        body: `${recipient.sender?.name || 'Rakibin'} ile planlanan maç zamanı geçti. Oynandıysa maçı onaylayın.`,
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

// ══════════════════════════════════════════════════════════════════════════════
//  HEALTH
// ══════════════════════════════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({
  status: 'ok', env: 'vercel', database: 'supabase', timestamp: new Date().toISOString()
}));
app.get('/', (_req, res) => res.json({
  name: 'Sports Partner API', version: '2.0.0', status: 'running', database: 'supabase'
}));

// ══════════════════════════════════════════════════════════════════════════════
//  GEO (public)
// ══════════════════════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════════
const authRouter = express.Router();

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email ve şifre gerekli.' });

    // Brute force protection
    const ip = req.headers['x-forwarded-for'] || req.ip;
    const now = Date.now();
    let att = loginAttempts.get(ip);
    if (!att || now - att.start > LOGIN_WINDOW) {
      att = { start: now, count: 0 };
      loginAttempts.set(ip, att);
    }
    if (att.count >= LOGIN_MAX) {
      return res.status(429).json({ message: 'Çok fazla başarısız giriş. 15 dk bekleyin.' });
    }

    const user = await db.findOne('users', { email: email.toLowerCase() });
    if (!user) { att.count++; return res.status(401).json({ message: 'Kullanıcı bulunamadı.' }); }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) { att.count++; return res.status(401).json({ message: 'Hatalı şifre.' }); }

    loginAttempts.delete(ip);
    const tokens = generateTokens(user.id);
    await db.insert('refresh_tokens', {
      token: tokens.refreshToken, user_id: user.id,
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    }).catch(() => {});

    res.json({ ...tokens, user: safeUser(user) });
  } catch (e) { console.error('login error:', e); res.status(500).json({ message: 'Sunucu hatası.' }); }
});

authRouter.post('/register', contentFilter('name'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Ad, email ve şifre gerekli.' });
    if (password.length < 6) return res.status(400).json({ message: 'Şifre en az 6 karakter olmalı.' });

    const existing = await db.findOne('users', { email: email.toLowerCase() });
    if (existing) return res.status(409).json({ message: 'Bu email zaten kayıtlı.' });

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
  } catch (e) { console.error('register error:', e); res.status(500).json({ message: 'Sunucu hatası.' }); }
});

authRouter.post('/token/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: 'Geçersiz refresh token.' });

    const stored = await db.findOne('refresh_tokens', { token: refreshToken });
    if (!stored) return res.status(401).json({ message: 'Geçersiz refresh token.' });

    const payload = verifyRefreshToken(refreshToken);
    await db.removeWhere('refresh_tokens', { token: refreshToken }).catch(() => {});

    const tokens = generateTokens(payload.sub);
    await db.insert('refresh_tokens', {
      token: tokens.refreshToken, user_id: payload.sub,
      expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
    }).catch(() => {});

    res.json(tokens);
  } catch { res.status(401).json({ message: 'Refresh token süresi dolmuş.' }); }
});

authRouter.post('/logout', authMiddleware, async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) await db.removeWhere('refresh_tokens', { token: refreshToken }).catch(() => {});
  res.json({ message: 'Çıkış yapıldı.' });
});

// Password reset tokens stored in Supabase DB (NOT in-memory — serverless safe)
// Table: password_reset_tokens (id, user_id, code, token, expires_at, created_at)

authRouter.post('/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  const user = email ? await db.findOne('users', { email }) : null;
  if (!user) return res.json({ message: 'Eğer hesap mevcutsa sıfırlama kodu gönderildi.' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const token = uuid();
  // Clean up old tokens for this user
  await db.removeWhere('password_reset_tokens', { user_id: user.id }).catch(() => {});
  await db.insert('password_reset_tokens', {
    id: uuid(), user_id: user.id, code, token,
    expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
  }).catch(() => {});
  // TODO: Send email with code via SendGrid/Resend when configured
  // For now, code is stored in DB but not sent — admin can look up in DB
  res.json({ message: 'Sıfırlama kodu gönderildi.' });
});

authRouter.post('/reset-password', async (req, res) => {
  const { token, code, newPassword } = req.body || {};
  const entry = token ? await db.findOne('password_reset_tokens', { token }) : null;
  if (!entry) return res.status(400).json({ message: 'Geçersiz veya süresi dolmuş token.' });
  if (entry.code !== code) return res.status(400).json({ message: 'Hatalı sıfırlama kodu.' });
  if (new Date(entry.expires_at) < new Date()) {
    await db.removeWhere('password_reset_tokens', { token }).catch(() => {});
    return res.status(400).json({ message: 'Kodun süresi dolmuş.' });
  }
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'Şifre en az 6 karakter olmalı.' });
  const hashed = await bcrypt.hash(newPassword, 10);
  await db.update('users', entry.user_id, { password: hashed });
  await db.removeWhere('password_reset_tokens', { token }).catch(() => {});
  res.json({ message: 'Şifre başarıyla sıfırlandı.' });
});

// Delete account — requires password confirmation
authRouter.delete('/delete-account', authMiddleware, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ message: 'Şifre gerekli.' });

    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Hatalı şifre.' });

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

    // Anonymize posts and comments (don't delete — preserve thread integrity)
    const userPosts = await db.query('posts', { filters: { user_id: req.userId } });
    for (const p of userPosts) {
      await db.update('posts', p.id, { user_id: null, content: '[Silinen kullanıcı]' }).catch(() => {});
    }
    const userComments = await db.query('comments', { filters: { user_id: req.userId } });
    for (const c of userComments) {
      await db.update('comments', c.id, { user_id: null, content: '[Silinen kullanıcı]' }).catch(() => {});
    }

    // Delete listings (cascade: matches, messages related will be orphaned but safe)
    const userListings = await db.query('listings', { filters: { user_id: req.userId } });
    for (const li of userListings) {
      await db.removeWhere('listings', { id: li.id }).catch(() => {});
    }

    // Finally delete user
    await db.removeWhere('users', { id: req.userId });

    res.json({ message: 'Hesap başarıyla silindi.' });
  } catch (e) {
    console.error('delete-account error:', e);
    res.status(500).json({ message: 'Hesap silme hatası.' });
  }
});

app.use('/api/auth', authRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  PROFILE
// ══════════════════════════════════════════════════════════════════════════════
const profileRouter = express.Router();
profileRouter.use(authMiddleware);

profileRouter.get('/', async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
    res.json({ data: { user: safeUser(user), myListings: [] } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

profileRouter.patch('/', contentFilter('name', 'bio', 'username'), async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

    const body = sanitize(req.body);

    // ── Block inappropriate social media links ──
    const socialFields = ['instagram','tiktok','facebook','twitter','youtube','linkedin','discord','twitch','snapchat','telegram','whatsapp','vk','litmatch'];
    const blockedDomains = ['pornhub','xvideos','xhamster','xnxx','redtube','youporn','brazzers','onlyfans','chaturbate','livejasmin','stripchat','cam4','bongacams','myfreecams','fansly','manyvids'];
    for (const f of socialFields) {
      if (body[f] && typeof body[f] === 'string') {
        const lower = body[f].toLowerCase();
        if (blockedDomains.some(d => lower.includes(d))) {
          return res.status(400).json({ message: 'Uygunsuz içerik bağlantısı eklenemez.' });
        }
      }
    }

    const changes = {};
    // cityId, districtId handled specially below — not in auto-map list
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

    // ── cityId / cityName handling ─────────────────────────────────────────
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

    // ── districtId / districtName handling ──────────────────────────────────
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

    // Special: sportIds → sports JSONB
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
          changes.sports = (selectedSports.length > 0 ? selectedSports : requestedSportIds.map(id => ({ id, name: id, icon: '🏅', category: null })))
            .map(s => ({ id: s.id, name: s.name, icon: s.icon, category: s.category }));
        } catch {
          changes.sports = requestedSportIds.map(id => ({ id, name: id, icon: '🏅', category: null }));
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
    res.status(500).json({ message: e.message || 'Profil güncellenemedi.' });
  }
});

app.use('/api/profile', profileRouter);

// ── Upload with Supabase Storage ─────────────────────────────────────────────
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

// ── Delete photo (avatar or cover) ───────────────────────────────────────────
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
    res.status(500).json({ message: 'Sunucu hatası.' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  LISTINGS
// ══════════════════════════════════════════════════════════════════════════════
const listingsRouter = express.Router();
listingsRouter.use(authMiddleware);

listingsRouter.get('/', async (req, res) => {
  try {
    const { sport, city, district, type, level, gender, userId, page = 1, pageSize = 20 } = req.query;
    const pg = Number(page);
    const ps = Math.min(50, Number(pageSize));
    const skip = (pg - 1) * ps;
    const nowIso = new Date().toISOString();

    const client = db.raw();
    let q = client.from('listings').select('*')
      .in('status', ['ACTIVE', 'MATCHED'])
      .gte('expires_at', nowIso)
      .order('created_at', { ascending: false });

    q = q.or(`date.is.null,date.gte.${nowIso}`);
    if (sport) q = q.or(`sport_id.eq.${sport},sport_name.eq.${sport}`);
    if (city)  q = q.or(`city_id.eq.${city},city_name.eq.${city}`);
    if (district) q = q.eq('district_id', district);
    if (type)  q = q.eq('type', type);
    if (level) q = q.eq('level', level);
    if (gender && gender !== 'ANY') q = q.or(`gender.eq.${gender},gender.eq.ANY`);
    if (userId) q = q.eq('user_id', userId);
    q = q.range(skip, skip + ps - 1);

    const { data, error } = await q;
    if (error) return res.status(500).json({ message: error.message });

    res.json({
      success: true,
      data: (data || []).map(toCamel),
      pagination: { page: pg, hasNext: (data || []).length >= ps }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.get('/:id', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });

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

    const result = toCamel(listing);
    result.applicants = applicants;
    result.acceptedUsers = applicants.filter(a => a.status === 'ACCEPTED');
    result.pendingUsers = applicants.filter(a => a.status === 'PENDING');
    result.rejectedCount = applicants.filter(a => a.status === 'REJECTED').length;

    res.json(result);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.post('/', contentFilter('title', 'description'), async (req, res) => {
  try {
    const user = await userById(req.userId);
    const body = sanitize(req.body);
    if (!body.title || body.title.trim().length < 3)
      return res.status(400).json({ message: 'Başlık en az 3 karakter olmalı.' });
    if (!body.sportId)
      return res.status(400).json({ message: 'Spor dalı seçilmeli.' });

    // ── İlan tarih validasyonu: max 3 gün sonrası ──
    const MAX_LISTING_DAYS = 3;
    if (body.dateTime || body.date) {
      const listingDate = new Date(body.dateTime || body.date);
      if (isNaN(listingDate.getTime()))
        return res.status(400).json({ message: 'Geçersiz tarih formatı.' });
      const now = new Date();
      // Geçmiş tarih kontrolü (1 saat tolerans)
      if (listingDate.getTime() < now.getTime() - 3600000)
        return res.status(400).json({ message: 'Geçmiş bir tarih için ilan açılamaz.' });
      const maxDate = new Date(now.getTime() + MAX_LISTING_DAYS * 24 * 3600 * 1000);
      if (listingDate > maxDate)
        return res.status(400).json({ message: `İlan tarihi en fazla ${MAX_LISTING_DAYS} gün sonrası olabilir.` });
    }

    const sport = await db.findById('sports', body.sportId);
    // NOTE: city_id and district_id have FK constraints to cities/districts tables
    // Flutter sends numeric IDs from states.json (e.g. "2170") but DB has "c1" format
    // So we store null for IDs and rely on city_name/district_name for display

    // expires_at: tarih varsa tarih + 1 gün, yoksa 3 gün sonra
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
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
    if (listing.user_id === req.userId)
      return res.status(400).json({ message: 'Kendi ilanınıza başvuramazsınız.' });

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
      title: 'Yeni başvuru',
      body: `${me?.name || 'Birisi'} ilanınıza başvurdu.`,
      relatedId: listing.id, senderId: req.userId,
    });

    res.json({ interested: true, count: (listing.response_count || 0) + 1, responseId: interest.id });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.get('/:id/interests', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });

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
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
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
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
    if (listing.user_id !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });

    const interest = await db.findById('interests', req.params.responseId);
    if (!interest) return res.status(404).json({ message: 'Başvuru bulunamadı.' });
    if (interest.listing_id !== listing.id) {
      return res.status(400).json({ message: 'Başvuru bu ilana ait değil.' });
    }

    const { action } = req.body;
    if (action !== 'ACCEPTED' && action !== 'REJECTED')
      return res.status(400).json({ message: "action 'ACCEPTED' veya 'REJECTED' olmalı." });

    const currentStatus = String(interest.status || 'PENDING').toUpperCase();

    if (action === 'REJECTED') {
      if (currentStatus !== 'REJECTED') {
        await db.update('interests', interest.id, { status: action });
        await pushNotification({
          userId: interest.user_id, type: 'RESPONSE_REJECTED',
          title: 'Başvurunuz reddedildi',
          body: 'Başvurunuz reddedildi.',
          relatedId: listing.id, senderId: req.userId,
        });
      }
      return res.json({ data: { interest: toCamel({ ...interest, status: action }) } });
    }

    if (currentStatus !== 'PENDING') {
      return res.status(409).json({ message: 'Bu başvuru zaten işlendi.' });
    }

    const currentAccepted = listing.accepted_count || 0;
    const slotsNeeded = Math.max(1, (listing.max_participants || 2) - 1);
    if (listing.status === 'MATCHED' || currentAccepted >= slotsNeeded) {
      await db.update('interests', interest.id, { status: 'REJECTED' }).catch(() => {});
      await pushNotification({
        userId: interest.user_id,
        type: 'QUOTA_FULL',
        title: 'Kontenjan doldu',
        body: 'İlanın kontenjanı dolduğu için başvurunuz otomatik reddedildi.',
        relatedId: listing.id,
        senderId: req.userId,
      });
      return res.status(409).json({ message: 'İlan kontenjanı doldu.' });
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
            message: 'Bu tarih ve saatte mevcut bir eşleşme var. Lütfen farklı bir zaman seçin.',
          });
        }
      }
    }

    if (action === 'ACCEPTED') {
      await db.update('interests', interest.id, { status: action });
      const u1 = await userById(listing.user_id);
      const u2 = await userById(interest.user_id);
      const sport = listing.sport_id ? await db.findById('sports', listing.sport_id) : null;
      const isGroupListing = (listing.max_participants || 2) > 2;

      let match = null;
      if (!isGroupListing) {
        match = {
          id: 'match_' + uuid(), listing_id: listing.id, source: 'LISTING',
          user1_id: listing.user_id, user2_id: interest.user_id,
          status: 'SCHEDULED', u1_approved: false, u2_approved: false,
          scheduled_at: listing.date || null, completed_at: null,
        };
        await db.insert('matches', match);
      }

      // Update listing capacity
      const newAccepted = currentAccepted + 1;
      const isFull = newAccepted >= slotsNeeded;
      const updates = { accepted_count: newAccepted };
      let acceptedInterests = [];
      let groupParticipantIds = [];
      let groupParticipantNames = [];
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
          const { data: participantUsers } = await client.from('users').select('id,name')
            .in('id', uniqueParticipantIds);
          const participantMap = new Map((participantUsers || []).map(user => [user.id, user.name]));
          groupParticipantNames = uniqueParticipantIds
            .map(userId => participantMap.get(userId))
            .filter(Boolean);
          groupParticipantIds = uniqueParticipantIds;

          // PARTNER grup eşleşmesi: her kabul edilen katılımcı için
          // listing sahibiyle ayrı bir matches kaydı oluştur.
          // Schema değişikliği gerekmez; her katılımcı kendi matches tab'ında görür.
          const groupMatchRows = acceptedInterests
            .map(row => row.user_id)
            .filter(pid => pid && pid !== listing.user_id)
            .map(participantId => ({
              id: 'match_' + uuid(),
              listing_id: listing.id,
              source: 'LISTING',
              user1_id: listing.user_id,
              user2_id: participantId,
              status: 'SCHEDULED',
              u1_approved: false,
              u2_approved: false,
              scheduled_at: listing.date || null,
              completed_at: null,
            }));
          if (groupMatchRows.length > 0) {
            await db.insertMany('matches', groupMatchRows).catch(e =>
              console.error('Group match insert error:', e.message)
            );
          }
        }

        for (const pending of (remainingPending || [])) {
          await pushNotification({
            userId: pending.user_id,
            type: 'QUOTA_FULL',
            title: 'Kontenjan doldu',
            body: 'İlan kontenjanı dolduğu için başvurunuz otomatik reddedildi.',
            relatedId: listing.id,
            senderId: req.userId,
          });
        }
      }
      await db.update('listings', listing.id, updates);

      if (match) {
        await pushNotification({
          userId: interest.user_id, type: 'RESPONSE_ACCEPTED',
          title: 'Başvurunuz kabul edildi!',
          body: `${u1?.name || 'İlan sahibi'} başvurunuzu kabul etti.`,
          relatedId: match.id, senderId: req.userId,
        });
      } else if (isGroupListing && isFull) {
        const listingLink = `/listings/${listing.id}`;
        const notifiedIds = new Set();
        const participantLabel = formatNameList(groupParticipantNames);
        const sportLabel = sport?.name || listing.sport_name || 'spor etkinliği';

        for (const participantId of groupParticipantIds) {
          if (!participantId || notifiedIds.has(participantId)) continue;
          notifiedIds.add(participantId);
          await pushNotification({
            userId: participantId,
            type: 'NEW_MATCH',
            title: 'İlanın kotası tamamlandı',
            body: participantLabel
              ? `${participantLabel} ${sportLabel} için eşleştiler.`
              : `İlanın kontenjanı doldu. ${sportLabel} için grup eşleşmesi tamamlandı.`,
            relatedId: listing.id,
            link: listingLink,
            senderId: req.userId,
            senderName: u1?.name,
            senderAvatar: u1?.avatar_url,
          });
        }
      } else {
        await pushNotification({
          userId: interest.user_id,
          type: 'RESPONSE_ACCEPTED',
          title: 'Başvurunuz onaylandı',
          body: `${u1?.name || 'İlan sahibi'} başvurunuzu onayladı. Kontenjan dolunca grup eşleşmesi tamamlanacak.`,
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
      }
      return res.json({ data: response });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.delete('/:id', async (req, res) => {
  try {
    const listing = await listingById(req.params.id);
    if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
    if (listing.user_id !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });
    await db.removeWhere('interests', { listing_id: listing.id });
    await db.remove('listings', listing.id);
    res.json({ message: 'İlan silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

listingsRouter.delete('/:id/interest', async (req, res) => {
  try {
    await db.removeWhere('interests', { listing_id: req.params.id, user_id: req.userId });
    res.json({ message: 'Başvuru geri çekildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/listings', listingsRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  MATCHES
// ══════════════════════════════════════════════════════════════════════════════
const matchesRouter = express.Router();
matchesRouter.use(authMiddleware);

matchesRouter.get('/', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;

    const client = db.raw();
    const { data, count } = await client.from('matches').select('*', { count: 'exact' })
      .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    const matches = data || [];
    if (matches.length === 0) return res.json({ data: [], pagination: { page, hasNext: false, total: 0 } });

    // Batch: collect unique IDs
    const userIds = new Set();
    const listingIds = new Set();
    for (const m of matches) {
      userIds.add(m.user1_id); userIds.add(m.user2_id);
      if (m.listing_id) listingIds.add(m.listing_id);
    }

    // Parallel batch queries
    const [usersArr, listingsArr] = await Promise.all([
      userIds.size > 0 ? client.from('users').select('*').in('id', [...userIds]).then(r => r.data || []) : [],
      listingIds.size > 0 ? client.from('listings').select('*').in('id', [...listingIds]).then(r => r.data || []) : [],
    ]);

    const usersMap = new Map(usersArr.map(u => [u.id, u]));
    const listingsMap = new Map(listingsArr.map(l => [l.id, l]));

    // Batch sports from listings
    const sportIds = new Set(listingsArr.filter(l => l.sport_id).map(l => l.sport_id));
    const sportsArr = sportIds.size > 0
      ? (await client.from('sports').select('*').in('id', [...sportIds])).data || []
      : [];
    const sportsMap = new Map(sportsArr.map(s => [s.id, s]));

    const enriched = matches.map(m => {
      const u1 = usersMap.get(m.user1_id);
      const u2 = usersMap.get(m.user2_id);
      const listing = m.listing_id ? listingsMap.get(m.listing_id) : null;
      const sport = listing?.sport_id ? sportsMap.get(listing.sport_id) : null;
      return {
        ...toCamel(m),
        user1: safeUser(u1), user2: safeUser(u2),
        listing: listing ? { id: listing.id, type: listing.type, sport: sport ? toCamel(sport) : null } : null,
      };
    });
    res.json({ data: enriched, pagination: { page, hasNext: offset + limit < (count || 0), total: count || 0 } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.get('/:id', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    const u1 = await userById(m.user1_id);
    const u2 = await userById(m.user2_id);
    const listing = m.listing_id ? await listingById(m.listing_id) : null;
    const sport = listing?.sport_id ? await db.findById('sports', listing.sport_id) : null;
    res.json({
      data: {
        ...toCamel(m), user1: safeUser(u1), user2: safeUser(u2),
        listing: listing ? { id: listing.id, type: listing.type, sport: sport ? toCamel(sport) : null } : null,
      }
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/complete', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    const updated = await db.update('matches', m.id, { status: 'COMPLETED', completed_at: new Date().toISOString() });
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.patch('/:id/approve', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    if (m.status === 'COMPLETED' || m.status === 'CANCELLED') return res.json({ data: toCamel(m) });

    const changes = {};
    if (m.user1_id === req.userId) changes.u1_approved = true;
    else if (m.user2_id === req.userId) changes.u2_approved = true;
    else return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });

    const bothApproved =
      (m.user1_id === req.userId ? true : m.u1_approved) &&
      (m.user2_id === req.userId ? true : m.u2_approved);

    if (bothApproved) {
      changes.status = 'COMPLETED';
      changes.completed_at = new Date().toISOString();
      const u1 = await userById(m.user1_id);
      const u2 = await userById(m.user2_id);
      if (u1) await db.update('users', u1.id, {
        total_matches: (u1.total_matches || 0) + 1,
        total_points: (u1.total_points || 0) + 10,
      });
      if (u2) await db.update('users', u2.id, {
        total_matches: (u2.total_matches || 0) + 1,
        total_points: (u2.total_points || 0) + 10,
      });
      if (u1) await pushNotification({
        userId: u1.id, type: 'MATCH_COMPLETED',
        title: '⭐ Değerlendirme Zamanı!',
        body: `${u2?.name || 'Rakibin'} maçı oynadığını onayladı`,
        relatedId: m.id, senderName: u2?.name,
      });
      if (u2) await pushNotification({
        userId: u2.id, type: 'MATCH_COMPLETED',
        title: '⭐ Değerlendirme Zamanı!',
        body: `${u1?.name || 'Rakibin'} maçı oynadığını onayladı`,
        relatedId: m.id, senderName: u1?.name,
      });
    } else {
      const awaitingId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
      const approver = await userById(req.userId);
      await pushNotification({
        userId: awaitingId, type: 'MATCH_STATUS_CHANGED',
        title: '⚽ Maçı Oynadınız mı?',
        body: `${approver?.name || 'Rakibin'} maçı oynadığını onayladı`,
        relatedId: m.id, senderId: req.userId,
        senderName: approver?.name, senderAvatar: approver?.avatar_url,
      });
    }

    const updated = await db.update('matches', m.id, changes);
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/otp/request', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    if (req.userId !== m.user1_id && req.userId !== m.user2_id)
      return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await db.insert('otps', {
      id: uuid(), match_id: m.id, requester_id: req.userId,
      code, expires_at: expiresAt, used_at: null,
    });

    const otherId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    const requester = await userById(req.userId);
    await pushNotification({
      userId: otherId, type: 'MATCH_OTP_REQUESTED',
      title: '🔐 Doğrulama Kodu İstendi',
      body: `${requester?.name || 'Rakibin'} maç doğrulaması için kod istedi.`,
      relatedId: m.id, senderId: req.userId,
    });

    res.json({ message: 'Doğrulama kodu oluşturuldu.', devCode: code, expiresAt });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/otp/verify', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: 'Doğrulama kodu gerekli.' });

    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });

    const client = db.raw();
    const { data: otps } = await client.from('otps').select('*')
      .eq('match_id', m.id).eq('code', String(code))
      .is('used_at', null).gt('expires_at', new Date().toISOString())
      .limit(1);

    const otp = otps?.[0];
    if (!otp) return res.status(400).json({ message: 'Geçersiz veya süresi dolmuş doğrulama kodu.' });

    await db.update('otps', otp.id, { used_at: new Date().toISOString() });
    const newTrust = Math.min(100, (m.trust_score || 0) + 40);
    await db.update('matches', m.id, { trust_score: newTrust });
    res.json({ message: 'Maç doğrulandı.', trustScore: newTrust });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

matchesRouter.post('/:id/noshow', async (req, res) => {
  try {
    const m = await db.findById('matches', req.params.id);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    if (req.userId !== m.user1_id && req.userId !== m.user2_id)
      return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });

    const already = await db.findOne('noshows', { match_id: m.id, reporter_id: req.userId });
    if (already) return res.status(409).json({ message: 'Bu maç için zaten rapor ettiniz.' });

    const reportedId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    await db.insert('noshows', { id: uuid(), match_id: m.id, reporter_id: req.userId, reported_id: reportedId });

    const reported = await userById(reportedId);
    if (reported) await db.update('users', reportedId, { no_show_count: (reported.no_show_count || 0) + 1 });

    const reporter = await userById(req.userId);
    await pushNotification({
      userId: reportedId, type: 'NO_SHOW_WARNING',
      title: '⚠️ Gelmedi Raporu',
      body: `${reporter?.name || 'Rakibin'} maça gelmediğinizi bildirdi.`,
      relatedId: m.id, senderId: req.userId,
    });
    res.json({ message: 'Rapor kaydedildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/matches', matchesRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  CONVERSATIONS & MESSAGES
// ══════════════════════════════════════════════════════════════════════════════
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
    if (!conv) return res.status(404).json({ message: 'Konuşma bulunamadı.' });
    if (conv.user1_id !== req.userId && conv.user2_id !== req.userId) {
      return res.status(403).json({ message: 'Bu konuşmaya erişiminiz yok.' });
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
      return res.status(400).json({ message: 'Mesaj içeriği gerekli.' });
    const conv = await db.findById('conversations', req.params.id);
    if (!conv) return res.status(404).json({ message: 'Konuşma bulunamadı.' });
    if (conv.user1_id !== req.userId && conv.user2_id !== req.userId) {
      return res.status(403).json({ message: 'Bu konuşmaya erişiminiz yok.' });
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
      body: `${sender?.name || 'Birisi'} size mesaj gönderdi.`,
      relatedId: req.params.id,
      senderId: req.userId,
      senderName: sender?.name,
      senderAvatar: sender?.avatar_url,
    });

    res.status(201).json({ data: toCamel(msg) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/conversations', convsRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  USERS (profile, follow, block)
// ══════════════════════════════════════════════════════════════════════════════
const usersRouter = express.Router();
usersRouter.use(authMiddleware);

usersRouter.get('/me/referral', async (req, res) => {
  try {
    const user = await userById(req.userId);
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
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
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

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
    if (!target) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

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
      title: status === 'pending' ? 'Yeni takip isteği' : 'Seni takip etmeye başladı',
      body: `${me?.name || 'Birisi'} ${status === 'pending' ? 'seni takip etmek istiyor' : 'seni takip etmeye başladı'}.`,
      relatedId: req.userId, senderId: req.userId,
      senderName: me?.name, senderAvatar: me?.avatar_url,
    });
    res.json({ following: status === 'accepted', pending: status === 'pending' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.get('/:id/followers', async (req, res) => {
  try {
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
    if (!f) return res.status(404).json({ message: 'Takipçi bulunamadı.' });
    await db.remove('follows', f.id);
    const me = await userById(req.userId);
    const follower = await userById(req.params.id);
    if (me) await db.update('users', req.userId, { follower_count: Math.max(0, (me.follower_count || 1) - 1) });
    if (follower) await db.update('users', req.params.id, { following_count: Math.max(0, (follower.following_count || 1) - 1) });
    res.json({ message: 'Takipçi kaldırıldı.' });
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
    res.json({ message: 'Kullanıcı engellendi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.delete('/:id/block', async (req, res) => {
  try {
    await db.removeWhere('blocked_users', { blocker_id: req.userId, blocked_id: req.params.id });
    res.json({ message: 'Engel kaldırıldı.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

usersRouter.post('/:id/report', async (req, res) => {
  res.json({ message: 'Şikayet alındı.' });
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

// ══════════════════════════════════════════════════════════════════════════════
//  FOLLOWS (requests)
// ══════════════════════════════════════════════════════════════════════════════
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
    if (!follow) return res.status(404).json({ message: 'İstek bulunamadı.' });
    if (follow.following_id !== req.userId) return res.status(403).json({ message: 'Bu isteği yanıtlama yetkiniz yok.' });

    if (action === 'ACCEPTED') {
      await db.update('follows', follow.id, { status: 'accepted' });
      const target = await userById(follow.following_id);
      const follower = await userById(follow.follower_id);
      if (target) await db.update('users', target.id, { follower_count: (target.follower_count || 0) + 1 });
      if (follower) await db.update('users', follower.id, { following_count: (follower.following_count || 0) + 1 });
      await pushNotification({
        userId: follow.follower_id, type: 'FOLLOW_ACCEPTED',
        title: 'Takip isteğin kabul edildi',
        body: `${target?.name || 'Birisi'} takip isteğini kabul etti.`,
        relatedId: req.userId,
      });
      res.json({ message: 'İstek kabul edildi.', follow: toCamel({ ...follow, status: 'accepted' }) });
    } else {
      await db.remove('follows', follow.id);
      res.json({ message: 'İstek reddedildi.' });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// Respond to follow request by follower user ID (used from notification inline action)
followsRouter.post('/respond-by-user', async (req, res) => {
  try {
    const { followerId, action } = req.body;
    if (!followerId) return res.status(400).json({ message: 'followerId gerekli.' });
    const pending = await db.query('follows', { filters: { follower_id: followerId, following_id: req.userId, status: 'pending' } });
    if (!pending.length) return res.status(404).json({ message: 'Bekleyen istek bulunamadı.' });
    const follow = pending[0];
    if (action === 'ACCEPTED') {
      await db.update('follows', follow.id, { status: 'accepted' });
      const target = await userById(req.userId);
      const follower = await userById(followerId);
      if (target) await db.update('users', target.id, { follower_count: (target.follower_count || 0) + 1 });
      if (follower) await db.update('users', follower.id, { following_count: (follower.following_count || 0) + 1 });
      await pushNotification({
        userId: followerId, type: 'FOLLOW_ACCEPTED',
        title: 'Takip isteğin kabul edildi',
        body: `${target?.name || 'Birisi'} takip isteğini kabul etti.`,
        relatedId: req.userId, senderId: req.userId,
        senderName: target?.name, senderAvatar: target?.avatar_url,
      });
      res.json({ message: 'İstek kabul edildi.' });
    } else {
      await db.remove('follows', follow.id);
      res.json({ message: 'İstek reddedildi.' });
    }
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/follows', followsRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  CHALLENGES
// ══════════════════════════════════════════════════════════════════════════════
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
    if (!targetId || !sportId) return res.status(400).json({ message: 'Hedef kullanıcı ve spor gerekli.' });
    if (targetId === req.userId) return res.status(400).json({ message: 'Kendinize teklif gönderemezsiniz.' });

    const target = await userById(targetId);
    if (!target) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

    const dup = await db.findOne('challenges', { sender_id: req.userId, target_id: targetId, sport_id: sportId, status: 'PENDING' });
    if (dup) return res.status(409).json({ message: 'Bu spor için zaten bekleyen bir teklifiniz var.' });

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
    await pushNotification({
      userId: targetId,
      type: 'DIRECT_CHALLENGE',
      title: `${challenge.challenge_type === 'RIVAL' ? '⚔️ Rakip' : '🤝 Partner'} Teklifi!`,
      body: `${me?.name || 'Birisi'} sana ${sport?.name || 'spor'} teklifi gönderdi.`,
      relatedId: challenge.id, link: '/challenges',
      senderId: req.userId, senderName: me?.name, senderAvatar: me?.avatar_url,
    });

    res.status(201).json({ data: await enrichChallenge(challenge) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

challengesRouter.patch('/:id', async (req, res) => {
  try {
    const c = await db.findById('challenges', req.params.id);
    if (!c) return res.status(404).json({ message: 'Teklif bulunamadı.' });
    if (c.target_id !== req.userId) return res.status(403).json({ message: 'Bu teklif size ait değil.' });
    if (c.status !== 'PENDING') return res.status(400).json({ message: 'Bu teklif zaten yanıtlandı.' });

    const action = String(req.body.action || '').toUpperCase();
    if (action !== 'ACCEPTED' && action !== 'REJECTED')
      return res.status(400).json({ message: 'Geçersiz işlem.' });

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

      await pushNotification({
        userId: c.sender_id, type: 'NEW_MATCH',
        title: '🎮 Eşleşme Sağlandı!',
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
      title: '❌ Teklif Reddedildi',
      body: `${rejecter?.name || 'Birisi'} teklifinizi reddetti.`,
      relatedId: c.target_id, senderId: req.userId,
    });
    res.json({ data: { challenge: await enrichChallenge({ ...c, status: action }), matchCreated: false, action } });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

challengesRouter.delete('/:id', async (req, res) => {
  try {
    const c = await db.findById('challenges', req.params.id);
    if (!c || c.sender_id !== req.userId) return res.status(404).json({ message: 'Teklif bulunamadı.' });
    if (c.status !== 'PENDING') return res.status(400).json({ message: 'Yalnızca beklemedeki teklifler silinebilir.' });
    await db.remove('challenges', c.id);
    res.json({ message: 'Teklif silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.use('/api/challenges', challengesRouter);

// ══════════════════════════════════════════════════════════════════════════════
//  POSTS (gönderi, reaksiyon, yorum)
// ══════════════════════════════════════════════════════════════════════════════
const postsRouter = express.Router();
postsRouter.use(authMiddleware);

postsRouter.get('/', async (req, res) => {
  try {
    const { page = 1, pageSize = 20, postType, cityId, cityName, countryCode, userId } = req.query;
    const pg = Number(page);
    const ps = Math.min(50, Number(pageSize));
    const skip = (pg - 1) * ps;

    const client = db.raw();
    let q = client.from('posts').select('*').order('created_at', { ascending: false });
    if (postType) q = q.eq('post_type', postType);
    if (cityId) q = q.eq('city_id', cityId);
    if (cityName) q = q.ilike('city_name', `%${cityName}%`);
    if (countryCode) q = q.eq('country_code', countryCode);
    if (userId) q = q.eq('user_id', userId);
    q = q.range(skip, skip + ps - 1);

    const { data } = await q;
    const posts = data || [];
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
      // Batch comment counts — get all comments for these posts and count in-memory
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
      return res.status(400).json({ message: 'İçerik gerekli.' });

    const user = await userById(req.userId);
    const sport = body.sportId ? await db.findById('sports', body.sportId) : null;

    // NOTE: city_id and district_id have FK constraints to cities/districts tables
    // Flutter sends numeric IDs from states.json but DB has "c1" format → FK violation
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
    const user = await userById(req.params.userId); // Single user — just one query

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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
    if (post.user_id !== req.userId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    const { content } = req.body;
    if (!content || content.trim().length === 0)
      return res.status(400).json({ message: 'İçerik boş olamaz.' });
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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
    const { type = 'LIKE' } = req.body;
    if (!REACTION_TYPES.includes(type)) return res.status(400).json({ message: 'Geçersiz reaksiyon tipi.' });

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
          title: 'Gönderi Reaksiyonu',
          body: `${reactor?.name || 'Birisi'} gönderinize tepki verdi.`,
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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
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
    if (postComments.length === 0) return res.json({ data: [] });

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
    if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
    const body = sanitize(req.body);
    if (!body.content || body.content.trim().length < 1)
      return res.status(400).json({ message: 'Yorum içeriği gerekli.' });
    if (body.content.length > 2000)
      return res.status(400).json({ message: 'Yorum en fazla 2000 karakter olabilir.' });

    // Validate parentId
    if (body.parentId) {
      const parent = await db.findById('comments', body.parentId);
      if (!parent || parent.post_id !== post.id) return res.status(404).json({ message: 'Üst yorum bulunamadı.' });
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
        title: body.parentId ? 'Yorumunuza yanıt' : 'Yeni yorum',
        body: `${user?.name || 'Birisi'} ${body.parentId ? 'yorumunuza yanıt verdi.' : 'gönderinize yorum yaptı.'}`,
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
      return res.status(404).json({ message: 'Yorum bulunamadı.' });
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
      return res.status(404).json({ message: 'Yorum bulunamadı.' });
    if (comment.user_id !== req.userId) return res.status(403).json({ message: 'Yetkiniz yok.' });
    const { content } = req.body;
    if (!content || content.trim().length === 0)
      return res.status(400).json({ message: 'İçerik boş olamaz.' });
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

// ══════════════════════════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════════════════
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
    res.json({ message: 'Okundu olarak işaretlendi.' });
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

// ══════════════════════════════════════════════════════════════════════════════
//  SETTINGS / PRIVACY
// ══════════════════════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════════════════════
//  HOME-BOOTSTRAP — Tek istek ile ana sayfa verisi (4→1 API call)
// ══════════════════════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════════════════════
//  CRON JOBS — Hobby plan uyumlu bakım endpoint'leri
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/cron/cleanup-expired', async (req, res) => {
  // Vercel Cron Authorization header kontrolü
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const client = db.raw();
    const now = new Date().toISOString();

    // 1. Süresi dolan ilanları sil (expires_at < now)
    const { data: expired } = await client.from('listings').select('id')
      .lt('expires_at', now).eq('status', 'ACTIVE');
    const expiredIds = (expired || []).map(l => l.id);

    let deletedListings = 0;
    if (expiredIds.length > 0) {
      // İlgili interests'leri önce sil
      await client.from('interests').delete().in('listing_id', expiredIds);
      const { count } = await client.from('listings').delete({ count: 'exact' }).in('id', expiredIds);
      deletedListings = count || 0;
    }

    // 2. Süresi dolmuş password reset token'larını temizle
    const { count: deletedTokens } = await client.from('password_reset_tokens')
      .delete({ count: 'exact' }).lt('expires_at', now);

    // 3. Süresi dolmuş refresh token'larını temizle
    const { count: deletedRefresh } = await client.from('refresh_tokens')
      .delete({ count: 'exact' }).lt('expires_at', now);

    // 4. Zamanı geçmiş ama henüz tamamlanmamış maçlar için tek seferlik hatırlatma üret
    const reminderNotifications = await generateMatchReminders({ now });

    res.json({
      message: 'Cleanup completed',
      deletedListings, deletedTokens: deletedTokens || 0,
      deletedRefreshTokens: deletedRefresh || 0,
      reminderNotifications,
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
  // Vercel Cron Authorization header kontrolü
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    // Ecosystem tick-all mantığını çağır
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

// ══════════════════════════════════════════════════════════════════════════════
//  FEED, SEARCH, LEADERBOARD, RECOMMENDATIONS, ACTIVITIES, RATINGS
// ══════════════════════════════════════════════════════════════════════════════
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
    res.json({ data: items, reason: 'Spor tercihlerinize göre' });
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

    // ── 1. My listings (last 20) ──
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

    // ── 2. My interests (responses to others' listings) ──
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

    // ── 3. My matches (last 20 — not unlimited!) ──
    const { data: matchData } = await client.from('matches').select('*')
      .or(`user1_id.eq.${req.userId},user2_id.eq.${req.userId}`)
      .order('created_at', { ascending: false })
      .limit(5);

    const mArr = matchData || [];
    // Batch: users + listings + sports for matches
    const mUserIds = new Set();
    const mListingIds = new Set();
    for (const m of mArr) {
      mUserIds.add(m.user1_id); mUserIds.add(m.user2_id);
      if (m.listing_id) mListingIds.add(m.listing_id);
    }
    const [mUsersArr, mListingsArr] = await Promise.all([
      mUserIds.size > 0 ? client.from('users').select('*').in('id', [...mUserIds]).then(r => r.data || []) : [],
      mListingIds.size > 0 ? client.from('listings').select('*').in('id', [...mListingIds]).then(r => r.data || []) : [],
    ]);
    const mUsersMap = new Map(mUsersArr.map(u => [u.id, u]));
    const mListingsMap = new Map(mListingsArr.map(l => [l.id, l]));
    const mSportIds = new Set(mListingsArr.filter(l => l.sport_id).map(l => l.sport_id));
    const mSportsArr = mSportIds.size > 0
      ? (await client.from('sports').select('*').in('id', [...mSportIds])).data || []
      : [];
    const mSportsMap = new Map(mSportsArr.map(s => [s.id, s]));

    const enrichedMatches = mArr.map(m => {
      const u1 = mUsersMap.get(m.user1_id);
      const u2 = mUsersMap.get(m.user2_id);
      const listing = m.listing_id ? mListingsMap.get(m.listing_id) : null;
      const sport = listing?.sport_id ? mSportsMap.get(listing.sport_id) : null;
      return {
        ...toCamel(m), source: m.source || 'LISTING',
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
    const { matchId, score, comment } = req.body;
    if (!matchId || score == null) return res.status(400).json({ message: 'matchId ve score gerekli.' });

    const s = parseInt(score, 10);
    if (isNaN(s) || s < 1 || s > 5) return res.status(400).json({ message: 'Puan 1-5 arasında olmalı.' });

    const m = await db.findById('matches', matchId);
    if (!m) return res.status(404).json({ message: 'Maç bulunamadı.' });
    if (m.status !== 'COMPLETED') return res.status(400).json({ message: 'Yalnızca tamamlanan maçlar değerlendirilebilir.' });
    if (req.userId !== m.user1_id && req.userId !== m.user2_id) return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });

    const rateeId = req.userId === m.user1_id ? m.user2_id : m.user1_id;
    const listing = await listingById(m.listing_id);
    const sportId = listing?.sport_id || null;

    // Check for existing rating: per sport per user pair (NOT per match)
    let existingRating = null;
    if (sportId) {
      existingRating = await db.findOne('ratings', { rater_id: req.userId, ratee_id: rateeId, sport_id: sportId });
    }
    if (!existingRating) {
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

      return res.json({ message: 'Değerlendirme güncellendi.', updated: true });
    }

    // NEW rating
    const ratee = await userById(rateeId);
    if (ratee) {
      const prevTotal = (ratee.average_rating || 0) * (ratee.rating_count || 0);
      const newCount = (ratee.rating_count || 0) + 1;
      const newAvg = parseFloat(((prevTotal + s) / newCount).toFixed(2));
      await db.update('users', rateeId, { average_rating: newAvg, rating_count: newCount });
    }

    await db.insert('ratings', {
      id: uuid(), match_id: matchId, rater_id: req.userId,
      ratee_id: rateeId, score: s, comment: comment || null,
      sport_id: sportId,
    });

    const rater = await userById(req.userId);
    await pushNotification({
      userId: rateeId, type: 'NEW_RATING',
      title: '⭐ Yeni Değerlendirme',
      body: `${rater?.name || 'Birisi'} sizi değerlendirdi`,
      relatedId: matchId, senderId: req.userId,
      senderName: rater?.name, senderAvatar: rater?.avatar_url,
    });

    res.status(201).json({ message: 'Değerlendirme kaydedildi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Misc ────────────────────────────────────────────────────────────────────
app.get('/api/turnuvalar', authMiddleware, (_req, res) => res.json({ data: [] }));
app.get('/api/tournaments', authMiddleware, (_req, res) => res.json({ data: [] }));
app.post('/api/push/token', authMiddleware, (_req, res) => res.json({ message: 'Push token kaydedildi.' }));
app.get('/api/clubs', authMiddleware, async (_req, res) => {
  try {
    const data = await db.query('communities', { filters: { type: 'CLUB' } });
    res.json({ data: data.map(toCamel) });
  } catch { res.json({ data: [] }); }
});
app.post('/api/reports', authMiddleware, (_req, res) => res.json({ success: true, message: 'Şikayet alındı.' }));

// ── Communities (simplified) ────────────────────────────────────────────────
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

// ══════════════════════════════════════════════════════════════════════════════
//  BOT ECOSYSTEM — Şehir/Ülke Canlandırma Motoru (Supabase-backed)
// ══════════════════════════════════════════════════════════════════════════════
// Lazy load: bot-automation modülü (LOCALIZED_NAMES 24 ülke) sadece
// ecosystem endpoint'i ilk kez çağrıldığında yüklenir — cold start'ı hızlandırır.
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
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Yetkisiz: Admin değilsiniz.' });
  next();
});

/**
 * GET /api/admin/ecosystems — Tüm aktif ekosistemler
 */
ecosystemRouter.get('/', async (req, res) => {
  try {
    const ecosystems = await db.query('bot_ecosystems', { order: 'created_at', ascending: false });
    if (ecosystems.length === 0) return res.json({ data: [] });

    // Batch: tüm bot kullanıcılarını tek sorguda çek, city_id + city_name fallback ile eşleştir
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
 * POST /api/admin/ecosystems — Yeni ekosistem oluştur (Şehir/Ülke Canlandır)
 *
 * Body:
 *   scope: 'CITY' | 'COUNTRY' | 'WORLD'
 *   countryCode: 'TR' (required for CITY/COUNTRY)
 *   cityId: 'state_123' (required for CITY)
 *   cityName: 'İstanbul' (required for CITY)
 *   sportIds: ['sport_yoga', 'sport_pilates'] (array of sport IDs)
 *   listingType: 'PARTNER' | 'RIVAL' | 'BOTH'
 *   botsPerCity: 4-20 (default 6) — must be even
 *   maxParticipants: 3-6 (default 4) — group listing size
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
      return res.status(400).json({ message: 'Şehir seçilmeli (cityId, cityName).' });
    }
    if ((scope === 'CITY' || scope === 'COUNTRY') && !countryCode) {
      return res.status(400).json({ message: 'Ülke kodu gerekli (countryCode).' });
    }

    // botsPerGroup * groupsPerCity = total bots per city (if botsPerGroup sent from Flutter)
    const totalBotsPerCity = botsPerGroup ? Math.min(40, (parseInt(botsPerGroup) || 8) * (parseInt(groupsPerCity) || 1)) : (parseInt(botsPerCity) || 6);
    const perCity = Math.min(40, Math.max(4, totalBotsPerCity));
    const maxPart = Math.min(6, Math.max(3, parseInt(maxParticipants) || 4));
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

    if (cities.length === 0) return res.status(400).json({ message: 'Şehir verisi bulunamadı.' });

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

      // Create bots (mostly female ~70%) — batch insert (tek Supabase çağrısı)
      const femalePct = 0.7;
      const femaleCount = Math.round(perCity * femalePct);
      const botRows = [];
      const botMeta = []; // id/name/gender/sportId bilgisi listings için

      const nowMs = Date.now();
      for (let i = 0; i < perCity; i++) {
        const isFemale = i < femaleCount;
        const gender = isFemale ? 'FEMALE' : 'MALE';
        const nameList = isFemale ? names.female : names.male;
        const bName = nameList[i % nameList.length];
        const sport = selectedSports[i % selectedSports.length];
        const botId = 'bot_' + uuid();
        const coords = botAutomation.estimateBotCoordinates({ citySeed: city.id, countryCode: cc });

        botRows.push({
          id: botId,
          email: `bot_${nowMs}_${i}_${city.id.slice(0, 6)}@sporpartner.internal`,
          name: bName,
          username: `bot_${bName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_${(nowMs + i) % 100000}`,
          password: '$2a$10$BOT_NO_LOGIN_PLACEHOLDER_HASH',
          avatar_url: botAutomation.buildBotAvatarUrl({ gender, seed: `${bName}-${city.id}-${sport.name}` }),
          cover_url: null, phone: null,
          is_admin: false, is_bot: true, bot_persona: null,
          onboarding_done: true, user_type: 'USER',
          city: city.name, city_id: persistCityId, country_code: cc,
          district: null, district_id: null,
          bio: botAutomation.generateBotBio({ locale, sportName: sport.name, cityName: city.name }),
          instagram: null, tiktok: null, facebook: null, twitter: null,
          youtube: null, linkedin: null, discord: null, twitch: null,
          snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
          sports: [{ id: sport.id, name: sport.name, icon: sport.icon }],
          level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
          gender,
          preferred_time: null, preferred_style: null,
          birth_date: new Date(1992 + (i % 13), i % 12, 1 + (i % 28)).toISOString(),
          total_matches: 0, current_streak: 0, longest_streak: 0, total_points: 0,
          follower_count: 0, following_count: 0, average_rating: 0, rating_count: 0,
          is_banned: false, no_show_count: 0, is_private: false,
          latitude: coords.latitude, longitude: coords.longitude,
          referral_code: `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
        });
        botMeta.push({ id: botId, name: bName, gender, sportId: sport.id, sportName: sport.name });
      }

      // Tüm botları tek bir Supabase INSERT çağrısıyla ekle
      let botsCreated = [];
      try {
        await db.insertMany('users', botRows);
        botsCreated = botMeta;
        totalBots += botsCreated.length;
      } catch (err) {
        console.error(`Bot batch insert error (city: ${city.name}):`, err.message);
        // Kısmi başarısızlık: bireysel fallback
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

      // Create initial group listings (female bots create listings) — batch insert
      const femaleBots = botsCreated.filter(b => b.gender === 'FEMALE');
      const listingRows = [];
      for (const bot of femaleBots) {
        const sport = selectedSports.find(s => s.id === bot.sportId) || selectedSports[0];
        const lType = listingType === 'BOTH' ? (Math.random() > 0.5 ? 'PARTNER' : 'RIVAL') : listingType;
        const futureDate = botAutomation.getFutureDate(1 + Math.floor(Math.random() * 6));
        const coords = botAutomation.estimateBotCoordinates({ citySeed: city.id, countryCode: cc });
        const listingId = 'listing_' + uuid();

        listingRows.push({
          id: listingId,
          type: lType,
          title: botAutomation.generateListingDesc({ name: bot.name, sport: sport.name, locale, city: city.name }),
          description: botAutomation.generateListingDesc({ name: bot.name, sport: sport.name, locale, city: city.name }),
          sport_id: sport.id, sport_name: sport.name,
          city_id: persistCityId, city_name: city.name,
          district_id: null, district_name: null,
          venue_id: null, venue_name: null,
          level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
          gender: 'ANY',
          date: futureDate.toISOString(),
          image_urls: [],
          max_participants: maxPart,
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

      // Tüm ilanları tek bir Supabase INSERT çağrısıyla ekle
      let cityListingsCreated = 0;
      if (listingRows.length > 0) {
        try {
          await db.insertMany('listings', listingRows);
          cityListingsCreated = listingRows.length;
          totalListings += cityListingsCreated;
        } catch (err) {
          console.error(`Listing batch insert error (city: ${city.name}):`, err.message);
          // Kısmi başarısızlık: bireysel fallback
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
      message: `${cities.length} şehirde ${totalBots} bot + ${totalListings} ilan oluşturuldu.`,
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
 * POST /api/admin/ecosystems/:id/tick — Saatlik ekosistem güncellemesi
 * Botlar birbirlerinin ilanlarına başvurur, kabul eder, eşleşir, puanlar
 */
ecosystemRouter.post('/:id/tick', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });
    if (eco.status !== 'ACTIVE') return res.status(400).json({ message: 'Ekosistem aktif değil.' });

    const result = await runEcosystemTick(eco);
    res.json({ success: true, data: result });
  } catch (e) {
    console.error('Ecosystem tick error:', e);
    res.status(500).json({ message: e.message });
  }
});

/**
 * POST /api/admin/ecosystems/tick-all — Tüm aktif ekosistemlerin saatlik güncellemesi
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
 * DELETE /api/admin/ecosystems/:id — Ekosistem sil (botları ve verilerini temizle)
 */
ecosystemRouter.delete('/:id', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

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
 * PATCH /api/admin/ecosystems/:id — Ekosistem güncelle (duraklatma, parametre değiştirme)
 */
ecosystemRouter.patch('/:id', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

    const { status, hourlyApplications, maxParticipants, sportIds, listingType } = req.body;
    const changes = {};
    if (status && ['ACTIVE', 'PAUSED'].includes(status)) changes.status = status;
    if (hourlyApplications) changes.hourly_applications = Math.min(5, Math.max(1, parseInt(hourlyApplications)));
    if (maxParticipants) changes.max_participants = Math.min(6, Math.max(3, parseInt(maxParticipants)));
    if (sportIds) changes.sport_ids = sportIds;
    if (listingType) changes.listing_type = listingType;

    const updated = await db.update('bot_ecosystems', eco.id, changes);
    res.json({ data: toCamel(updated) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * POST /api/admin/ecosystems/:id/toggle-bots-privacy
 * Botların profillerini public/private yap
 */
ecosystemRouter.post('/:id/toggle-bots-privacy', async (req, res) => {
  try {
    const eco = await db.findById('bot_ecosystems', req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

    const { isPrivate } = req.body;
    const bots = await getBotsForEcosystem(eco);
    let updated = 0;
    for (const bot of bots) {
      await db.update('users', bot.id, { is_private: !!isPrivate });
      updated++;
    }
    res.json({ message: `${updated} bot profili ${isPrivate ? 'gizli' : 'herkese açık'} yapıldı.` });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Ecosystem Tick Engine ───────────────────────────────────────────────────
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
        fillRows.push({
          id: botId, email: `bot_${nowMs}_fill_${i}_${eco.city_id.slice(0,6)}@sporpartner.internal`,
          name: bName, username: `bot_${bName.replace(/[^a-zA-Z0-9]/g,'').toLowerCase()}_fill_${(nowMs+i)%100000}`,
          password: '$2a$10$BOT_NO_LOGIN_PLACEHOLDER_HASH',
          avatar_url: botAutomationFill.buildBotAvatarUrl({ gender, seed: `${bName}-${eco.city_id}-${sport.name}` }),
          cover_url: null, phone: null, is_admin: false, is_bot: true, bot_persona: null,
          onboarding_done: true, user_type: 'USER',
          city: eco.city_name, city_id: persistEcoCityId, country_code: eco.country_code,
          district: null, district_id: null,
          bio: botAutomationFill.generateBotBio({ locale, sportName: sport.name, cityName: eco.city_name }),
          instagram: null, tiktok: null, facebook: null, twitter: null, youtube: null,
          linkedin: null, discord: null, twitch: null, snapchat: null, telegram: null,
          whatsapp: null, vk: null, litmatch: null,
          sports: [{ id: sport.id, name: sport.name, icon: sport.icon }],
          level: ['BEGINNER','INTERMEDIATE','ADVANCED'][Math.floor(Math.random()*3)],
          gender, preferred_time: null, preferred_style: null,
          birth_date: new Date(1992+(i%13), i%12, 1+(i%28)).toISOString(),
          total_matches: 0, current_streak: 0, longest_streak: 0, total_points: 0,
          follower_count: 0, following_count: 0, average_rating: 0, rating_count: 0,
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

  const botIds = bots.map(b => b.id);
  const botIdSet = new Set(botIds);
  const botAutomation = getBotAutomation();
  const locale = botAutomation ? botAutomation.mapCountryCodeToLocale(eco.country_code || 'EN') : 'en';

  // 1. APPLICATIONS — Bots apply to active listings
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
        message: botAutomation ? botAutomation.generateResponseMsg(bot.name, locale) : `${bot.name} katılmak istiyor!`,
        status: 'PENDING',
      };
      try {
        await db.insert('interests', interest);
        await db.update('listings', listing.id, { response_count: (listing.response_count || 0) + 1 });
        stats.newApplications++;
      } catch { /* skip duplicates */ }
    }
  }

  // 2. ACCEPTANCES — Listing owners accept pending applications
  const { data: pendingInterests } = await client.from('interests').select('*')
    .in('listing_id', (activeListings || []).map(l => l.id))
    .eq('status', 'PENDING');

  for (const interest of (pendingInterests || [])) {
    const listing = (activeListings || []).find(l => l.id === interest.listing_id);
    if (!listing || !botIdSet.has(listing.user_id)) continue;

    // Check capacity
    const currentAccepted = listing.accepted_count || 0;
    const slotsNeeded = Math.max(1, (listing.max_participants || 4) - 1);
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

    if ((listing.max_participants || 2) <= 2) {
      const matchId = 'match_' + uuid();
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
      stats.newMatches++;
    }
    stats.newAcceptances++;

    // Update bot match stats
    await db.raw().from('users').update({ total_matches: db.raw().rpc ? 1 : 1 }).eq('id', listing.user_id);
    const u1 = await userById(listing.user_id);
    if (u1) await db.update('users', u1.id, { total_matches: (u1.total_matches || 0) + 1 });
    const u2 = await userById(interest.user_id);
    if (u2) await db.update('users', u2.id, { total_matches: (u2.total_matches || 0) + 1 });
  }

  // 3. RATINGS — Complete scheduled matches and rate each other
  const { data: scheduledMatches } = await client.from('matches').select('*')
    .eq('status', 'SCHEDULED')
    .or(botIds.map(id => `user1_id.eq.${id}`).join(','));

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
        const comments = ['Harika partner! 🎾', 'Çok keyifli maçtı!', 'Tekrar oynamak isterim', 'Great game!', 'Super Spiel!', 'Отличная игра!'];
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

  // 4. NEW LISTINGS — Create new listings to replace matched ones
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
    try {
      await db.insert('listings', {
        id: listingId,
        type: lType,
        title: botAutomation ? botAutomation.generateListingDesc({ name: bot.name, sport: sport.name, locale, city: eco.city_name }) : `${bot.name} - ${sport.name}`,
        description: botAutomation ? botAutomation.generateListingDesc({ name: bot.name, sport: sport.name, locale, city: eco.city_name }) : null,
        sport_id: sport.id, sport_name: sport.name,
        city_id: persistEcoCityId, city_name: eco.city_name,
        district_id: null, district_name: null,
        venue_id: null, venue_name: null,
        level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
        gender: 'ANY',
        date: futureDate.toISOString ? futureDate.toISOString() : futureDate,
        image_urls: [],
        max_participants: eco.max_participants || 4,
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

  // 5. SOCIAL POSTS — Bots create social posts (SOCIAL_LISTING) in their own language
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

  // 6. REACTIONS — Bots react (LIKE/FIRE/CLAP) to recent posts from ANY ecosystem
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

  // 7. COMMENTS — Bots comment on recent global posts (40% chance per reaction)
  if (botAutomation) {
    const twoDaysAgoC = new Date(Date.now() - 48 * 3600000).toISOString();
    const { data: postsToComment } = await client.from('posts')
      .select('id,user_id,sport_id').eq('post_type', 'SOCIAL_LISTING')
      .gte('created_at', twoDaysAgoC).order('created_at', { ascending: false }).limit(20);

    if ((postsToComment || []).length > 0) {
      // Fetch existing comments from our bots to avoid double-commenting
      const postIdsC = (postsToComment || []).map(p => p.id);
      const { data: existingComments } = await client.from('comments')
        .select('post_id,user_id,content').in('post_id', postIdsC).in('user_id', botIds);
      const commentedSet = new Set((existingComments || []).map(c => `${c.user_id}_${c.post_id}`));
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
          // Get poster name for personalized comment
          const posterBot = bots.find(b => b.id === post.user_id);
          const posterName = posterBot ? posterBot.name.split(' ')[0] : '';
          const sportForComment = post.sport_id
            ? (validSports.find(s => s.id === post.sport_id) || null)
            : null;
          const commentSportName = sportForComment
            ? (botAutomation.translateSportName
                ? botAutomation.translateSportName(sportForComment.id, botLocale, sportForComment.name)
                : sportForComment.name)
            : null;

          const usedForPost = usedCommentsByPost.get(post.id) || new Set();
          if (!usedCommentsByPost.has(post.id)) usedCommentsByPost.set(post.id, usedForPost);

          let content = '';
          let pickedSignature = '';
          // Prevent clone comments on the same post by trying multiple variants.
          for (let attempt = 0; attempt < 12; attempt++) {
            const candidate = botAutomation.generateBotComment({
              locale: botLocale,
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

// ── Admin Stats (Supabase-backed — replaces broken in-memory admin.js) ──────
const adminStatsRouter = express.Router();
adminStatsRouter.use(authMiddleware);
adminStatsRouter.use(async (req, res, next) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Yetkisiz: Admin değilsiniz.' });
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

// ── Admin: PATCH /users/:id (update user) ──
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

// ── Admin: DELETE /users/:id ──
adminStatsRouter.delete('/users/:id', async (req, res) => {
  try {
    await db.remove('users', req.params.id);
    res.json({ message: 'Kullanıcı silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: PATCH /reports/:id (resolve report) ──
adminStatsRouter.patch('/reports/:id', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const action = (body.action || body.status || 'RESOLVED').toUpperCase();
    const report = await db.findById('reports', req.params.id);
    if (!report) return res.status(404).json({ message: 'Rapor bulunamadı.' });

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

// ── Admin: GET /posts (list all posts) ──
adminStatsRouter.get('/posts', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const posts = await db.query('posts', { order: 'created_at', ascending: false, limit: parseInt(limit), offset });
    const total = await db.count('posts');
    res.json({ data: posts.map(toCamel), total, page: parseInt(page), limit: parseInt(limit) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: DELETE /posts/:id ──
adminStatsRouter.delete('/posts/:id', async (req, res) => {
  try {
    await db.remove('posts', req.params.id);
    res.json({ message: 'Gönderi silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: GET /listings (list all listings) ──
adminStatsRouter.get('/listings', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const listings = await db.query('listings', { order: 'created_at', ascending: false, limit: parseInt(limit), offset });
    const total = await db.count('listings');
    res.json({ data: listings.map(toCamel), total, page: parseInt(page), limit: parseInt(limit) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: DELETE /listings/bulk ──
adminStatsRouter.delete('/listings/bulk', async (req, res) => {
  try {
    const body = sanitize(req.body);
    const ids = body.ids || [];
    for (const id of ids) await db.remove('listings', id);
    res.json({ message: `${ids.length} ilan silindi.` });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: DELETE /listings/:id (individual listing delete) ──
adminStatsRouter.delete('/listings/:id', async (req, res) => {
  try {
    await db.remove('listings', req.params.id);
    res.json({ message: 'İlan silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── Admin: Bots CRUD ──
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

// ── Admin: Countries/Cities/Districts ──
adminStatsRouter.get('/countries', async (_req, res) => {
  try {
    const cities = await db.query('cities', { limit: 100 });
    // Group by a pseudo-country (Turkey)
    res.json({ data: [{ id: 'TR', name: 'Türkiye', cities: cities.map(toCamel) }] });
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

// ── Admin: Bot Tasks ──
adminStatsRouter.get('/bot-tasks', async (_req, res) => {
  try {
    const tasks = await db.query('bot_tasks', { order: 'created_at', ascending: false, limit: 50 }).catch(() => []);
    res.json({ data: tasks.map(toCamel) });
  } catch (e) { res.json({ data: [] }); }
});

adminStatsRouter.post('/bot-tasks/:id/execute', async (req, res) => {
  try {
    const updated = await db.update('bot_tasks', req.params.id, { status: 'EXECUTED' }).catch(() => null);
    res.json({ data: updated ? toCamel(updated) : null, message: 'Görev yürütüldü.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/bot-tasks', async (_req, res) => {
  try {
    // Bulk delete all completed bot tasks
    const tasks = await db.query('bot_tasks', { filter: { status: 'EXECUTED' }, limit: 200 }).catch(() => []);
    for (const t of tasks) await db.remove('bot_tasks', t.id).catch(() => {});
    res.json({ message: `${tasks.length} görev silindi.` });
  } catch (e) { res.json({ message: 'Temizlendi.' }); }
});

// ── Admin: Challenges ──
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

// ── Admin: Matches ──
adminStatsRouter.get('/matches', async (_req, res) => {
  try {
    const matches = await db.query('matches', { order: 'created_at', ascending: false, limit: 50 });
    res.json({ data: matches.map(toCamel) });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

adminStatsRouter.delete('/matches/:id', async (req, res) => {
  try {
    await db.remove('matches', req.params.id);
    res.json({ message: 'Eşleşme silindi.' });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// Mount Supabase-backed admin routes BEFORE the legacy in-memory admin.js
app.use('/api/admin/ecosystems', ecosystemRouter);
app.use('/api/admin', adminStatsRouter);

// Legacy admin routes (in-memory store — only works in Docker/dev)
try {
  const adminRouter = require('../routes/admin');
  app.use('/api/admin', authMiddleware, adminRouter);
} catch { /* admin routes not available */ }

// ── Stress Monitor (auth required) ──────────────────────────────────────────
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

// ── DB Migration (admin-only, idempotent) ───────────────────────────────────
app.post('/api/admin/migrate', authMiddleware, async (req, res) => {
  const user = await userById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ message: 'Admin only.' });

  const client = db.raw();
  const results = [];

  // 1. bot_ecosystems table
  try {
    const { error: checkErr } = await client.from('bot_ecosystems').select('id').limit(1);
    if (checkErr && checkErr.message.includes('could not find')) {
      // Table doesn't exist — create via raw SQL through a temp function
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

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_listings_expires_at ON listings(expires_at) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_bot_ecosystems_active ON bot_ecosystems(is_active) WHERE is_active = true;
  ` });
});

// ── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ message: `Endpoint bulunamadı: ${req.method} ${req.path}` }));

module.exports = app;
