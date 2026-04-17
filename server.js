'use strict';
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const { v4: uuid } = require('uuid');
const http     = require('http');
const WebSocket = require('ws');
const path     = require('path');

const store    = require('./db/store');
const { startPersistence } = require('./db/persistence');
const { generateTokens, verifyRefreshToken, authMiddleware } = require('./middleware/auth');
const { contentFilter } = require('./middleware/content-filter');
const adminRouter = require('./routes/admin');
const compression = require('compression');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

// WebSocket clients map: userId → ws
const wsClients = new Map();

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(compression()); // gzip response compression
app.use(helmet({
  // Allow API responses from mobile apps (no iframe embedding needed)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'"],
      imgSrc:     ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,       // 1 year
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50kb' }));

// ─── Rate Limiting (in-memory, per IP) ─────────────────────────────────────────
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 dakika
const RATE_LIMIT_MAX = process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 300; // pencere başına max istek

// Login brute force koruması: 5 başarısız deneme / 15 dakika
const loginAttemptStore = new Map();
const LOGIN_WINDOW = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

// Rate limit store temizlik: Her 5 dakikada süresi dolmuş girdileri sil
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now - entry.start > RATE_LIMIT_WINDOW * 2) rateLimitStore.delete(key);
  }
  for (const [key, entry] of loginAttemptStore) {
    if (now - entry.start > LOGIN_WINDOW * 2) loginAttemptStore.delete(key);
  }
}, 5 * 60 * 1000);

// İlan tarihi geçmiş ilanları otomatik EXPIRED yap: Her 60 saniyede kontrol
setInterval(() => {
  const now = new Date();
  for (const listing of store.listings) {
    if (
      (listing.status === 'ACTIVE' || listing.status === 'MATCHED') &&
      listing.date && new Date(listing.date) < now
    ) {
      listing.status = 'EXPIRED';
    }
  }
}, 60 * 1000);

function rateLimiter(req, res, next) {
  const key = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  let entry = rateLimitStore.get(key);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimitStore.delete(key);
    entry = { start: now, count: 0 };
    rateLimitStore.set(key, entry);
  }
  entry.count++;
  res.set('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
  res.set('X-RateLimit-Remaining', String(Math.max(0, RATE_LIMIT_MAX - entry.count)));
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ message: 'Çok fazla istek. Lütfen bekleyin.' });
  }
  next();
}
app.use(rateLimiter);

// ─── XSS Sanitization Helper ──────────────────────────────────────────────────
function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/javascript\s*:/gi, '')
    .replace(/data\s*:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}
function sanitizeObject(obj) {
  if (typeof obj === 'string') return sanitizeString(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeObject);
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(obj)) result[k] = sanitizeObject(v);
    return result;
  }
  return obj;
}

// Multer (file upload — store in memory, return a placeholder URL)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ─── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'ws://localhost');
  const token = url.searchParams.get('token');
  let userId = null;
  try {
    const jwt = require('jsonwebtoken');
    const { JWT_SECRET } = require('./middleware/auth');
    const payload = jwt.verify(token, JWT_SECRET);
    userId = payload.sub;
    wsClients.set(userId, ws);
    ws._lastPong = Date.now();
    console.log(`WS connected: ${userId}`);
  } catch {
    ws.close(4001, 'Unauthorized');
    return;
  }
  ws.on('pong', () => { ws._lastPong = Date.now(); });
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'ping') ws.send(JSON.stringify({ type: 'pong' }));
    } catch { /* binary/invalid — ignore */ }
  });
  ws.on('close', () => { if (userId) wsClients.delete(userId); });
});

// WebSocket ping/pong — 30sn'de bir stale bağlantıları tespit et ve kapat
setInterval(() => {
  const now = Date.now();
  wss.clients.forEach((ws) => {
    if (ws._lastPong && now - ws._lastPong > 90000) {
      ws.terminate(); // 90sn yanıt yok → kapat
      return;
    }
    if (ws.readyState === WebSocket.OPEN) ws.ping();
  });
}, 30000);

function sendWsEvent(userId, event, data = {}) {
  const ws = wsClients.get(userId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: event, ...(data || {}) }));
  }
}

function pushNotification({
  userId,
  type,
  title,
  body,
  relatedId = null,
  link = null,
  senderId = null,
  senderName = null,
  senderAvatar = null,
}) {
  const notification = {
    id: uuid(),
    userId,
    type,
    title,
    body,
    relatedId,
    link,
    senderId,
    senderName,
    senderAvatar,
    isRead: false,
    createdAt: new Date().toISOString(),
  };
  store.notifications.push(notification);
  sendWsEvent(userId, 'new_notification', {
    id: notification.id,
    notifType: notification.type,
    title: notification.title,
    body: notification.body,
    relatedId: notification.relatedId,
    link: notification.link,
    createdAt: notification.createdAt,
  });
  return notification;
}

// ─── Streak Helper ───────────────────────────────────────────────────────────
function updateStreak(user) {
  const now = new Date();
  const last = user.lastMatchDate ? new Date(user.lastMatchDate) : null;
  if (last && (now - last) / 3600000 <= 48) {
    user.currentStreak = (user.currentStreak || 0) + 1;
  } else {
    user.currentStreak = 1;
  }
  if (user.currentStreak > (user.longestStreak || 0)) {
    user.longestStreak = user.currentStreak;
  }
  user.lastMatchDate = now.toISOString();
}

// ─── Password Reset Token Store (in-memory) ────────────────────────────────────
const resetTokens = new Map(); // token → { userId, expiresAt }

// ─── Helpers ───────────────────────────────────────────────────────────────────
function safeUser(u) {
  const { password, ...rest } = u;
  return rest;
}

function userById(id) {
  return store.users.find(u => u.id === id);
}

function listingById(id) {
  return store.listings.find(l => l.id === id);
}

function findOrCreateConversation(user1Id, user2Id) {
  const now = new Date().toISOString();
  let conv = store.conversations.find(
    c => (c.user1Id === user1Id && c.user2Id === user2Id) ||
         (c.user1Id === user2Id && c.user2Id === user1Id)
  );
  if (!conv) {
    conv = {
      id: uuid(),
      user1Id,
      user2Id,
      type: 'direct',
      createdAt: now,
      updatedAt: now,
      lastMessage: null,
    };
    store.conversations.push(conv);
  } else {
    conv.updatedAt = now;
  }
  return conv;
}

const SOCIAL_PLATFORMS = [
  'instagram',
  'tiktok',
  'facebook',
  'twitter',
  'youtube',
  'linkedin',
  'discord',
  'twitch',
  'snapchat',
  'telegram',
  'whatsapp',
  'vk',
  'litmatch',
];

function normalizeVisibility(value, fallback = 'EVERYONE') {
  const raw = String(value || '').toUpperCase();
  if (raw === 'PUBLIC' || raw === 'EVERYONE') return 'EVERYONE';
  if (raw === 'FOLLOWERS' || raw === 'FRIENDS' || raw === 'PRIVATE') return 'FOLLOWERS';
  if (raw === 'NOBODY' || raw === 'NONE') return 'NOBODY';
  return fallback;
}

function normalizePrivacySettings(input = {}) {
  const socialRaw = input.socialPlatformVisibility && typeof input.socialPlatformVisibility === 'object'
    ? input.socialPlatformVisibility
    : {};
  const socialPlatformVisibility = {};
  for (const platform of SOCIAL_PLATFORMS) {
    socialPlatformVisibility[platform] = normalizeVisibility(
      socialRaw[platform],
      normalizeVisibility(input.socialLinksVisibility, 'EVERYONE'),
    );
  }

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

function canViewerSeeByVisibility(viewerId, ownerId, visibility) {
  const rule = normalizeVisibility(visibility, 'EVERYONE');
  if (viewerId && ownerId && viewerId === ownerId) return true;
  if (rule === 'NOBODY') return false;
  if (rule === 'EVERYONE') return true;
  const follow = store.follows.find(
    f => f.followerId === viewerId && f.followingId === ownerId,
  );
  return follow?.status === 'accepted';
}

function isListingIdentityVisible(listing, viewerId) {
  if (!listing?.isAnonymous) return true;
  if (listing.userId === viewerId) return true;
  return store.matches.some(
    m => m.listingId === listing.id && (m.user1Id === viewerId || m.user2Id === viewerId),
  );
}

function anonymizedListingForViewer(listing, viewerId) {
  if (isListingIdentityVisible(listing, viewerId)) return listing;
  const anonSuffix = String(listing.id || '').replace(/\D/g, '').slice(-3) || '000';
  return {
    ...listing,
    userName: `Sporcu_${anonSuffix}`,
    userAvatar: null,
  };
}

// ─── AUTH ──────────────────────────────────────────────────────────────────────
const authRouter = express.Router();

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email ve şifre gerekli.' });

  // Brute force koruması
  const ipKey = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  let attempt = loginAttemptStore.get(ipKey);
  if (!attempt || now - attempt.start > LOGIN_WINDOW) {
    attempt = { start: now, count: 0 };
    loginAttemptStore.set(ipKey, attempt);
  }
  if (attempt.count >= LOGIN_MAX_ATTEMPTS) {
    return res.status(429).json({ message: 'Çok fazla başarısız giriş denemesi. 15 dakika bekleyin.' });
  }

  const user = store.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) { attempt.count++; return res.status(401).json({ message: 'Kullanıcı bulunamadı.' }); }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) { attempt.count++; return res.status(401).json({ message: 'Hatalı şifre.' }); }
  // Başarılı giriş — sayacı sıfırla
  loginAttemptStore.delete(ipKey);
  const tokens = generateTokens(user.id);
  store.refreshTokens.add(tokens.refreshToken);
  res.json({ ...tokens, user: safeUser(user) });
});

authRouter.post('/register', contentFilter('name'), async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'Ad, email ve şifre gerekli.' });
  if (store.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ message: 'Bu email zaten kayıtlı.' });
  }
  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: uuid(),
    email,
    name,
    username: email.split('@')[0],
    password: hashed,
    avatarUrl: null,
    coverUrl: null,
    phone: null,
    isAdmin: false,
    onboardingDone: false,
    userType: 'USER',
    city: null, cityId: null, district: null, districtId: null,
    bio: null, instagram: null, tiktok: null, facebook: null,
    twitter: null, youtube: null, linkedin: null, discord: null, twitch: null,
    snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
    sports: [],
    level: 'BEGINNER',
    gender: null,
    preferredTime: null, preferredStyle: null,
    birthDate: null,
    totalMatches: 0, currentStreak: 0, longestStreak: 0, totalPoints: 0,
    followerCount: 0, followingCount: 0, averageRating: 0, ratingCount: 0,
    isBanned: false, noShowCount: 0,
    lastMatchDate: null,
    referralCode: `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
    referredBy: req.body.referralCode || null,
    referralCount: 0,
    createdAt: new Date().toISOString(),
  };
  store.users.push(user);
  const tokens = generateTokens(user.id);
  store.refreshTokens.add(tokens.refreshToken);
  res.status(201).json({ ...tokens, user: safeUser(user) });
});

authRouter.post('/token/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken || !store.refreshTokens.has(refreshToken)) {
    return res.status(401).json({ message: 'Geçersiz refresh token.' });
  }
  try {
    const payload = verifyRefreshToken(refreshToken);
    store.refreshTokens.delete(refreshToken);
    const tokens = generateTokens(payload.sub);
    store.refreshTokens.add(tokens.refreshToken);
    res.json(tokens);
  } catch {
    res.status(401).json({ message: 'Refresh token süresi dolmuş.' });
  }
});

authRouter.post('/logout', authMiddleware, (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) store.refreshTokens.delete(refreshToken);
  res.status(200).json({ message: 'Çıkış yapıldı.' });
});

authRouter.post('/forgot-password', (req, res) => {
  const { email } = req.body || {};
  const user = store.users.find(u => u.email === email);
  if (!user) return res.json({ message: 'Eğer hesap mevcutsa sıfırlama kodu gönderildi.' }); // güvenlik için aynı mesaj
  // 6 haneli kod oluştur, 15 dakika geçerli
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const token = uuid();
  resetTokens.set(token, { userId: user.id, code, expiresAt: Date.now() + 15 * 60 * 1000 });
  // Gerçek prodüksiyonda burada email gönderilir; dev'de kodu response'a ekle
  res.json({ message: 'Sıfırlama kodu gönderildi.', devCode: code, devToken: token });
});

authRouter.post('/reset-password', (req, res) => {
  const { token, code, newPassword } = req.body || {};
  const entry = token ? resetTokens.get(token) : null;
  if (!entry) return res.status(400).json({ message: 'Geçersiz veya süresi dolmuş token.' });
  if (entry.code !== code) return res.status(400).json({ message: 'Hatalı sıfırlama kodu.' });
  if (Date.now() > entry.expiresAt) {
    resetTokens.delete(token);
    return res.status(400).json({ message: 'Kodun süresi dolmuş. Tekrar deneyin.' });
  }
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'Şifre en az 6 karakter olmalı.' });
  const user = store.users.find(u => u.id === entry.userId);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  user.password = bcrypt.hashSync(newPassword, 10);
  resetTokens.delete(token);
  res.json({ message: 'Şifre başarıyla sıfırlandı.' });
});

// ─── PROFILE ───────────────────────────────────────────────────────────────────
const profileRouter = express.Router();
profileRouter.use(authMiddleware);

profileRouter.get('/', (req, res) => {
  const user = userById(req.userId);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  const myListings = store.listings.filter(l => l.userId === req.userId);
  res.json({ data: { user: safeUser(user), myListings } });
});

profileRouter.patch('/', contentFilter('name', 'bio', 'username'), (req, res) => {
  const user = userById(req.userId);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  const sanitized = sanitizeObject(req.body);

  // Input validation
  if (sanitized.name !== undefined) {
    if (typeof sanitized.name !== 'string' || sanitized.name.trim().length < 2 || sanitized.name.trim().length > 50) {
      return res.status(400).json({ message: 'İsim 2-50 karakter olmalı.' });
    }
  }
  if (sanitized.bio !== undefined && sanitized.bio !== null) {
    if (typeof sanitized.bio !== 'string' || sanitized.bio.length > 500) {
      return res.status(400).json({ message: 'Biyografi en fazla 500 karakter olmalı.' });
    }
  }
  if (sanitized.username !== undefined) {
    if (typeof sanitized.username !== 'string' || sanitized.username.trim().length < 3 || sanitized.username.trim().length > 30) {
      return res.status(400).json({ message: 'Kullanıcı adı 3-30 karakter olmalı.' });
    }
  }

  const allowed = ['name','bio','gender','instagram','tiktok','facebook',
                   'twitter','youtube','linkedin','discord','twitch',
                   'snapchat','telegram','whatsapp','vk','litmatch',
                   'sportIds','city','cityId','district','districtId','level','preferredTime',
                   'preferredStyle','phone','birthDate','onboardingDone','username'];
  for (const key of allowed) {
    if (sanitized[key] !== undefined) {
      if (key === 'sportIds') {
        user.sports = (sanitized.sportIds || [])
          .map(id => store.SPORTS.find(s => s.id === id))
          .filter(Boolean);
      } else {
        user[key] = sanitized[key];
      }
    }
  }
  res.json({ data: { user: safeUser(user) } });
});

// ─── UPLOAD ────────────────────────────────────────────────────────────────────
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  const type = req.body.type || 'image';
  // Return a placeholder image URL
  const url = `http://10.0.2.2:3000/static/placeholder_${type}_${Date.now()}.jpg`;
  res.json({ url });
});

// Static placeholder (zararlı değil, sadece 1x1 px beyaz JPEG)
app.use('/static', express.static(path.join(__dirname, 'static')));

// ─── LISTINGS ──────────────────────────────────────────────────────────────────
const listingsRouter = express.Router();
listingsRouter.use(authMiddleware);

listingsRouter.get('/', (req, res) => {
  const { sport, city, district, type, level, gender, page = 1, pageSize = 20 } = req.query;
  const now = new Date();
  // ACTIVE ve MATCHED ilanları göster; tarihi geçmiş ilanları gizle
  let result = [...store.listings].filter(l => {
    if (l.status !== 'ACTIVE' && l.status !== 'MATCHED') return false;
    if (l.date && new Date(l.date) < now) return false;
    return true;
  });
  if (sport)    result = result.filter(l => l.sportId === sport || l.sportName === sport);
  if (city)     result = result.filter(l => l.cityId === city || l.cityName === city);
  if (district) result = result.filter(l => l.districtId === district);
  if (type)     result = result.filter(l => l.type === type);
  if (level)    result = result.filter(l => l.level === level);
  if (gender && gender !== 'ANY') result = result.filter(l => l.gender === gender || l.gender === 'ANY');
  const skip = (Number(page) - 1) * Number(pageSize);
  const paged = result
    .slice(skip, skip + Number(pageSize))
    .map(l => anonymizedListingForViewer(l, req.userId));
  res.json({ success: true, data: paged, pagination: { page: Number(page), hasNext: skip + paged.length < result.length } });
});

listingsRouter.get('/:id', (req, res) => {
  const listing = listingById(req.params.id);
  if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
  res.json(anonymizedListingForViewer(listing, req.userId));
});

listingsRouter.post('/', contentFilter('title', 'description'), (req, res) => {
  const user = userById(req.userId);
  const body = sanitizeObject(req.body);

  // Input validation
  if (!body.title || typeof body.title !== 'string' || body.title.trim().length < 3) {
    return res.status(400).json({ message: 'Başlık en az 3 karakter olmalı.' });
  }
  if (!body.sportId) {
    return res.status(400).json({ message: 'Spor dalı seçilmeli.' });
  }
  if (body.description && body.description.length > 2000) {
    return res.status(400).json({ message: 'Açıklama en fazla 2000 karakter olabilir.' });
  }
  if (body.title.length > 200) {
    return res.status(400).json({ message: 'Başlık en fazla 200 karakter olabilir.' });
  }

  const listing = {
    id: uuid(),
    type: body.type || 'RIVAL',
    title: body.title || `${user?.name || 'Kullanıcı'} ilanı`,
    description: body.description || null,
    sportId: body.sportId || 's1',
    sportName: (store.SPORTS.find(s => s.id === body.sportId) || {}).name || null,
    cityId: body.cityId || null,
    cityName: body.cityName || (store.CITIES.find(c => c.id === body.cityId) || {}).name || null,
    districtId: body.districtId || null,
    districtName: body.districtName || null,
    venueId: body.venueId || null,
    venueName: null,
    level: body.level || 'INTERMEDIATE',
    gender: body.gender || 'ANY',
    date: body.dateTime || body.date || null,
    imageUrls: [],
    maxParticipants: body.maxParticipants || 0,
    acceptedCount: 0,
    status: 'ACTIVE',
    ageMin: body.ageMin || null,
    ageMax: body.ageMax || null,
    isRecurring: body.isRecurring || false,
    isAnonymous: body.isAnonymous || false,
    isUrgent: body.isUrgent || false,
    isQuick: body.isQuick || false,
    responseCount: 0,
    userId: req.userId,
    userName: user?.name || null,
    userAvatar: user?.avatarUrl || null,
    createdAt: new Date().toISOString(),
    expiresAt: body.expiresAt || new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
  };
  store.listings.push(listing);
  res.status(201).json({ listing });
});

listingsRouter.post('/:id/interest', contentFilter('message'), (req, res) => {
  const listing = listingById(req.params.id);
  if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
  if (listing.userId === req.userId) {
    return res.status(400).json({ message: 'Kendi ilanınıza başvuramazsınız.' });
  }
  // Prevent duplicate interests
  const already = store.interests.find(i => i.listingId === listing.id && i.userId === req.userId);
  if (already) return res.json({ interested: true, count: listing.responseCount, responseId: already.id });

  const me = userById(req.userId);
  const interest = {
    id: uuid(),
    listingId: listing.id,
    userId: req.userId,
    userName: me?.name || null,
    userAvatar: me?.avatarUrl || null,
    message: req.body.message || null,
    status: 'PENDING',
    createdAt: new Date().toISOString(),
  };
  store.interests.push(interest);
  listing.responseCount = (listing.responseCount || 0) + 1;

  // Notify listing owner via pushNotification so WS new_notification event is fired
  pushNotification({
    userId: listing.userId,
    type: 'NEW_INTEREST',
    title: 'Yeni başvuru',
    body: `${me?.name || 'Birisi'} ilanınıza başvurdu.`,
    relatedId: listing.id,
    senderId: req.userId,
  });

  res.json({ interested: true, count: listing.responseCount, responseId: interest.id });
});

// Get interests for listing (all authenticated users can see applicants)
listingsRouter.get('/:id/interests', (req, res) => {
  const listing = listingById(req.params.id);
  if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });

  const pending = store.interests.filter(i => i.listingId === listing.id && i.status === 'PENDING');
  const result = pending.map(i => {
    const u = userById(i.userId);
    return {
      id: i.id,
      userId: i.userId,
      userName: u?.name || i.userName || null,
      userAvatar: u?.avatarUrl || i.userAvatar || null,
      message: listing.userId === req.userId ? i.message : null,
      status: i.status,
      createdAt: i.createdAt,
    };
  });
  res.json({ interests: result });
});

// Update listing (owner only)
listingsRouter.patch('/:id', contentFilter('description'), (req, res) => {
  const listing = listingById(req.params.id);
  if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
  if (listing.userId !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });

  const body = sanitizeObject(req.body);
  const allowed = ['level','gender','allowedGender','date','dateTime','description','maxParticipants',
                   'cityId','cityName','districtId','districtName'];
  for (const key of allowed) {
    if (body[key] !== undefined) {
      if (key === 'dateTime') { listing.date = body[key]; }
      else if (key === 'allowedGender') { listing.gender = body[key]; }
      else { listing[key] = body[key]; }
    }
  }
  res.json({ listing });
});

// Accept or reject an interest → accept creates a match
listingsRouter.patch('/:id/interests/:responseId', (req, res) => {
  const listing = listingById(req.params.id);
  if (!listing) return res.status(404).json({ message: 'İlan bulunamadı.' });
  if (listing.userId !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });

  const interest = store.interests.find(i => i.id === req.params.responseId);
  if (!interest) return res.status(404).json({ message: 'Başvuru bulunamadı.' });

  const { action } = req.body; // 'ACCEPTED' | 'REJECTED'
  if (action !== 'ACCEPTED' && action !== 'REJECTED') {
    return res.status(400).json({ message: "action 'ACCEPTED' veya 'REJECTED' olmalı." });
  }

  interest.status = action;

  if (action === 'ACCEPTED') {
    // Create a match
    const match = {
      id: uuid(),
      listingId: listing.id,
      source: 'LISTING',
      user1Id: listing.userId,
      user2Id: interest.userId,
      status: 'SCHEDULED',
      u1Approved: false,
      u2Approved: false,
      scheduledAt: listing.date || null,
      completedAt: null,
      createdAt: new Date().toISOString(),
      user1: safeUser(userById(listing.userId)),
      user2: safeUser(userById(interest.userId)),
      listing: { id: listing.id, type: listing.type, sportId: listing.sportId, sport: store.SPORTS.find(s => s.id === listing.sportId) },
    };
    store.matches.push(match);

    // Kota güncelle — kota dolunca MATCHED yap (hem RIVAL hem PARTNER)
    listing.acceptedCount = (listing.acceptedCount || 0) + 1;
    const isMatchEligible = listing.type === 'RIVAL' || listing.type === 'PARTNER';
    const slotsNeeded = Math.max(1, (listing.maxParticipants || 1) - 1);
    const isCapacityFull = listing.acceptedCount >= slotsNeeded;
    if (isMatchEligible && isCapacityFull) {
      listing.status = 'MATCHED';
      // Bekleyen diğer başvuruları otomatik reddet
      store.interests.forEach(i => {
        if (i.listingId === listing.id && i.id !== req.params.responseId && i.status === 'PENDING') {
          i.status = 'REJECTED';
        }
      });
      store.notifications.push({
        id: uuid(),
        userId: listing.userId,
        type: 'LISTING_MATCHED',
        title: 'Eşleşme Gerçekleşti! 🎉',
        body: `"${listing.title || listing.type}" ilanınızda eşleşme tamamlandı!`,
        relatedId: listing.id,
        senderId: req.userId,
        isRead: false,
        createdAt: new Date().toISOString(),
      });
    }

    // Notify the applicant
    const owner = userById(req.userId);
    pushNotification({
      userId: interest.userId,
      type: 'RESPONSE_ACCEPTED',
      title: 'Başvurunuz kabul edildi!',
      body: `${owner?.name || 'İlan sahibi'} başvurunuzu kabul etti. Yeni maçınız oluşturuldu!`,
      relatedId: match.id,
      senderId: req.userId,
    });
    return res.json({ data: { interest, match } });
  }

  // REJECTED
  const owner = userById(req.userId);
  pushNotification({
    userId: interest.userId,
    type: 'RESPONSE_REJECTED',
    title: 'Başvurunuz reddedildi',
    body: `${owner?.name || 'İlan sahibi'} başvurunuzu reddetti.`,
    relatedId: listing.id,
    senderId: req.userId,
  });
  res.json({ data: { interest } });
});

// DELETE /api/listings/:id — kullanıcı kendi ilanını silebilir
listingsRouter.delete('/:id', (req, res) => {
  const idx = store.listings.findIndex(l => l.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'İlan bulunamadı.' });
  if (store.listings[idx].userId !== req.userId) return res.status(403).json({ message: 'Yetkisiz.' });
  store.listings.splice(idx, 1);
  // İlgili başvuruları da sil
  store.interests = store.interests.filter(i => i.listingId !== req.params.id);
  res.json({ message: 'İlan silindi.' });
});

// DELETE /api/listings/:id/interest — kullanıcı kendi başvurusunu geri çekebilir
listingsRouter.delete('/:id/interest', (req, res) => {
  const idx = store.interests.findIndex(i => i.listingId === req.params.id && i.userId === req.userId);
  if (idx === -1) return res.status(404).json({ message: 'Başvuru bulunamadı.' });
  store.interests.splice(idx, 1);
  res.json({ message: 'Başvuru geri çekildi.' });
});

// ─── MATCHES ───────────────────────────────────────────────────────────────────
const matchesRouter = express.Router();
matchesRouter.use(authMiddleware);

// GET /api/matches — kullanıcının tüm maçları
matchesRouter.get('/', (req, res) => {
  const myMatches = store.matches.filter(
    m => m.user1Id === req.userId || m.user2Id === req.userId
  );
  res.json({ data: myMatches });
});

matchesRouter.get('/:id', (req, res) => {
  const match = store.matches.find(m => m.id === req.params.id);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });
  res.json({ data: match });
});

matchesRouter.post('/:id/complete', (req, res) => {
  const match = store.matches.find(m => m.id === req.params.id);
  if (match) match.status = 'COMPLETED';
  res.json({ data: match });
});

// PATCH /api/matches/:id/approve — kullanıcı kendi onayını verir
matchesRouter.patch('/:id/approve', (req, res) => {
  const match = store.matches.find(m => m.id === req.params.id);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });

  // Maç zaten tamamlanmış/iptal edilmişse idempotent dön (duplicate bildirimleri önler)
  if (match.status === 'COMPLETED' || match.status === 'CANCELLED') {
    return res.json({ data: match });
  }

  // Maç tarihi henüz gelmemişse onay vermeyi engelle
  const scheduledDate = match.scheduledAt
    ? new Date(match.scheduledAt)
    : (match.listingId
        ? (() => { const l = store.listings.find(li => li.id === match.listingId); return l?.dateTime ? new Date(l.dateTime) : null; })()
        : null);
  if (scheduledDate && scheduledDate > new Date()) {
    return res.status(400).json({ message: 'Maç tarihi henüz gelmedi. Onay vermek için maç tarihini beklemelisiniz.' });
  }

  const u1Id = match.user1Id || match.user1?.id;
  const u2Id = match.user2Id || match.user2?.id;

  if (u1Id === req.userId) {
    match.u1Approved = true;
  } else if (u2Id === req.userId) {
    match.u2Approved = true;
  } else {
    return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });
  }

  const listing = store.listings.find(l => l.id === match.listingId);
  const sport = listing ? (store.SPORTS.find(s => s.id === listing.sportId) || {}) : {};
  const sportName = sport.name || 'Spor';

  // Her iki taraf da onayladıysa maçı tamamla ve değerlendirme bildirimi gönder
  if (match.u1Approved && match.u2Approved) {
    match.status = 'COMPLETED';
    match.completedAt = new Date().toISOString();
    const u1 = store.users.find(u => u.id === u1Id);
    const u2 = store.users.find(u => u.id === u2Id);
    if (u1) { u1.totalMatches = (u1.totalMatches || 0) + 1; u1.totalPoints = (u1.totalPoints || 0) + 10; updateStreak(u1); }
    if (u2) { u2.totalMatches = (u2.totalMatches || 0) + 1; u2.totalPoints = (u2.totalPoints || 0) + 10; updateStreak(u2); }

    // Her iki kullanıcıya değerlendirme bildirimi gönder
    const ratingNotif = (targetId, senderName) => ({
      id: uuid(),
      userId: targetId,
      type: 'MATCH_COMPLETED',
      title: '⭐ Değerlendirme Zamanı!',
      body: `maçı oynadığını onayladı`,
      relatedId: match.id,
      senderName,
      isRead: false,
      createdAt: new Date().toISOString(),
    });
    if (u1 && u2) {
      // Kullanıcı daha önce bu maçı değerlendirmediyse bildirim gönder
      const u1AlreadyRated = store.ratings.some(r => r.matchId === match.id && r.raterId === u1Id);
      const u2AlreadyRated = store.ratings.some(r => r.matchId === match.id && r.raterId === u2Id);
      if (!u1AlreadyRated) store.notifications.push(ratingNotif(u1Id, u2.name));
      if (!u2AlreadyRated) store.notifications.push(ratingNotif(u2Id, u1.name));
      sendWsEvent(u1Id, 'match_completed', { matchId: match.id, message: `⭐ ${sportName} - ${u2.name} değerlendirmesini bekliyor!` });
      sendWsEvent(u2Id, 'match_completed', { matchId: match.id, message: `⭐ ${sportName} - ${u1.name} değerlendirmesini bekliyor!` });
    }
  } else {
    // Sadece bir taraf onayladı — diğerini bilgilendir
    const awaitingId = req.userId === u1Id ? u2Id : u1Id;
    const approverUser = store.users.find(u => u.id === req.userId);
    const approverName = approverUser?.name || 'Rakibin';
    store.notifications.push({
      id: uuid(),
      userId: awaitingId,
      type: 'MATCH_STATUS_CHANGED',
      title: `⚽ Maçı Oynadınız mı?`,
      body: `maçı oynadığını onayladı`,
      relatedId: match.id,
      senderId: req.userId,
      senderName: approverName,
      senderAvatar: approverUser?.avatarUrl || null,
      isRead: false,
      createdAt: new Date().toISOString(),
    });
    sendWsEvent(awaitingId, 'match_approval_pending', { matchId: match.id, from: approverName });
  }

  res.json({ data: match });
});

// ─── OTP DOĞRULAMA ─────────────────────────────────────────────────────────────
// POST /api/matches/:id/otp/request — 6 haneli kod üret ve rakibe gönder
matchesRouter.post('/:id/otp/request', (req, res) => {
  const match = store.matches.find(m => m.id === req.params.id);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });

  const u1Id = match.user1Id || match.user1?.id;
  const u2Id = match.user2Id || match.user2?.id;
  if (req.userId !== u1Id && req.userId !== u2Id) {
    return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });
  }
  if (match.status === 'COMPLETED' || match.status === 'CANCELLED') {
    return res.status(400).json({ message: 'Bu maç için OTP gönderilemez.' });
  }

  // 15 dakika geçerli OTP oluştur
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  store.otps.push({
    id: uuid(),
    matchId: match.id,
    requesterId: req.userId,
    code,
    expiresAt,
    usedAt: null,
    createdAt: new Date().toISOString(),
  });

  // Rakibe OTP bildirim gönder
  const otherId = req.userId === u1Id ? u2Id : u1Id;
  const requester = userById(req.userId);
  store.notifications.push({
    id: uuid(),
    userId: otherId,
    type: 'MATCH_OTP_REQUESTED',
    title: '🔐 Doğrulama Kodu İstendi',
    body: `${requester?.name || 'Rakibin'} maç doğrulaması için kod istedi.`,
    relatedId: match.id,
    senderId: req.userId,
    isRead: false,
    createdAt: new Date().toISOString(),
  });
  sendWsEvent(otherId, 'otp_requested', { matchId: match.id, from: requester?.name });

  // Dev modunda kodu response'a ekle (üretimde e-posta/SMS olur)
  res.json({ message: 'Doğrulama kodu oluşturuldu.', devCode: code, expiresAt });
});

// POST /api/matches/:id/otp/verify — Kod doğrula → trustScore artır
matchesRouter.post('/:id/otp/verify', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ message: 'Doğrulama kodu gerekli.' });

  const match = store.matches.find(m => m.id === req.params.id);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });

  const u1Id = match.user1Id || match.user1?.id;
  const u2Id = match.user2Id || match.user2?.id;
  if (req.userId !== u1Id && req.userId !== u2Id) {
    return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });
  }

  const now = new Date();
  const otp = store.otps.find(o =>
    o.matchId === match.id &&
    o.code === String(code) &&
    !o.usedAt &&
    new Date(o.expiresAt) > now,
  );
  if (!otp) {
    return res.status(400).json({ message: 'Geçersiz veya süresi dolmuş doğrulama kodu.' });
  }

  otp.usedAt = now.toISOString();
  match.trustScore = Math.min(100, (match.trustScore || 0) + 40);

  // Kodu isteyen kişiye bildirim gönder
  const verifier = userById(req.userId);
  store.notifications.push({
    id: uuid(),
    userId: otp.requesterId,
    type: 'MATCH_STATUS_CHANGED',
    title: '✅ Maç Doğrulandı',
    body: `${verifier?.name || 'Rakibin'} doğrulama kodunu onayladı.`,
    relatedId: match.id,
    senderId: req.userId,
    isRead: false,
    createdAt: new Date().toISOString(),
  });
  sendWsEvent(otp.requesterId, 'otp_verified', { matchId: match.id, trustScore: match.trustScore });

  res.json({ message: 'Maç doğrulandı.', trustScore: match.trustScore });
});

// ─── NO-SHOW RAPORU ────────────────────────────────────────────────────────────
// POST /api/matches/:id/noshow — Rakibim gelmedi raporu
matchesRouter.post('/:id/noshow', (req, res) => {
  const match = store.matches.find(m => m.id === req.params.id);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });

  const u1Id = match.user1Id || match.user1?.id;
  const u2Id = match.user2Id || match.user2?.id;
  if (req.userId !== u1Id && req.userId !== u2Id) {
    return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });
  }
  if (match.status === 'COMPLETED' || match.status === 'CANCELLED') {
    return res.status(400).json({ message: 'Tamamlanmış veya iptal edilmiş maç raporlanamaz.' });
  }

  // Zaten rapor ettiyse engelle
  const alreadyReported = store.noshows.find(
    n => n.matchId === match.id && n.reporterId === req.userId,
  );
  if (alreadyReported) {
    return res.status(409).json({ message: 'Bu maç için zaten rapor ettiniz.' });
  }

  const reportedId = req.userId === u1Id ? u2Id : u1Id;
  store.noshows.push({
    id: uuid(),
    matchId: match.id,
    reporterId: req.userId,
    reportedId,
    createdAt: new Date().toISOString(),
  });

  // u1Reported / u2Reported güncelle
  if (req.userId === u1Id) { match.u1Reported = true; }
  else { match.u2Reported = true; }

  // Her ikisi de raporladıysa maçı NO_SHOW yap
  if (match.u1Reported && match.u2Reported) {
    match.status = 'NO_SHOW';
  }

  // Raporlanan kişinin noShowCount'unu artır
  const reportedUser = userById(reportedId);
  if (reportedUser) {
    reportedUser.noShowCount = (reportedUser.noShowCount || 0) + 1;
  }

  // Raporlanan kişiye bildirim gönder
  const reporter = userById(req.userId);
  store.notifications.push({
    id: uuid(),
    userId: reportedId,
    type: 'NO_SHOW_WARNING',
    title: '⚠️ Gelmedi Raporu',
    body: `${reporter?.name || 'Rakibin'} maça gelmediğinizi bildirdi.`,
    relatedId: match.id,
    senderId: req.userId,
    isRead: false,
    createdAt: new Date().toISOString(),
  });
  sendWsEvent(reportedId, 'noshow_reported', { matchId: match.id, from: reporter?.name });

  res.json({ message: 'Rapor kaydedildi.', status: match.status });
});

// ─── CONVERSATIONS & MESSAGES ──────────────────────────────────────────────────
const convsRouter = express.Router();
convsRouter.use(authMiddleware);

convsRouter.post('/', (req, res) => {
  const { targetUserId } = req.body;
  if (!targetUserId) return res.status(400).json({ message: 'targetUserId gerekli.' });

  // Mesaj gönderme gizlilik kontrolü
  if (req.userId !== targetUserId) {
    const tPrivacy = normalizePrivacySettings(userPrivacy[targetUserId] || {});
    if (!canViewerSeeByVisibility(req.userId, targetUserId, tPrivacy.whoCanMessage)) {
      const msg = normalizeVisibility(tPrivacy.whoCanMessage, 'EVERYONE') === 'NOBODY'
        ? 'Bu kullanıcıya mesaj gönderilemiyor.'
        : 'Bu kullanıcı yalnızca takipçilerinden mesaj kabul ediyor.';
      return res.status(403).json({ message: msg });
    }
  }

  const conv = findOrCreateConversation(req.userId, targetUserId);
  res.status(201).json({ data: { id: conv.id } });
});

convsRouter.get('/', (req, res) => {
  const myConvs = store.conversations.filter(
    c => c.user1Id === req.userId || c.user2Id === req.userId
  ).sort(
    (a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0)
  ).map(c => {
    const otherId = c.user1Id === req.userId ? c.user2Id : c.user1Id;
    const other = userById(otherId);
    return {
      ...c,
      type: c.type || 'direct',
      hasUnread: !!(c.unreadFor && c.unreadFor[req.userId]),
      partner: other ? { id: other.id, name: other.name, avatarUrl: other.avatarUrl || null } : { id: otherId, name: 'Bilinmeyen', avatarUrl: null },
    };
  });
  res.json({ data: myConvs });
});

convsRouter.patch('/:id/read', (req, res) => {
  const conv = store.conversations.find(c => c.id === req.params.id);
  if (conv) {
    if (!conv.unreadFor) conv.unreadFor = {};
    conv.unreadFor[req.userId] = false;
  }
  res.json({ success: true });
});

convsRouter.get('/:id/messages', (req, res) => {
  const msgs = store.messages.filter(m => m.conversationId === req.params.id)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  res.json({ data: { messages: msgs, nextCursor: null } });
});

convsRouter.post('/:id/messages', contentFilter('content'), (req, res) => {
  const { content } = req.body;
  const msg = {
    id: uuid(),
    conversationId: req.params.id,
    senderId: req.userId,
    content,
    createdAt: new Date().toISOString(),
  };
  store.messages.push(msg);
  // Notify other party
  const conv = store.conversations.find(c => c.id === req.params.id);
  if (conv) {
    conv.lastMessage = msg;
    conv.updatedAt = msg.createdAt;
    const otherId = conv.user1Id === req.userId ? conv.user2Id : conv.user1Id;
    // Mark conversation as having unread messages for the recipient
    if (!conv.unreadFor) conv.unreadFor = {};
    conv.unreadFor[otherId] = true;
    sendWsEvent(otherId, 'new_message', msg);
  }
  res.status(201).json({ data: msg });
});

// ─── COMMUNITIES ───────────────────────────────────────────────────────────────
const commRouter = express.Router();
commRouter.use(authMiddleware);

// Format community for a specific user's perspective
function _formatComm(comm, userId) {
  const members = comm.members || [];
  const myMembership = members.find(m => m.userId === userId);
  const approvedCount = members.filter(m => m.status === 'APPROVED').length;
  const pendingCount  = members.filter(m => m.status === 'PENDING').length;
  const isAdmin = myMembership?.role === 'ADMIN';
  return {
    id: comm.id,
    type: comm.type,
    name: comm.name,
    description: comm.description,
    avatarUrl: comm.avatarUrl,
    website: comm.website,
    isPrivate: comm.isPrivate,
    sport: comm.sport,
    city: comm.city,
    _count: {
      members: approvedCount,
      posts: (comm.posts || []).length,
    },
    isMember: myMembership?.status === 'APPROVED',
    isPending: myMembership?.status === 'PENDING',
    isAdmin,
    ownerId: comm.ownerId,
    pendingCount: isAdmin ? pendingCount : 0,
    createdAt: comm.createdAt,
  };
}

// POST /api/communities — create
commRouter.post('/', contentFilter('name', 'description'), (req, res) => {
  const { name, type, description, isPrivate, sportId, website } = req.body;
  if (!name || !type) return res.status(400).json({ message: 'name ve type gerekli.' });
  const validTypes = ['GROUP', 'CLUB', 'TEAM'];
  if (!validTypes.includes(type)) return res.status(400).json({ message: 'Geçersiz tür. GROUP, CLUB veya TEAM olmalı.' });
  const me = userById(req.userId);
  if (!me) return res.status(401).json({ message: 'Yetkisiz.' });
  const sport = sportId ? store.SPORTS.find(s => s.id === sportId) : null;
  const community = {
    id: uuid(),
    type,
    name,
    description: description || null,
    avatarUrl: null,
    website: website || null,
    isPrivate: isPrivate || false,
    sport: sport ? { id: sport.id, name: sport.name, icon: sport.icon } : null,
    city: me?.city ? { id: String(me.city.id || 'c1'), name: me.city.name || String(me.city) } : null,
    ownerId: req.userId,
    createdAt: new Date().toISOString(),
    members: [{
      id: uuid(),
      userId: req.userId,
      role: 'ADMIN',
      status: 'APPROVED',
      joinedAt: new Date().toISOString(),
      user: { id: me.id, name: me.name, avatarUrl: me.avatarUrl || null }
    }],
    posts: [],
  };
  store.communities.push(community);
  res.status(201).json({ data: _formatComm(community, req.userId) });
});

// GET /api/communities — list with filters
commRouter.get('/', (req, res) => {
  const { type, search, myMemberships } = req.query;
  let result = store.communities.filter(c => {
    if (type   && c.type !== type) return false;
    if (search && !c.name.toLowerCase().includes(search.toLowerCase())) return false;
    if (myMemberships === 'true') {
      return (c.members || []).some(m => m.userId === req.userId && m.status === 'APPROVED');
    }
    return true;
  });
  res.json({ data: result.map(c => _formatComm(c, req.userId)), total: result.length });
});

// GET /api/communities/:id
commRouter.get('/:id', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  res.json({ data: _formatComm(comm, req.userId) });
});

// PATCH /api/communities/:id — edit (admin only)
commRouter.patch('/:id', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const myMember = (comm.members || []).find(m => m.userId === req.userId);
  if (!myMember || myMember.role !== 'ADMIN') return res.status(403).json({ message: 'Yetkiniz yok.' });
  const { name, description, website, isPrivate } = req.body;
  if (name !== undefined) comm.name = name;
  if (description !== undefined) comm.description = description;
  if (website !== undefined) comm.website = website;
  if (isPrivate !== undefined) comm.isPrivate = isPrivate;
  res.json({ data: _formatComm(comm, req.userId) });
});

// DELETE /api/communities/:id — delete (owner only)
commRouter.delete('/:id', (req, res) => {
  const idx = store.communities.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  if (store.communities[idx].ownerId !== req.userId) return res.status(403).json({ message: 'Yalnızca kurucu silebilir.' });
  store.communities.splice(idx, 1);
  res.json({ message: 'Topluluk silindi.' });
});

// POST /api/communities/:id/members — join
commRouter.post('/:id/members', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const existing = (comm.members || []).find(m => m.userId === req.userId && m.status !== 'REJECTED');
  if (existing) return res.status(409).json({ message: 'Zaten üyesiniz veya başvurunuz bekliyor.' });
  const me = userById(req.userId);
  const status = comm.isPrivate ? 'PENDING' : 'APPROVED';
  const membership = {
    id: uuid(),
    userId: req.userId,
    role: 'MEMBER',
    status,
    joinedAt: new Date().toISOString(),
    user: { id: me.id, name: me.name, avatarUrl: me.avatarUrl || null }
  };
  if (!comm.members) comm.members = [];
  comm.members.push(membership);
  res.status(201).json({ message: status === 'APPROVED' ? 'Katıldınız.' : 'İsteğiniz gönderildi.', status });
});

// DELETE /api/communities/:id/members — leave
commRouter.delete('/:id/members', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const idx = (comm.members || []).findIndex(m => m.userId === req.userId);
  if (idx !== -1) comm.members.splice(idx, 1);
  res.status(200).json({ message: 'Ayrıldınız.' });
});

// GET /api/communities/:id/members — list members
commRouter.get('/:id/members', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const myMembership = (comm.members || []).find(m => m.userId === req.userId);
  const isAdmin = myMembership?.role === 'ADMIN';
  const { status } = req.query;
  let members = comm.members || [];
  if (status === 'PENDING') {
    if (!isAdmin) return res.status(403).json({ message: 'Yetkiniz yok.' });
    members = members.filter(m => m.status === 'PENDING');
  } else {
    members = members.filter(m => m.status === 'APPROVED');
  }
  res.json({ data: members, isAdmin });
});

// PATCH /api/communities/:id/members/:membershipId — approve/reject/promote (admin)
commRouter.patch('/:id/members/:membershipId', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const myMembership = (comm.members || []).find(m => m.userId === req.userId);
  if (!myMembership || myMembership.role !== 'ADMIN') return res.status(403).json({ message: 'Yetkiniz yok.' });
  const member = (comm.members || []).find(m => m.id === req.params.membershipId);
  if (!member) return res.status(404).json({ message: 'Üye bulunamadı.' });
  const { status, role } = req.body;
  if (status) member.status = status;
  if (role)   member.role   = role;
  res.json({ data: member });
});

// DELETE /api/communities/:id/members/:membershipId — kick (admin)
commRouter.delete('/:id/members/:membershipId', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const myMembership = (comm.members || []).find(m => m.userId === req.userId);
  if (!myMembership || myMembership.role !== 'ADMIN') return res.status(403).json({ message: 'Yetkiniz yok.' });
  const idx = (comm.members || []).findIndex(m => m.id === req.params.membershipId);
  if (idx !== -1) comm.members.splice(idx, 1);
  res.json({ message: 'Üye çıkarıldı.' });
});

// GET /api/communities/:id/posts — community posts feed
commRouter.get('/:id/posts', (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  if (comm.isPrivate) {
    const myMembership = (comm.members || []).find(m => m.userId === req.userId && m.status === 'APPROVED');
    if (!myMembership) return res.status(403).json({ message: 'Bu topluluğun üyesi değilsiniz.' });
  }
  const posts = (comm.posts || []).slice().reverse();
  res.json({ data: posts, total: posts.length });
});

// POST /api/communities/:id/posts — create post in community
commRouter.post('/:id/posts', contentFilter('content'), (req, res) => {
  const comm = store.communities.find(c => c.id === req.params.id);
  if (!comm) return res.status(404).json({ message: 'Topluluk bulunamadı.' });
  const myMembership = (comm.members || []).find(m => m.userId === req.userId && m.status === 'APPROVED');
  if (!myMembership) return res.status(403).json({ message: 'Üye olmalısınız.' });
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ message: 'İçerik boş olamaz.' });
  const me = userById(req.userId);
  const post = {
    id: uuid(),
    content: content.trim(),
    communityId: comm.id,
    userId: req.userId,
    author: { id: me.id, name: me.name, avatarUrl: me.avatarUrl || null },
    likesCount: 0,
    commentsCount: 0,
    createdAt: new Date().toISOString(),
  };
  if (!comm.posts) comm.posts = [];
  comm.posts.push(post);
  res.status(201).json({ data: post });
});

// ─── GROUPS ────────────────────────────────────────────────────────────────────
const groupsRouter = express.Router();
groupsRouter.use(authMiddleware);

groupsRouter.get('/', (req, res) => {
  res.json({ groups: store.groups });
});

groupsRouter.get('/:id', (req, res) => {
  const group = store.groups.find(g => g.id === req.params.id);
  if (!group) return res.status(404).json({ message: 'Grup bulunamadı.' });
  res.json({ data: group });
});

groupsRouter.get('/:id/members', (req, res) => {
  const members = store.groupMembers.filter(m => m.groupId === req.params.id);
  res.json({ members });
});

groupsRouter.post('/:id/members', (req, res) => {
  const group = store.groups.find(g => g.id === req.params.id);
  if (group && group._count) group._count.members++;
  res.status(200).json({ message: 'Gruba katıldınız.' });
});

groupsRouter.delete('/:id/members', (req, res) => {
  const group = store.groups.find(g => g.id === req.params.id);
  if (group && group._count) group._count.members = Math.max(0, group._count.members - 1);
  res.status(200).json({ message: 'Gruptan ayrıldınız.' });
});

// ─── USERS (public profile + follow/block) ─────────────────────────────────────
const usersRouter = express.Router();
usersRouter.use(authMiddleware);

usersRouter.get('/:id', (req, res) => {
  const user = userById(req.params.id);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

  // Compute follow status for the requesting user
  const follow = store.follows.find(
    f => f.followerId === req.userId && f.followingId === user.id,
  );
  const isBlockedByMe = store.blockedUsers.some(
    b => b.blockerId === req.userId && b.blockedId === user.id,
  );

  // Bot private profile: show limited data but include social links (non-clickable) + ratings
  if (user.isBot && user.isPrivate && req.userId !== user.id) {
    const socialLinks = {};
    for (const p of ['instagram', 'tiktok', 'facebook', 'twitter', 'youtube', 'linkedin',
      'discord', 'twitch', 'snapchat', 'telegram', 'whatsapp', 'vk', 'litmatch']) {
      socialLinks[p] = user[p] || null;
    }
    return res.json({
      data: {
        id: user.id,
        name: user.name,
        username: user.username,
        avatarUrl: user.avatarUrl,
        coverUrl: user.coverUrl,
        bio: user.bio,
        followerCount: user.followerCount || 0,
        followersCount: user.followerCount || 0,
        followingCount: user.followingCount || 0,
        totalMatches: user.totalMatches || 0,
        sports: user.sports || [],
        level: user.level,
        gender: user.gender,
        avgRating: user.averageRating || 0,
        ratingCount: user.ratingCount || 0,
        isPrivateProfile: true,
        isRestricted: true,
        isBot: true,
        socialLinksVisible: true,    // Links gösterilir ama tıklanamaz
        socialLinksClickable: false, // Frontend bu flag'e göre disabled yapar
        ...socialLinks,
        isFollowing: follow?.status === 'accepted',
        isPending: follow?.status === 'pending',
        isBlockedByMe: false,
      },
    });
  }

  const privacy = normalizePrivacySettings(userPrivacy[user.id] || privacyDefaults());

  // Profil görünürlüğü kontrolü — sahibi her zaman görebilir
  // Instagram mantığı: gizli profil 403 vermiyor, kısıtlı veri döner
  if (req.userId !== user.id && !canViewerSeeByVisibility(req.userId, user.id, privacy.profileVisibility)) {
    return res.json({
      data: {
        id: user.id,
        name: user.name,
        username: user.username,
        avatarUrl: user.avatarUrl,
        coverUrl: user.coverUrl,
        followerCount: user.followerCount || 0,
        followersCount: user.followerCount || 0,
        followingCount: user.followingCount || 0,
        totalMatches: user.totalMatches || 0,
        sports: user.sports || [],
        avgRating: user.averageRating || 0,
        ratingCount: user.ratingCount || 0,
        isPrivateProfile: privacy.isPrivateProfile === true || privacy.profileVisibility === 'FOLLOWERS_ONLY',
        isRestricted: true,
        isFollowing: follow?.status === 'accepted',
        isPending: follow?.status === 'pending',
        isBlockedByMe: false,
      },
    });
  }

  const withSocialPrivacy = { ...safeUser(user) };
  for (const platform of SOCIAL_PLATFORMS) {
    const canSee = canViewerSeeByVisibility(
      req.userId,
      user.id,
      privacy.socialPlatformVisibility[platform],
    );
    if (!canSee) withSocialPrivacy[platform] = null;
  }
  res.json({
    data: {
      ...withSocialPrivacy,
      followersCount: user.followerCount || 0,
      avgRating: user.averageRating || 0,
      ratingCount: user.ratingCount || 0,
      isFollowing: follow?.status === 'accepted',
      isPending: follow?.status === 'pending',
      isBlockedByMe,
    },
  });
});

usersRouter.post('/:id/follow', (req, res) => {
  const targetId = req.params.id;
  if (targetId === req.userId) return res.status(400).json({ message: 'Kendini takip edemezsin.' });

  const existing = store.follows.find(
    f => f.followerId === req.userId && f.followingId === targetId,
  );
  if (existing) {
    // Unfollow (or cancel pending)
    store.follows.splice(store.follows.indexOf(existing), 1);
    if (existing.status === 'accepted') {
      const target = userById(targetId);
      const me = userById(req.userId);
      if (target) target.followerCount = Math.max(0, (target.followerCount || 1) - 1);
      if (me) me.followingCount = Math.max(0, (me.followingCount || 1) - 1);
    }
    return res.json({ following: false, pending: false });
  }

  const target = userById(targetId);
  if (!target) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

  const status = target.isPrivate ? 'pending' : 'accepted';
  store.follows.push({
    id: uuid(), followerId: req.userId, followingId: targetId, status,
    createdAt: new Date().toISOString(),
  });

  if (status === 'accepted') {
    if (target) target.followerCount = (target.followerCount || 0) + 1;
    const me = userById(req.userId);
    if (me) me.followingCount = (me.followingCount || 0) + 1;
  }

  // Notify target
  const me = userById(req.userId);
  store.notifications.push({
    id: uuid(),
    userId: targetId,
    type: status === 'pending' ? 'FOLLOW_REQUEST' : 'NEW_FOLLOWER',
    title: status === 'pending' ? 'Yeni takip isteği' : 'Seni takip etmeye başladı',
    body: `${me?.name || 'Birisi'} ${status === 'pending' ? 'seni takip etmek istiyor' : 'seni takip etmeye başladı'}.`,
    relatedId: req.userId,
    isRead: false,
    createdAt: new Date().toISOString(),
    senderId: req.userId,
    senderName: me?.name,
    senderAvatar: me?.avatarUrl,
  });

  res.json({ following: status === 'accepted', pending: status === 'pending' });
});

usersRouter.get('/:id/followers', (req, res) => {
  const userId = req.params.id;
  const accepted = store.follows.filter(
    f => f.followingId === userId && f.status === 'accepted',
  );
  const result = accepted.map(f => {
    const follower = userById(f.followerId);
    if (!follower) return null;
    const reverseFollow = store.follows.find(
      r => r.followerId === req.userId && r.followingId === f.followerId,
    );
    return {
      id: f.id,
      user: safeUser(follower),
      isFollowingBack: reverseFollow?.status === 'accepted',
      pendingFollow: reverseFollow?.status === 'pending',
      createdAt: f.createdAt,
    };
  }).filter(Boolean);
  res.json({ data: result });
});

usersRouter.get('/:id/following', (req, res) => {
  const userId = req.params.id;
  const accepted = store.follows.filter(
    f => f.followerId === userId && f.status === 'accepted',
  );
  const result = accepted.map(f => {
    const followed = userById(f.followingId);
    if (!followed) return null;
    const reverseFollow = store.follows.find(
      r => r.followerId === req.userId && r.followingId === f.followingId,
    );
    return {
      id: f.id,
      user: safeUser(followed),
      isFollowingBack: reverseFollow?.status === 'accepted',
      pendingFollow: reverseFollow?.status === 'pending',
      createdAt: f.createdAt,
    };
  }).filter(Boolean);
  res.json({ data: result });
});

// Remove a follower from MY followers (the :id user stops following me)
usersRouter.delete('/:id/followers', (req, res) => {
  const followerId = req.params.id;
  const idx = store.follows.findIndex(
    f => f.followerId === followerId && f.followingId === req.userId && f.status === 'accepted',
  );
  if (idx === -1) return res.status(404).json({ message: 'Takipçi bulunamadı.' });
  store.follows.splice(idx, 1);
  const me = userById(req.userId);
  const follower = userById(followerId);
  if (me) me.followerCount = Math.max(0, (me.followerCount || 1) - 1);
  if (follower) follower.followingCount = Math.max(0, (follower.followingCount || 1) - 1);
  res.json({ message: 'Takipçi kaldırıldı.' });
});

usersRouter.post('/:id/block', (req, res) => {
  const targetId = req.params.id;
  if (targetId === req.userId) return res.status(400).json({ message: 'Kendini engelleyemezsin.' });
  const already = store.blockedUsers.some(b => b.blockerId === req.userId && b.blockedId === targetId);
  if (!already) {
    store.blockedUsers.push({ id: uuid(), blockerId: req.userId, blockedId: targetId, createdAt: new Date().toISOString() });
  }
  // Remove any follow relationships between these users
  const indicesToRemove = [];
  store.follows.forEach((f, i) => {
    if ((f.followerId === req.userId && f.followingId === targetId) ||
        (f.followerId === targetId && f.followingId === req.userId)) {
      indicesToRemove.push(i);
    }
  });
  for (let i = indicesToRemove.length - 1; i >= 0; i--) {
    store.follows.splice(indicesToRemove[i], 1);
  }
  res.json({ message: 'Kullanıcı engellendi.' });
});

usersRouter.delete('/:id/block', (req, res) => {
  const targetId = req.params.id;
  const idx = store.blockedUsers.findIndex(b => b.blockerId === req.userId && b.blockedId === targetId);
  if (idx !== -1) store.blockedUsers.splice(idx, 1);
  res.json({ message: 'Engel kaldırıldı.' });
});

usersRouter.post('/:id/report', (req, res) => {
  const targetId = req.params.id;
  const { reason, description } = req.body;
  store.reports.push({
    id: uuid(),
    reporterId: req.userId,
    reportedId: targetId,
    reason: reason || 'OTHER',
    description: description || null,
    createdAt: new Date().toISOString(),
  });
  res.json({ message: 'Şikayet alındı.' });
});

// ─── REFERRAL ─────────────────────────────────────────────────────────────────
// GET /api/users/me/referral — kendi referral bilgilerini getir
usersRouter.get('/me/referral', (req, res) => {
  const user = userById(req.userId);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  if (!user.referralCode) {
    user.referralCode = `SP${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
  }
  const referred = store.users.filter(u => u.referredBy === user.referralCode);
  res.json({
    referralCode: user.referralCode,
    referralCount: referred.length,
    referralPoints: referred.length * 50, // her davet 50 puan
    referredUsers: referred.map(u => ({ id: u.id, name: u.name, avatarUrl: u.avatarUrl, createdAt: u.createdAt })),
  });
});

// ─── FOLLOWS (requests + respond) ─────────────────────────────────────────────
const followsRouter = express.Router();
followsRouter.use(authMiddleware);

// GET /api/follows/requests — pending requests sent TO the current user
followsRouter.get('/requests', (req, res) => {
  const pending = store.follows.filter(
    f => f.followingId === req.userId && f.status === 'pending',
  );
  const result = pending.map(f => {
    const sender = userById(f.followerId);
    if (!sender) return null;
    return {
      id: f.id,
      follower: safeUser(sender),
      createdAt: f.createdAt,
    };
  }).filter(Boolean);
  res.json({ data: result });
});

// PATCH /api/follows/:id — accept or reject a follow request
followsRouter.patch('/:id', (req, res) => {
  const { action } = req.body; // "ACCEPTED" | "REJECTED"
  const follow = store.follows.find(f => f.id === req.params.id);
  if (!follow) return res.status(404).json({ message: 'İstek bulunamadı.' });
  if (follow.followingId !== req.userId) {
    return res.status(403).json({ message: 'Bu isteği yanıtlama yetkiniz yok.' });
  }

  if (action === 'ACCEPTED') {
    follow.status = 'accepted';
    const target = userById(follow.followingId);
    const follower = userById(follow.followerId);
    if (target) target.followerCount = (target.followerCount || 0) + 1;
    if (follower) follower.followingCount = (follower.followingCount || 0) + 1;
    // Notify the person whose request was accepted
    const me = userById(req.userId);
    store.notifications.push({
      id: uuid(),
      userId: follow.followerId,
      type: 'FOLLOW_ACCEPTED',
      title: 'Takip isteğin kabul edildi',
      body: `${me?.name || 'Birisi'} takip isteğini kabul etti.`,
      relatedId: req.userId,
      isRead: false,
      createdAt: new Date().toISOString(),
    });
    res.json({ message: 'İstek kabul edildi.', follow });
  } else {
    // Rejected — just remove it
    store.follows.splice(store.follows.indexOf(follow), 1);
    res.json({ message: 'İstek reddedildi.' });
  }
});

// ─── FEED ─────────────────────────────────────────────────────────────────────
app.get('/api/feed', authMiddleware, (req, res) => {
  const items = store.listings.filter(l => l.status === 'ACTIVE').slice(0, 20).map(l => ({
    id: uuid(),
    type: 'listing',
    listing: l,
    createdAt: l.createdAt,
  }));
  res.json({ data: items, pagination: { page: 1, hasNext: false } });
});

// ─── RECOMMENDATIONS ──────────────────────────────────────────────────────────
app.get('/api/recommendations', authMiddleware, (req, res) => {
  const items = store.listings.filter(l => l.status === 'ACTIVE').slice(0, 5).map(l => ({
    id: uuid(),
    type: 'listing',
    listing: l,
    createdAt: l.createdAt,
  }));
  res.json({ data: items, reason: 'Spor tercihlerinize göre' });
});

// ─── SEARCH ───────────────────────────────────────────────────────────────────
app.get('/api/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const matchedListings = store.listings.filter(l =>
    l.title.toLowerCase().includes(q) || (l.description || '').toLowerCase().includes(q)
  );
  const matchedUsers = store.users.filter(u =>
    u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q)
  ).map(safeUser);
  const matchedSports = store.SPORTS.filter(s => s.name.toLowerCase().includes(q));
  res.json({ data: { listings: matchedListings, users: matchedUsers, sports: matchedSports, clubs: [], groups: [] } });
});

// ─── LEADERBOARD ──────────────────────────────────────────────────────────────
app.get('/api/leaderboard', authMiddleware, (req, res) => {
  const ranked = [...store.users]
    .filter(u => !u.isBot && !u.isBanned)
    .sort((a, b) => (b.totalPoints || 0) - (a.totalPoints || 0))
    .slice(0, 20)
    .map((u, i) => {
      const { password, ...safe } = u;
      return {
        ...safe,
        avgRating: u.averageRating || 0,
        ratingCount: u.ratingCount || 0,
        rank: i + 1,
      };
    });
  res.json({ ranked });
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
app.get('/api/notifications', authMiddleware, (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const allNotifs = store.notifications
    .filter(n => n.userId === req.userId)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map(n => ({ ...n, read: !!n.isRead }));
  const unread   = allNotifs.filter(n => !n.isRead).length;
  const total    = allNotifs.length;
  const start    = (page - 1) * limit;
  const data     = allNotifs.slice(start, start + limit);
  const hasMore  = start + limit < total;
  res.json({ data, unreadCount: unread, total, hasMore, page });
});

app.patch('/api/notifications', authMiddleware, (req, res) => {
  const { ids, all } = req.body;
  if (all) {
    store.notifications.filter(n => n.userId === req.userId).forEach(n => { n.isRead = true; });
  } else if (ids) {
    ids.forEach(id => {
      const n = store.notifications.find(n => n.id === id && n.userId === req.userId);
      if (n) n.isRead = true;
    });
  }
  res.json({ message: 'Okundu olarak işaretlendi.' });
});

// ─── CHALLENGES ───────────────────────────────────────────────────────────────
const challengesRouter = express.Router();
challengesRouter.use(authMiddleware);

function findDistrictById(id) {
  if (!id) return null;
  const allDistricts = Object.values(store.DISTRICTS || {}).flat();
  return allDistricts.find(x => x.id === id) || null;
}

function areUsersBlocked(userAId, userBId) {
  return store.blockedUsers.some(
    b =>
      (b.blockerId === userAId && b.blockedId === userBId) ||
      (b.blockerId === userBId && b.blockedId === userAId),
  );
}

function isAcceptedFollower(followerId, followingId) {
  return store.follows.some(
    f =>
      f.followerId === followerId &&
      f.followingId === followingId &&
      f.status === 'accepted',
  );
}

function createMatchFromAcceptedChallenge(challenge) {
  const challenger = userById(challenge.senderId);
  const target = userById(challenge.targetId);
  const sport = store.SPORTS.find(s => s.id === challenge.sportId);
  const district = findDistrictById(
    challenge.districtId || challenger?.districtId || target?.districtId,
  );
  const scheduledAt =
    challenge.proposedDateTime ||
    new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const createdAt = new Date().toISOString();
  findOrCreateConversation(challenge.senderId, challenge.targetId);

  const listing = {
    id: uuid(),
    type: challenge.challengeType,
    title: `${sport?.name || 'Spor'} ${challenge.challengeType === 'RIVAL' ? 'rakip' : 'partner'} teklifi`,
    description:
      challenge.message ||
      `${challenger?.name || 'Bir kullanıcı'} tarafından gönderilen teklif üzerinden oluşturuldu.`,
    sportId: challenge.sportId,
    sportName: sport?.name || 'Spor',
    cityId: district?.cityId || challenger?.cityId || target?.cityId || null,
    cityName:
      district?.city?.name ||
      district?.cityName ||
      challenger?.city ||
      target?.city ||
      null,
    districtId: district?.id || null,
    districtName: district?.name || challenger?.district || target?.district || null,
    venueId: null,
    venueName: null,
    level: challenger?.level || target?.level || 'BEGINNER',
    gender: 'ANY',
    date: scheduledAt,
    imageUrls: [],
    status: 'MATCHED',
    ageMin: null,
    ageMax: null,
    isRecurring: false,
    isAnonymous: false,
    isUrgent: false,
    isQuick: false,
    responseCount: 1,
    acceptedCount: 1,
    maxParticipants: challenge.challengeType === 'PARTNER' ? 2 : 1,
    userId: challenge.senderId,
    userName: challenger?.name || 'Kullanıcı',
    userAvatar: challenger?.avatarUrl || null,
    createdAt,
  };
  store.listings.push(listing);

  const match = {
    id: uuid(),
    listingId: listing.id,
    user1Id: challenge.senderId,
    user2Id: challenge.targetId,
    status: 'SCHEDULED',
    source: 'CHALLENGE',
    u1Approved: false,
    u2Approved: false,
    scheduledAt,
    completedAt: null,
    createdAt,
    user1: challenger ? safeUser(challenger) : null,
    user2: target ? safeUser(target) : null,
    listing: {
      id: listing.id,
      type: listing.type,
      description: listing.description,
      dateTime: listing.date,
      sport: sport
        ? { id: sport.id, name: sport.name, icon: sport.icon || '🏅' }
        : null,
      district: district
        ? {
            name: district.name,
            city: { name: district.city?.name || district.cityName || listing.cityName || '' },
          }
        : null,
    },
  };
  store.matches.push(match);

  return { challenger, target, sport, match };
}

// Helper: enrich a raw challenge with user/sport/district details
function enrichChallenge(c) {
  const challenger = userById(c.senderId);
  const target = userById(c.targetId);
  const sport = store.SPORTS.find(s => s.id === c.sportId);
  let district = null;
  if (c.districtId) {
    const d = findDistrictById(c.districtId);
    if (d) {
      const cityName = d.cityName || d.city?.name || d.city || '';
      district = { id: d.id, name: d.name, city: { name: cityName } };
    }
  }
  const createdAt = c.createdAt || new Date().toISOString();
  const expiresAt = c.expiresAt || new Date(new Date(createdAt).getTime() + 48 * 60 * 60 * 1000).toISOString();
  return {
    id: c.id,
    challengeType: c.challengeType || 'RIVAL',
    status: c.status || 'PENDING',
    message: c.message || null,
    proposedDateTime: c.proposedDateTime || null,
    createdAt,
    expiresAt,
    challenger: challenger ? { id: challenger.id, name: challenger.name, avatarUrl: challenger.avatarUrl || null, userLevel: challenger.userLevel || null } : null,
    target: target ? { id: target.id, name: target.name, avatarUrl: target.avatarUrl || null, userLevel: target.userLevel || null } : null,
    sport: sport ? { id: sport.id, name: sport.name, icon: sport.icon || null } : null,
    district,
  };
}

challengesRouter.get('/', (req, res) => {
  const { direction } = req.query;
  let result;
  if (direction === 'sent') {
    // Gönderilen teklifler: tüm durumları göster (PENDING, ACCEPTED, REJECTED, EXPIRED)
    result = store.challenges.filter(c => c.senderId === req.userId);
  } else {
    // Alınan teklifler: sadece aktif (PENDING + süresi dolmamış)
    result = store.challenges.filter(c => {
      const expiresAt = new Date(c.expiresAt || 0);
      return c.status === 'PENDING' && expiresAt > new Date();
    });
    if (direction === 'received') result = result.filter(c => c.targetId === req.userId);
  }
  result = result.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  res.json({ data: result.map(enrichChallenge) });
});

challengesRouter.post('/', contentFilter('message'), (req, res) => {
  const targetId = req.body.targetId;
  const sportId = req.body.sportId;
  if (!targetId || !sportId) {
    return res.status(400).json({ message: 'Hedef kullanıcı ve spor gerekli.' });
  }
  if (targetId === req.userId) {
    return res.status(400).json({ message: 'Kendinize teklif gönderemezsiniz.' });
  }

  const target = userById(targetId);
  if (!target) {
    return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  }
  if (target.isBanned) {
    return res.status(403).json({ message: 'Bu kullanıcıya teklif gönderemezsiniz.' });
  }
  if (areUsersBlocked(req.userId, targetId)) {
    return res.status(403).json({ message: 'Bu kullanıcıya teklif gönderemezsiniz.' });
  }

  // whoCanChallenge doğru kaynaktan oku: userPrivacy store
  const targetPrivacy = normalizePrivacySettings(userPrivacy[targetId] || {});
  if (!canViewerSeeByVisibility(req.userId, targetId, targetPrivacy.whoCanChallenge)) {
    const isNobody = normalizeVisibility(targetPrivacy.whoCanChallenge, 'EVERYONE') === 'NOBODY';
    return res.status(403).json({
      message: isNobody
        ? 'Bu kullanıcı teklif kabul etmiyor.'
        : 'Bu kullanıcı yalnızca takipçilerinden teklif kabul ediyor.',
    });
  }

  const duplicatePending = store.challenges.find(
    c =>
      c.senderId === req.userId &&
      c.targetId === targetId &&
      c.sportId === sportId &&
      c.status === 'PENDING' &&
      new Date(c.expiresAt || 0) > new Date(),
  );
  if (duplicatePending) {
    return res.status(409).json({ message: 'Bu spor için zaten bekleyen bir teklifiniz var.' });
  }

  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
  const challenge = {
    id: uuid(),
    senderId: req.userId,
    targetId,
    sportId,
    challengeType: req.body.challengeType === 'PARTNER' ? 'PARTNER' : 'RIVAL',
    message: req.body.message || null,
    proposedDateTime: req.body.proposedDateTime || null,
    districtId: req.body.districtId || null,
    status: 'PENDING',
    createdAt,
    expiresAt,
  };
  store.challenges.push(challenge);
  const me = userById(req.userId);
  const sport = store.SPORTS.find(s => s.id === sportId);
  pushNotification({
    userId: targetId,
    type: 'DIRECT_CHALLENGE',
    title: `${challenge.challengeType === 'RIVAL' ? '⚔️ Rakip' : '🤝 Partner'} Teklifi!`,
    body: `${me?.name || 'Bir kullanıcı'} sana ${sport?.icon || ''} ${sport?.name || 'spor'} için ${challenge.challengeType === 'RIVAL' ? 'rakip' : 'partner'} teklifi gönderdi.`,
    relatedId: challenge.id,
    link: '/challenges',
    senderId: req.userId,
    senderName: me?.name,
    senderAvatar: me?.avatarUrl,
  });
  res.status(201).json({ data: enrichChallenge(challenge) });
});

challengesRouter.patch('/:id', (req, res) => {
  const challenge = store.challenges.find(c => c.id === req.params.id);
  if (!challenge) return res.status(404).json({ message: 'Teklif bulunamadı.' });
  if (challenge.targetId !== req.userId) {
    return res.status(403).json({ message: 'Bu teklif size ait değil.' });
  }
  if (challenge.status !== 'PENDING') {
    return res.status(400).json({ message: 'Bu teklif zaten yanıtlandı.' });
  }
  if (new Date(challenge.expiresAt || 0) <= new Date()) {
    challenge.status = 'EXPIRED';
    return res.status(400).json({ message: 'Bu teklifin süresi doldu.' });
  }

  const action = String(req.body.action || '').toUpperCase();
  if (action !== 'ACCEPTED' && action !== 'REJECTED') {
    return res.status(400).json({ message: 'Geçersiz işlem.' });
  }

  challenge.status = action;

  if (action === 'ACCEPTED') {
    const { sport, match } = createMatchFromAcceptedChallenge(challenge);
    const accepter = userById(req.userId);
    pushNotification({
      userId: challenge.senderId,
      type: 'NEW_MATCH',
      title: '🎮 Eşleşme Sağlandı!',
      body: `${accepter?.name || 'Bir kullanıcı'} ${sport?.icon || ''} ${sport?.name || 'spor'} teklifinizi kabul etti.`,
      relatedId: match.id,
      link: `/matches/${match.id}`,
      senderId: req.userId,
      senderName: accepter?.name,
      senderAvatar: accepter?.avatarUrl,
    });
    sendWsEvent(challenge.senderId, 'new_match', { matchId: match.id });
    return res.json({
      data: {
        challenge: enrichChallenge(challenge),
        matchId: match.id,
        matchCreated: true,
        action,
      },
    });
  }

  const rejecter = userById(req.userId);
  const sport = store.SPORTS.find(s => s.id === challenge.sportId);
  pushNotification({
    userId: challenge.senderId,
    type: 'DIRECT_CHALLENGE',
    title: '❌ Teklif Reddedildi',
    body: `${rejecter?.name || 'Bir kullanıcı'} ${sport?.name || 'spor'} teklifinizi reddetti.`,
    relatedId: challenge.targetId,
    link: `/users/${challenge.targetId}`,
    senderId: req.userId,
    senderName: rejecter?.name,
    senderAvatar: rejecter?.avatarUrl,
  });
  res.json({
    data: {
      challenge: enrichChallenge(challenge),
      matchCreated: false,
      action,
    },
  });
});

challengesRouter.delete('/:id', (req, res) => {
  const idx = store.challenges.findIndex(
    c => c.id === req.params.id && c.senderId === req.userId,
  );
  if (idx === -1) return res.status(404).json({ message: 'Teklif bulunamadı.' });
  const challenge = store.challenges[idx];
  if (challenge.status !== 'PENDING') {
    return res.status(400).json({ message: 'Yalnızca beklemedeki teklifler silinebilir.' });
  }
  store.challenges.splice(idx, 1);
  res.json({ message: 'Teklif silindi.' });
});

// ─── ACTIVITIES ───────────────────────────────────────────────────────────────
app.get('/api/aktivitelerim', authMiddleware, (req, res) => {
  const myListings = store.listings.filter(l => l.userId === req.userId).map(l => {
    const pendingInterests = store.interests.filter(i => i.listingId === l.id && i.status === 'PENDING');
    const responses = pendingInterests.map(i => {
      const u = userById(i.userId);
      return { id: i.id, message: i.message, user: u ? safeUser(u) : null };
    });
    const sport = store.SPORTS.find(s => s.id === l.sportId);
    const districtObj = l.districtId
      ? Object.values(store.DISTRICTS).flat().find(d => d.id === l.districtId) || null
      : null;
    return {
      ...l,
      dateTime: l.date,
      sport: sport ? { id: sport.id, name: sport.name, icon: sport.icon } : null,
      district: districtObj,
      _count: { responses: l.responseCount || 0 },
      responses,
    };
  });

  // Responses I sent as an applicant
  const myInterests = store.interests.filter(i => i.userId === req.userId).map(i => {
    const listing = listingById(i.listingId);
    if (!listing) return null;
    const sport = store.SPORTS.find(s => s.id === listing.sportId);
    const district = listing.districtId
      ? Object.values(store.DISTRICTS).flat().find(d => d.id === listing.districtId) || null
      : null;
    const owner = userById(listing.userId);
    return {
      id: i.id,
      status: i.status,
      message: i.message,
      createdAt: i.createdAt,
      listing: {
        id: listing.id,
        type: listing.type,
        status: listing.status,
        dateTime: listing.date,
        sport: sport || null,
        district,
        user: owner ? safeUser(owner) : null,
      },
    };
  }).filter(Boolean);

  const myMatches = store.matches
    .filter(m => m.user1Id === req.userId || m.user2Id === req.userId)
    .map(m => {
      const u1 = userById(m.user1Id);
      const u2 = userById(m.user2Id);
      const listing = listingById(m.listingId);
      const sport = listing ? store.SPORTS.find(s => s.id === listing.sportId) : null;
      return {
        ...m,
        source: m.source || 'LISTING',
        user1: u1 ? { id: u1.id, name: u1.name, avatarUrl: u1.avatarUrl } : null,
        user2: u2 ? { id: u2.id, name: u2.name, avatarUrl: u2.avatarUrl } : null,
        listing: listing
          ? { id: listing.id, type: listing.type, sport: sport || null }
          : null,
      };
    });

  res.json({ listings: myListings, responses: myInterests, matches: myMatches });
});

// ─── RATINGS ──────────────────────────────────────────────────────────────────
app.post('/api/ratings', authMiddleware, (req, res) => {
  const { matchId, score, comment } = req.body;
  if (!matchId || score == null) {
    return res.status(400).json({ message: 'matchId ve score gerekli.' });
  }
  const s = parseInt(score, 10);
  if (isNaN(s) || s < 1 || s > 5) {
    return res.status(400).json({ message: 'Puan 1-5 arasında olmalı.' });
  }
  const match = store.matches.find(m => m.id === matchId);
  if (!match) return res.status(404).json({ message: 'Maç bulunamadı.' });
  if (match.status !== 'COMPLETED') {
    return res.status(400).json({ message: 'Değerlendirme yalnızca tamamlanan maçlar için yapılabilir.' });
  }

  const u1Id = match.user1Id || match.user1?.id;
  const u2Id = match.user2Id || match.user2?.id;
  if (req.userId !== u1Id && req.userId !== u2Id) {
    return res.status(403).json({ message: 'Bu maçın katılımcısı değilsiniz.' });
  }

  // Aynı maç için 1 değerlendirme
  const alreadyRated = store.ratings.find(r => r.matchId === matchId && r.raterId === req.userId);
  if (alreadyRated) {
    return res.status(409).json({ message: 'Bu maç için zaten değerlendirme yaptınız.' });
  }

  // Aynı kişiye 24 saatte 1 değerlendirme
  const rateeId = req.userId === u1Id ? u2Id : u1Id;

  // Aynı spor dalında aynı kişiye sadece 1 yorum — zaten varsa güncelle
  const listingSport = store.listings.find(l => l.id === match.listingId);
  const sportId = match.sportId || listingSport?.sportId || null;
  const existingSportRating = sportId
    ? store.ratings.find(r => r.raterId === req.userId && r.rateeId === rateeId && r.sportId === sportId)
    : null;
  if (existingSportRating) {
    // Edit existing rating (don't create new)
    existingSportRating.score = s;
    existingSportRating.comment = comment || existingSportRating.comment;
    existingSportRating.matchId = matchId;
    existingSportRating.updatedAt = new Date().toISOString();
    // Recalculate ratee average
    const ratee = userById(rateeId);
    if (ratee) {
      const allRatingsForRatee = store.ratings.filter(r => r.rateeId === rateeId);
      const total = allRatingsForRatee.reduce((sum, r) => sum + r.score, 0);
      ratee.averageRating = parseFloat((total / allRatingsForRatee.length).toFixed(2));
    }
    return res.status(200).json({
      data: existingSportRating,
      message: 'Aynı spor dalında mevcut değerlendirmeniz güncellendi.',
    });
  }

  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const recentFromSamePair = store.ratings.find(r =>
    r.raterId === req.userId && r.rateeId === rateeId &&
    new Date(r.createdAt) > yesterday
  );
  if (recentFromSamePair) {
    return res.status(429).json({ message: 'Aynı kullanıcıyı 24 saat içinde sadece bir kez değerlendirebilirsiniz.' });
  }

  const ratee = userById(rateeId);
  if (ratee) {
    const prevTotal = (ratee.averageRating || 0) * (ratee.ratingCount || 0);
    ratee.ratingCount = (ratee.ratingCount || 0) + 1;
    ratee.averageRating = parseFloat(((prevTotal + s) / ratee.ratingCount).toFixed(2));
  }

  store.ratings.push({
    id: uuid(),
    matchId,
    raterId: req.userId,
    rateeId,
    score: s,
    comment: comment || null,
    sportId: match.sportId || (store.listings.find(l => l.id === match.listingId)?.sportId) || null,
    createdAt: new Date().toISOString(),
  });

  // Değerlendirilen kullanıcıya bildirim (dedup: aynı maç için 60sn içinde tekrar gönderme)
  const raterUser = userById(req.userId);
  const sixtySecondsAgo = new Date(Date.now() - 60 * 1000);
  const recentRatingNotif = store.notifications.find(n =>
    n.userId === rateeId &&
    n.type === 'NEW_RATING' &&
    n.relatedId === matchId &&
    new Date(n.createdAt) > sixtySecondsAgo
  );
  if (!recentRatingNotif) {
    store.notifications.push({
      id: uuid(),
      userId: rateeId,
      type: 'NEW_RATING',
      title: '⭐ Yeni Değerlendirme',
      body: `sizi değerlendirdi`,
      relatedId: matchId,
      senderId: req.userId,
      senderName: raterUser?.name || null,
      senderAvatar: raterUser?.avatarUrl || null,
      isRead: false,
      createdAt: new Date().toISOString(),
    });
  }
  sendWsEvent(rateeId, 'new_rating', { score: s, from: raterUser?.name });

  res.status(201).json({ message: 'Değerlendirme kaydedildi.' });
});

// GET /api/users/:id/ratings — Kullanıcının aldığı değerlendirmeler
app.get('/api/users/:id/ratings', authMiddleware, (req, res) => {
  const ratings = store.ratings
    .filter(r => r.rateeId === req.params.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 20)
    .map(r => {
      const rater = userById(r.raterId);
      const sport = r.sportId ? store.SPORTS.find(s => s.id === r.sportId) : null;
      return {
        id: r.id,
        score: r.score,
        comment: r.comment,
        createdAt: r.createdAt,
        raterName: rater?.name || null,
        raterAvatar: rater?.avatarUrl || null,
        sportName: sport?.name || null,
        sportIcon: sport?.icon || null,
      };
    });
  const user = userById(req.params.id);
  res.json({
    data: ratings,
    averageRating: user?.averageRating || 0,
    ratingCount: user?.ratingCount || 0,
  });
});

// ─── SETTINGS ─────────────────────────────────────────────────────────────────
const settingsRouter = express.Router();
settingsRouter.use(authMiddleware);

const privacyDefaults = () => ({
  profileVisibility: 'EVERYONE',
  showOnlineStatus: true,
  allowMessages: 'EVERYONE',
  showLocation: true,
  showSports: true,
  showOnLeaderboard: true,
  isPrivateProfile: false,
  socialLinksVisibility: 'EVERYONE',
  whoCanSeeMyInterests: 'EVERYONE',
  whoCanMessage: 'EVERYONE',
  whoCanChallenge: 'EVERYONE',
  whoCanSeeSportListings: 'EVERYONE',
  whoCanSeeSocialListings: 'EVERYONE',
  socialPlatformVisibility: Object.fromEntries(
    SOCIAL_PLATFORMS.map(p => [p, 'EVERYONE']),
  ),
});

const userPrivacy = {};
// userPrivacy'yi store'a bağla (persistence modülü erişebilsin)
store.userPrivacy = userPrivacy;

settingsRouter.get('/privacy', (req, res) => {
  const settings = normalizePrivacySettings(userPrivacy[req.userId] || privacyDefaults());
  res.json({ data: settings });
});

settingsRouter.put('/privacy', (req, res) => {
  userPrivacy[req.userId] = normalizePrivacySettings({
    ...privacyDefaults(),
    ...userPrivacy[req.userId],
    ...req.body,
  });
  const me = userById(req.userId);
  if (me) {
    me.isPrivate = userPrivacy[req.userId].isPrivateProfile === true;
  }
  res.json({ data: userPrivacy[req.userId] });
});

settingsRouter.get('/blocked-users', (req, res) => {
  const blocked = store.blockedUsers
    .filter(b => b.blockerId === req.userId)
    .map(b => {
      const user = userById(b.blockedId);
      if (!user) return null;
      return { id: b.id, blockedAt: b.createdAt, user: safeUser(user) };
    })
    .filter(Boolean);
  res.json({ data: blocked });
});

// ─── GEO ──────────────────────────────────────────────────────────────────────
app.get('/api/geo/cities', (req, res) => {
  res.json({ data: store.CITIES });
});

app.get('/api/geo/districts', (req, res) => {
  const { cityId } = req.query;
  const list = cityId ? (store.DISTRICTS[cityId] || []) : Object.values(store.DISTRICTS).flat();
  res.json({ data: list });
});

// ─── SPORTS ───────────────────────────────────────────────────────────────────
app.get('/api/sports', (req, res) => {
  res.json({ data: store.SPORTS });
});

// ─── TOURNAMENTS ──────────────────────────────────────────────────────────────
app.get('/api/turnuvalar', authMiddleware, (req, res) => {
  res.json({ data: [] });
});

app.get('/api/tournaments', authMiddleware, (req, res) => {
  res.json({ data: [] });
});

// ─── PUSH TOKEN ───────────────────────────────────────────────────────────────
app.post('/api/push/token', authMiddleware, (req, res) => {
  res.json({ message: 'Push token kaydedildi.' });
});

// ─── CLUBS (community filtrelenmiş) ──────────────────────────────────────────
app.get('/api/clubs', authMiddleware, (req, res) => {
  const clubs = store.communities.filter(c => c.type === 'CLUB');
  res.json({ data: clubs });
});

app.get('/api/clubs/:id', authMiddleware, (req, res) => {
  const club = store.communities.find(c => c.id === req.params.id && c.type === 'CLUB');
  if (!club) return res.status(404).json({ message: 'Kulüp bulunamadı.' });
  res.json({ data: club });
});

// ─── POSTS (Gönderi / Paylaşım) ROUTES ────────────────────────────────────────
const postsRouter = express.Router();
postsRouter.use(authMiddleware);

// Helper: Reaksiyon verilerini hesapla
const REACTION_TYPES = ['LIKE', 'LOVE', 'FIRE', 'STRONG', 'WOW', 'CLAP'];
function enrichPostReactions(postId, currentUserId) {
  const reactions = store.postReactions.filter(r => r.postId === postId);
  const userReaction = reactions.find(r => r.userId === currentUserId)?.type || null;
  const reactionCounts = {};
  REACTION_TYPES.forEach(t => {
    const count = reactions.filter(r => r.type === t).length;
    if (count > 0) reactionCounts[t] = count;
  });
  return { userReaction, reactionCounts, likeCount: reactions.length, isLiked: !!userReaction };
}

// GET /api/posts — Gönderi akışı (sayfalı, postType ve cityId filtrelemesi)
postsRouter.get('/', (req, res) => {
  const { page = 1, pageSize = 20, postType, cityId } = req.query;
  let filtered = [...store.posts];
  if (postType) filtered = filtered.filter(p => p.postType === postType);
  if (cityId) filtered = filtered.filter(p => p.cityId === cityId);
  const sorted = filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const skip = (Number(page) - 1) * Number(pageSize);
  const paged = sorted.slice(skip, skip + Number(pageSize));

  const enriched = paged.map(p => {
    const author = userById(p.userId);
    const commentCount = store.comments.filter(c => c.postId === p.id).length;
    const reactionData = enrichPostReactions(p.id, req.userId);
    return {
      ...p,
      user: author ? { id: author.id, name: author.name, avatarUrl: author.avatarUrl } : null,
      commentCount,
      ...reactionData,
    };
  });

  res.json({
    success: true,
    data: enriched,
    pagination: { page: Number(page), hasNext: skip + paged.length < filtered.length },
  });
});

// POST /api/posts — Gönderi oluştur (POST ve SOCIAL_LISTING destekli)
postsRouter.post('/', contentFilter('content', 'title'), (req, res) => {
  const body = sanitizeObject(req.body);
  const postType = body.postType === 'SOCIAL_LISTING' ? 'SOCIAL_LISTING' : 'POST';
  if (!body.content || typeof body.content !== 'string' || body.content.trim().length < 1) {
    return res.status(400).json({ message: 'İçerik gerekli.' });
  }
  if (body.content.length > 5000) {
    return res.status(400).json({ message: 'İçerik en fazla 5000 karakter olabilir.' });
  }
  // Sosyal ilan için başlık zorunlu
  if (postType === 'SOCIAL_LISTING') {
    if (!body.title || typeof body.title !== 'string' || body.title.trim().length < 2) {
      return res.status(400).json({ message: 'Sosyal ilan için başlık gerekli (en az 2 karakter).' });
    }
    if (body.title.length > 200) {
      return res.status(400).json({ message: 'Başlık en fazla 200 karakter olabilir.' });
    }
  }
  const user = userById(req.userId);
  const post = {
    id: uuid(),
    userId: req.userId,
    postType,
    content: body.content.trim(),
    title: postType === 'SOCIAL_LISTING' ? (body.title || '').trim() : null,
    imageUrl: body.imageUrl || null,
    sportId: body.sportId || null,
    sportName: body.sportId ? (store.SPORTS.find(s => s.id === body.sportId) || {}).name || null : null,
    countryName: body.countryName || null,
    cityId: body.cityId || null,
    cityName: body.cityName || null,
    districtId: body.districtId || null,
    districtName: body.districtName || null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  store.posts.push(post);
  res.status(201).json({
    data: {
      ...post,
      user: user ? { id: user.id, name: user.name, avatarUrl: user.avatarUrl } : null,
      likeCount: 0,
      commentCount: 0,
      isLiked: false,
      userReaction: null,
      reactionCounts: {},
    },
  });
});

// GET /api/posts/:id — Tekil gönderi detay
postsRouter.get('/:id', (req, res) => {
  const post = store.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  const author = userById(post.userId);
  const commentCount = store.comments.filter(c => c.postId === post.id).length;
  const reactionData = enrichPostReactions(post.id, req.userId);
  res.json({
    data: {
      ...post,
      user: author ? { id: author.id, name: author.name, avatarUrl: author.avatarUrl } : null,
      commentCount,
      ...reactionData,
    },
  });
});

// DELETE /api/posts/:id — Gönderi sil (sadece sahibi)
postsRouter.delete('/:id', (req, res) => {
  const idx = store.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  if (store.posts[idx].userId !== req.userId) {
    return res.status(403).json({ message: 'Bu gönderiyi silme yetkiniz yok.' });
  }
  store.posts.splice(idx, 1);
  // Cascade: sil ilişkili reaksiyonları ve yorumları
  for (let i = store.postReactions.length - 1; i >= 0; i--) {
    if (store.postReactions[i].postId === req.params.id) store.postReactions.splice(i, 1);
  }
  for (let i = store.comments.length - 1; i >= 0; i--) {
    if (store.comments[i].postId === req.params.id) store.comments.splice(i, 1);
  }
  for (let i = store.commentLikes.length - 1; i >= 0; i--) {
    const comment = store.comments.find(c => c.id === store.commentLikes[i].commentId);
    if (!comment) store.commentLikes.splice(i, 1);
  }
  res.json({ success: true });
});

// PUT /api/posts/:id — Gönderi düzenle (sadece sahibi)
postsRouter.put('/:id', contentFilter('content'), (req, res) => {
  const post = store.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  if (post.userId !== req.userId) return res.status(403).json({ message: 'Bu gönderiyi düzenleme yetkiniz yok.' });
  const { content } = req.body;
  if (!content || content.trim().length === 0) return res.status(400).json({ message: 'İçerik boş olamaz.' });
  if (content.trim().length > 5000) return res.status(400).json({ message: 'İçerik en fazla 5000 karakter olabilir.' });
  post.content = content.trim();
  post.updatedAt = new Date().toISOString();
  const user = userById(post.userId);
  const commentCount = store.comments.filter(c => c.postId === post.id && !c.deletedAt).length;
  const reactionData = enrichPostReactions(post.id, req.userId);
  const sport = post.sportId ? store.SPORTS.find(s => s.id === post.sportId) : null;
  res.json({ data: { ...post, user: user ? { id: user.id, name: user.name, avatarUrl: user.avatarUrl } : null, commentCount, ...reactionData, sportName: sport?.name ?? null } });
});

// GET /api/posts/user/:userId — Bir kullanıcının gönderileri
postsRouter.get('/user/:userId', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 20;
  const userPosts = store.posts
    .filter(p => p.userId === req.params.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const total = userPosts.length;
  const paginated = userPosts.slice((page - 1) * pageSize, page * pageSize);
  const data = paginated.map(post => {
    const user = userById(post.userId);
    const commentCount = store.comments.filter(c => c.postId === post.id && !c.deletedAt).length;
    const reactionData = enrichPostReactions(post.id, req.userId);
    const sport = post.sportId ? store.SPORTS.find(s => s.id === post.sportId) : null;
    return { ...post, user: user ? { id: user.id, name: user.name, avatarUrl: user.avatarUrl } : null, commentCount, ...reactionData, sportName: sport?.name ?? null };
  });
  res.json({ data, pagination: { page, pageSize, total, hasNext: page * pageSize < total } });
});

// POST /api/posts/:id/react — Emoji reaksiyon (toggle/change)
postsRouter.post('/:id/react', (req, res) => {
  const post = store.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  const { type = 'LIKE' } = req.body;
  if (!REACTION_TYPES.includes(type)) return res.status(400).json({ message: 'Geçersiz reaksiyon tipi.' });

  const existingIdx = store.postReactions.findIndex(r => r.postId === post.id && r.userId === req.userId);
  if (existingIdx !== -1) {
    const existing = store.postReactions[existingIdx];
    if (existing.type === type) {
      store.postReactions.splice(existingIdx, 1); // aynı reaksiyon → kaldır
    } else {
      store.postReactions[existingIdx].type = type; // farklı → değiştir
    }
  } else {
    store.postReactions.push({ id: uuid(), postId: post.id, userId: req.userId, type, createdAt: new Date().toISOString() });
    if (post.userId !== req.userId) {
      const reactor = userById(req.userId);
      const emojiMap = { LIKE: '👍', LOVE: '❤️', FIRE: '🔥', STRONG: '💪', WOW: '😮', CLAP: '👏' };
      const emoji = emojiMap[type] || '👍';
      pushNotification({
        userId: post.userId, type: 'POST_REACT',
        title: 'Gönderi Reaksiyonu',
        body: `${reactor?.name || 'Birisi'} gönderinize ${emoji} tepkisi verdi.`,
        relatedId: post.id, senderId: req.userId,
        senderName: reactor?.name || null, senderAvatar: reactor?.avatarUrl || null,
      });
      sendWsEvent(post.userId, 'post_reacted', { postId: post.id, reactionType: type, user: reactor ? safeUser(reactor) : null });
    }
  }
  res.json(enrichPostReactions(post.id, req.userId));
});

// POST /api/posts/:id/like — Geriye dönük uyumluluk (LIKE reaksiyonu toggle)
postsRouter.post('/:id/like', (req, res) => {
  const post = store.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });

  const existingIdx = store.postReactions.findIndex(r => r.postId === post.id && r.userId === req.userId);
  if (existingIdx !== -1) {
    store.postReactions.splice(existingIdx, 1);
  } else {
    store.postReactions.push({ id: uuid(), postId: post.id, userId: req.userId, type: 'LIKE', createdAt: new Date().toISOString() });
    if (post.userId !== req.userId) {
      const liker = userById(req.userId);
      store.notifications.push({
        id: uuid(), userId: post.userId, type: 'POST_LIKE',
        title: 'Gönderi beğenildi', body: `${liker?.name || 'Birisi'} gönderinizi beğendi.`,
        relatedId: post.id, senderId: req.userId, isRead: false, createdAt: new Date().toISOString(),
      });
      sendWsEvent(post.userId, 'post_liked', { postId: post.id, user: liker ? safeUser(liker) : null });
    }
  }
  const reactionData = enrichPostReactions(post.id, req.userId);
  res.json({ liked: reactionData.isLiked, likeCount: reactionData.likeCount, ...reactionData });
});

// GET /api/posts/:id/likes — Reaksiyon kullanıcıları
postsRouter.get('/:id/likes', (req, res) => {
  const reactions = store.postReactions.filter(r => r.postId === req.params.id);
  const users = reactions.map(r => {
    const u = userById(r.userId);
    return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl, likedAt: r.createdAt, reactionType: r.type } : null;
  }).filter(Boolean);
  res.json({ data: users });
});

// GET /api/posts/:id/comments — Yorumları listele (iç içe destekli)
postsRouter.get('/:id/comments', (req, res) => {
  const postComments = store.comments.filter(c => c.postId === req.params.id);

  function buildTree(parentId) {
    return postComments
      .filter(c => (c.parentId || null) === parentId)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
      .map(c => {
        const author = userById(c.userId);
        const likes = store.commentLikes.filter(cl => cl.commentId === c.id);
        const isLiked = likes.some(cl => cl.userId === req.userId);
        return {
          ...c,
          user: author ? { id: author.id, name: author.name, avatarUrl: author.avatarUrl } : null,
          likeCount: likes.length,
          isLiked,
          replies: buildTree(c.id),
        };
      });
  }

  res.json({ data: buildTree(null) });
});

// POST /api/posts/:id/comments — Yorum yap (iç içe yorum için parentId)
postsRouter.post('/:id/comments', contentFilter('content'), (req, res) => {
  const post = store.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  const body = sanitizeObject(req.body);
  if (!body.content || typeof body.content !== 'string' || body.content.trim().length < 1) {
    return res.status(400).json({ message: 'Yorum içeriği gerekli.' });
  }
  if (body.content.length > 2000) {
    return res.status(400).json({ message: 'Yorum en fazla 2000 karakter olabilir.' });
  }
  // parentId varsa: iç içe yorum (reply)
  if (body.parentId) {
    const parent = store.comments.find(c => c.id === body.parentId && c.postId === post.id);
    if (!parent) return res.status(404).json({ message: 'Üst yorum bulunamadı.' });
  }
  const user = userById(req.userId);
  const comment = {
    id: uuid(),
    postId: post.id,
    userId: req.userId,
    parentId: body.parentId || null,
    content: body.content.trim(),
    createdAt: new Date().toISOString(),
  };
  store.comments.push(comment);
  // Bildirim
  const notifyUserId = body.parentId
    ? store.comments.find(c => c.id === body.parentId)?.userId
    : post.userId;
  if (notifyUserId && notifyUserId !== req.userId) {
    store.notifications.push({
      id: uuid(), userId: notifyUserId, type: body.parentId ? 'COMMENT_REPLY' : 'POST_COMMENT',
      title: body.parentId ? 'Yorumunuza yanıt' : 'Yeni yorum',
      body: `${user?.name || 'Birisi'} ${body.parentId ? 'yorumunuza yanıt verdi.' : 'gönderinize yorum yaptı.'}`,
      relatedId: post.id, senderId: req.userId, isRead: false, createdAt: new Date().toISOString(),
    });
    sendWsEvent(notifyUserId, body.parentId ? 'comment_reply' : 'post_comment', {
      postId: post.id, commentId: comment.id, user: user ? safeUser(user) : null,
    });
  }
  const likes = store.commentLikes.filter(cl => cl.commentId === comment.id);
  res.status(201).json({
    data: {
      ...comment,
      user: user ? { id: user.id, name: user.name, avatarUrl: user.avatarUrl } : null,
      likeCount: 0,
      isLiked: false,
      replies: [],
    },
  });
});

// DELETE /api/posts/:postId/comments/:commentId — Yorum sil
postsRouter.delete('/:postId/comments/:commentId', (req, res) => {
  const idx = store.comments.findIndex(c => c.id === req.params.commentId && c.postId === req.params.postId);
  if (idx === -1) return res.status(404).json({ message: 'Yorum bulunamadı.' });
  // Gönderi sahibi veya yorum sahibi silebilir
  const post = store.posts.find(p => p.id === req.params.postId);
  if (store.comments[idx].userId !== req.userId && post?.userId !== req.userId) {
    return res.status(403).json({ message: 'Bu yorumu silme yetkiniz yok.' });
  }
  // Alt yorumları da sil (cascade)
  const toDelete = [req.params.commentId];
  const findChildren = (parentId) => {
    store.comments.filter(c => c.parentId === parentId).forEach(c => {
      toDelete.push(c.id);
      findChildren(c.id);
    });
  };
  findChildren(req.params.commentId);
  for (let i = store.comments.length - 1; i >= 0; i--) {
    if (toDelete.includes(store.comments[i].id)) store.comments.splice(i, 1);
  }
  for (let i = store.commentLikes.length - 1; i >= 0; i--) {
    if (toDelete.includes(store.commentLikes[i].commentId)) store.commentLikes.splice(i, 1);
  }
  res.json({ success: true });
});

// PUT /api/posts/:postId/comments/:commentId — Yorum düzenle (sadece yorum sahibi)
postsRouter.put('/:postId/comments/:commentId', contentFilter('content'), (req, res) => {
  const comment = store.comments.find(c => c.id === req.params.commentId && c.postId === req.params.postId);
  if (!comment) return res.status(404).json({ message: 'Yorum bulunamadı.' });
  if (comment.userId !== req.userId) return res.status(403).json({ message: 'Bu yorumu düzenleme yetkiniz yok.' });
  const { content } = req.body;
  if (!content || content.trim().length === 0) return res.status(400).json({ message: 'İçerik boş olamaz.' });
  comment.content = content.trim();
  comment.updatedAt = new Date().toISOString();
  const user = userById(comment.userId);
  const likeCount = store.commentLikes.filter(l => l.commentId === comment.id).length;
  const isLiked = store.commentLikes.some(l => l.commentId === comment.id && l.userId === req.userId);
  res.json({ data: { ...comment, user: user ? { id: user.id, name: user.name, avatarUrl: user.avatarUrl } : null, likeCount, isLiked, replies: [] } });
});

// POST /api/posts/:postId/comments/:commentId/like — Yorum beğen (toggle)
postsRouter.post('/:postId/comments/:commentId/like', (req, res) => {
  const comment = store.comments.find(c => c.id === req.params.commentId && c.postId === req.params.postId);
  if (!comment) return res.status(404).json({ message: 'Yorum bulunamadı.' });
  const existingIdx = store.commentLikes.findIndex(l => l.commentId === comment.id && l.userId === req.userId);
  if (existingIdx !== -1) {
    store.commentLikes.splice(existingIdx, 1);
    res.json({ liked: false, likeCount: store.commentLikes.filter(l => l.commentId === comment.id).length });
  } else {
    store.commentLikes.push({ id: uuid(), commentId: comment.id, userId: req.userId, createdAt: new Date().toISOString() });
    if (comment.userId !== req.userId) {
      const liker = userById(req.userId);
      store.notifications.push({
        id: uuid(), userId: comment.userId, type: 'COMMENT_LIKE',
        title: 'Yorum beğenildi', body: `${liker?.name || 'Birisi'} yorumunuzu beğendi.`,
        relatedId: comment.postId, senderId: req.userId, isRead: false, createdAt: new Date().toISOString(),
      });
    }
    res.json({ liked: true, likeCount: store.commentLikes.filter(l => l.commentId === comment.id).length });
  }
});

// GET /api/posts/:postId/comments/:commentId/likes — Yorum beğenenlerini listele
postsRouter.get('/:postId/comments/:commentId/likes', (req, res) => {
  const likes = store.commentLikes.filter(l => l.commentId === req.params.commentId);
  const users = likes.map(l => {
    const u = userById(l.userId);
    return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl, likedAt: l.createdAt } : null;
  }).filter(Boolean);
  res.json({ data: users });
});

// ─── Mount routers ─────────────────────────────────────────────────────────────
app.use('/api/auth',          authRouter);
app.use('/api/profile',       profileRouter);
app.use('/api/listings',      listingsRouter);
app.use('/api/matches',       matchesRouter);
app.use('/api/conversations', convsRouter);
app.use('/api/communities',   commRouter);
app.use('/api/groups',        groupsRouter);
app.use('/api/users',         usersRouter);
app.use('/api/challenges',    challengesRouter);
app.use('/api/settings',      settingsRouter);
app.use('/api/follows',       followsRouter);
app.use('/api/posts',         postsRouter);
app.use('/api/admin',         authMiddleware, adminRouter);

// ─── Reports (content reporting) ──────────────────────────────────────────────
app.post('/api/reports', authMiddleware, (req, res) => {
  const { type, targetId, reason } = req.body;
  const validTypes = ['POST', 'LISTING', 'USER', 'SOCIAL_LISTING'];
  if (!validTypes.includes(type)) {
    return res.status(400).json({ message: 'Geçersiz içerik türü.' });
  }
  if (!targetId || typeof targetId !== 'string') {
    return res.status(400).json({ message: 'Hedef ID gerekli.' });
  }
  store.reports.push({
    id: uuid(),
    reporterId: req.userId,
    type,
    targetId,
    reason: reason || 'OTHER',
    createdAt: new Date().toISOString(),
  });
  res.json({ success: true, message: 'Şikayet alındı.' });
});

// ─── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ name: 'Sports Partner API', version: '1.0.0', status: 'running' }));

// ─── Stress Test Monitor Endpoint ──────────────────────────────────────────────
app.get('/api/stress-monitor', (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    memory: {
      rss: `${(mem.rss / 1024 / 1024).toFixed(1)}MB`,
      heapUsed: `${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB`,
      heapTotal: `${(mem.heapTotal / 1024 / 1024).toFixed(1)}MB`,
      external: `${(mem.external / 1024 / 1024).toFixed(1)}MB`,
    },
    store: {
      users: store.users.length,
      listings: store.listings.length,
      matches: store.matches.length,
      conversations: store.conversations.length,
      messages: store.messages.length,
      posts: store.posts.length,
      notifications: store.notifications.length,
      challenges: store.challenges.length,
      communities: store.communities.length,
      groups: store.groups.length,
    },
    uptime: `${(process.uptime() / 60).toFixed(1)} min`,
    rateLimitMax: RATE_LIMIT_MAX,
    timestamp: new Date().toISOString(),
  });
});

// 404 fallback
app.use((req, res) => res.status(404).json({ message: `Endpoint bulunamadı: ${req.method} ${req.path}` }));

// ─── Start ────────────────────────────────────────────────────────────────────
// ─── Maç Onay Bildirimi Timer (her dakika kontrol) ─────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const match of store.matches) {
    if (match.status !== 'SCHEDULED' && match.status !== 'PENDING') continue;
    if (match.confirmationNotified) continue;
    const listing = store.listings.find(l => l.id === match.listingId);
    if (!listing || !listing.date) continue;
    const matchTime = new Date(listing.date).getTime();
    // Maç tarihinden 1 saat sonra geçtiyse bildirim gönder
    if (now >= matchTime + 60 * 60 * 1000) {
      match.confirmationNotified = true;
      const sport = store.SPORTS.find(s => s.id === listing.sportId);
      const sportName = sport?.name || 'Spor';
      const u1Id = match.user1Id || match.user1?.id;
      const u2Id = match.user2Id || match.user2?.id;
      const notifBody = `${sportName} maçının tarihi geçti. Maçı oynadıysanız onaylamayı unutmayın!`;
      for (const uid of [u1Id, u2Id]) {
        if (!uid) continue;
        store.notifications.push({
          id: uuid(),
          userId: uid,
          type: 'MATCH_STATUS_CHANGED',
          title: `⚽ Maçınız Nasıl Geçti?`,
          body: notifBody,
          relatedId: match.id,
          isRead: false,
          createdAt: new Date().toISOString(),
        });
        sendWsEvent(uid, 'match_confirmation_reminder', { matchId: match.id, message: notifBody });
      }
    }
  }
}, 60 * 1000);

const PORT = process.env.PORT || 3000;

// ─── Persistent Storage ─────────────────────────────────────────────────────
// Veriyi dosyaya kaydet/yükle — Docker restart'ta veri korunur
startPersistence(store);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Sports Partner API çalışıyor → http://0.0.0.0:${PORT}`);
  console.log(`📋 Sağlık kontrol: http://localhost:${PORT}/health`);
  console.log(`\n👤 Test hesapları:`);
  console.log(`   Email: test@sporpartner.com    Şifre: Test123!`);
  console.log(`   Email: admin@sporpartner.com   Şifre: Admin123!\n`);
});
