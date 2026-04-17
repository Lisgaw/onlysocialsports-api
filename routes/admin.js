'use strict';
const express = require('express');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const store = require('../db/store');
const {
  mapCountryCodeToLocale,
  buildBotAvatarUrl,
  LOCALIZED_NAMES,
  DEFAULT_NAMES,
  generateBotBio,
  generateListingDesc,
  generateResponseMsg,
  generateShadowMatchText,
  estimateBotCoordinates,
  getFutureDate,
} = require('../lib/bot-automation');

const router = express.Router();

// ─── Admin middleware ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const user = store.users.find(u => u.id === req.userId);
  if (!user || !user.isAdmin) {
    return res.status(403).json({ message: 'Yetkisiz: Admin değilsiniz.' });
  }
  next();
}

router.use(requireAdmin);

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DASHBOARD STATS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/stats', (req, res) => {
  const now = Date.now();
  const d7  = now - 7  * 86400000;
  const d30 = now - 30 * 86400000;

  const totalUsers  = store.users.filter(u => !u.isBot).length;
  const totalBots   = store.users.filter(u => u.isBot).length;
  const newUsers7d  = store.users.filter(u => !u.isBot && new Date(u.createdAt).getTime() > d7).length;
  const newUsers30d = store.users.filter(u => !u.isBot && new Date(u.createdAt).getTime() > d30).length;
  const bannedUsers = store.users.filter(u => u.isBanned).length;

  const totalListings     = store.listings.length;
  const activeListings    = store.listings.filter(l => l.status === 'ACTIVE').length;
  const botListings       = store.listings.filter(l => { const u = store.users.find(x => x.id === l.userId); return u && u.isBot; }).length;

  const totalMatches      = store.matches.length;
  const completedMatches  = store.matches.filter(m => m.status === 'COMPLETED').length;

  const totalPosts    = store.posts.length;
  const totalReports  = store.reports.length;
  const pendingReports = store.reports.filter(r => r.status === 'PENDING').length;

  const totalCommunities = store.communities.length;
  const totalBotTasks    = store.botTasks.length;
  const pendingTasks     = store.botTasks.filter(t => t.status === 'PENDING').length;
  const completedTasks   = store.botTasks.filter(t => t.status === 'MATCH_DONE').length;
  const failedTasks      = store.botTasks.filter(t => t.status === 'FAILED').length;

  const activeCountries  = store.COUNTRIES.filter(c => c.isActive).length;

  res.json({
    data: {
      users: { total: totalUsers, new7d: newUsers7d, new30d: newUsers30d, banned: bannedUsers },
      bots: { total: totalBots },
      listings: { total: totalListings, active: activeListings, botCreated: botListings },
      matches: { total: totalMatches, completed: completedMatches },
      posts: { total: totalPosts },
      reports: { total: totalReports, pending: pendingReports },
      communities: { total: totalCommunities },
      botTasks: { total: totalBotTasks, pending: pendingTasks, completed: completedTasks, failed: failedTasks },
      countries: { active: activeCountries, total: store.COUNTRIES.length },
    },
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. USER MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/users', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const search = (req.query.search || '').toLowerCase();
  const filter = req.query.filter; // 'all' | 'banned' | 'bots' | 'admin'

  let filtered = store.users;
  if (filter === 'banned') filtered = filtered.filter(u => u.isBanned);
  else if (filter === 'bots') filtered = filtered.filter(u => u.isBot);
  else if (filter === 'admin') filtered = filtered.filter(u => u.isAdmin);
  else filtered = filtered.filter(u => !u.isBot);

  if (search) {
    filtered = filtered.filter(u =>
      (u.name || '').toLowerCase().includes(search) ||
      (u.email || '').toLowerCase().includes(search) ||
      (u.username || '').toLowerCase().includes(search)
    );
  }

  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit).map(u => {
    const { password, ...rest } = u;
    return rest;
  });

  res.json({ data: { items, total, page, pageSize: limit, totalPages: Math.ceil(total / limit) } });
});

router.patch('/users/:id', (req, res) => {
  const user = store.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });

  const { action } = req.body; // 'ban' | 'unban' | 'promote' | 'demote'
  if (action === 'ban')     user.isBanned = true;
  else if (action === 'unban')   user.isBanned = false;
  else if (action === 'promote') user.isAdmin = true;
  else if (action === 'demote')  user.isAdmin = false;
  else return res.status(400).json({ message: 'Geçersiz action. ban/unban/promote/demote' });

  const { password, ...safe } = user;
  res.json({ data: safe });
});

router.delete('/users/:id', (req, res) => {
  const idx = store.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  store.users.splice(idx, 1);
  // Cascade: remove related data
  const uid = req.params.id;
  store.listings.splice(0, store.listings.length, ...store.listings.filter(l => l.userId !== uid));
  store.posts.splice(0, store.posts.length, ...store.posts.filter(p => p.userId !== uid));
  res.json({ message: 'Kullanıcı silindi.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. REPORT MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/reports', (req, res) => {
  const status = req.query.status || 'PENDING';
  const limit  = Math.min(100, parseInt(req.query.limit) || 30);

  let filtered = store.reports;
  if (status !== 'ALL') filtered = filtered.filter(r => r.status === status);
  filtered = filtered.slice(0, limit);

  // Enrich with user details
  const items = filtered.map(r => ({
    ...r,
    reporter: (() => { const u = store.users.find(x => x.id === r.reporterId); return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl } : null; })(),
    reported: (() => { const u = store.users.find(x => x.id === r.reportedUserId); return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl } : null; })(),
  }));

  res.json({ data: items });
});

router.patch('/reports/:id', (req, res) => {
  const report = store.reports.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ message: 'Rapor bulunamadı.' });

  const { action } = req.body; // 'resolve' | 'ban'
  report.status = 'RESOLVED';
  report.resolvedAt = new Date().toISOString();
  report.resolvedBy = req.userId;

  if (action === 'ban' && report.reportedUserId) {
    const u = store.users.find(x => x.id === report.reportedUserId);
    if (u) u.isBanned = true;
  }

  res.json({ data: report });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. CONTENT MODERATION (Posts)
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/posts', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 20);
  const filter = req.query.filter; // 'all' | 'bot' | 'user' | 'reported'

  let filtered = store.posts;
  if (filter === 'bot') {
    const botIds = new Set(store.users.filter(u => u.isBot).map(u => u.id));
    filtered = filtered.filter(p => botIds.has(p.userId));
  } else if (filter === 'user') {
    const botIds = new Set(store.users.filter(u => u.isBot).map(u => u.id));
    filtered = filtered.filter(p => !botIds.has(p.userId));
  }

  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit).map(p => {
    const u = store.users.find(x => x.id === p.userId);
    return { ...p, user: u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl, isBot: u.isBot } : null };
  });

  res.json({ data: { items, total, page, pageSize: limit } });
});

router.delete('/posts/:id', (req, res) => {
  const idx = store.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Gönderi bulunamadı.' });
  const postId = store.posts[idx].id;
  store.posts.splice(idx, 1);
  // Cascade
  store.postLikes.splice(0, store.postLikes.length, ...store.postLikes.filter(l => l.postId !== postId));
  store.comments.splice(0, store.comments.length, ...store.comments.filter(c => c.postId !== postId));
  res.json({ message: 'Gönderi silindi.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. LISTING MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/listings', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 20);
  const filter = req.query.filter; // 'all' | 'bot' | 'user' | 'active' | 'expired'

  let filtered = store.listings;
  if (filter === 'bot') {
    const botIds = new Set(store.users.filter(u => u.isBot).map(u => u.id));
    filtered = filtered.filter(l => botIds.has(l.userId));
  } else if (filter === 'user') {
    const botIds = new Set(store.users.filter(u => u.isBot).map(u => u.id));
    filtered = filtered.filter(l => !botIds.has(l.userId));
  } else if (filter === 'active') {
    filtered = filtered.filter(l => l.status === 'ACTIVE');
  } else if (filter === 'expired') {
    filtered = filtered.filter(l => l.status === 'EXPIRED' || new Date(l.expiresAt) < new Date());
  }

  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit).map(l => {
    const u = store.users.find(x => x.id === l.userId);
    return { ...l, user: u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl, isBot: !!u.isBot } : null };
  });

  res.json({ data: { items, total, page, pageSize: limit } });
});

router.delete('/listings/bulk', (req, res) => {
  const { ids, filter } = req.body; // ids: string[] OR filter: 'all-bots'
  let removed = 0;
  if (filter === 'all-bots') {
    const botIds = new Set(store.users.filter(u => u.isBot).map(u => u.id));
    const before = store.listings.length;
    store.listings.splice(0, store.listings.length, ...store.listings.filter(l => !botIds.has(l.userId)));
    removed = before - store.listings.length;
  } else if (Array.isArray(ids)) {
    const idSet = new Set(ids);
    const before = store.listings.length;
    store.listings.splice(0, store.listings.length, ...store.listings.filter(l => !idSet.has(l.id)));
    removed = before - store.listings.length;
  }
  res.json({ message: `${removed} ilan silindi.`, removed });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. BOT MANAGEMENT (CRUD)
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/bots', (req, res) => {
  const bots = store.users.filter(u => u.isBot);
  const items = bots.map(u => {
    const { password, ...rest } = u;
    const taskCount = store.botTasks.filter(t => t.listingBotId === u.id || t.responderBotId === u.id).length;
    const listingCount = store.listings.filter(l => l.userId === u.id).length;
    return { ...rest, taskCount, listingCount };
  });
  res.json({ data: items });
});

router.post('/bots', (req, res) => {
  const { name, gender, cityId, cityName, sports, persona, countryCode } = req.body;
  if (!name) return res.status(400).json({ message: 'name zorunlu.' });

  const locale = mapCountryCodeToLocale(countryCode || 'TR');
  const sportList = Array.isArray(sports) ? sports.map(s => {
    const found = store.SPORTS.find(sp => sp.id === s || sp.name === s);
    return found || { id: s, name: s, icon: '🏅' };
  }) : [];

  const bot = {
    id: uuid(),
    email: `bot_${Date.now()}_${Math.random().toString(36).slice(2, 6)}@sporpartner.internal`,
    name,
    username: `bot_${name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}`,
    password: null,
    avatarUrl: buildBotAvatarUrl({ gender: gender || 'MALE', seed: `${name}-${cityId || 'x'}-${sportList[0]?.name || 'sport'}` }),
    coverUrl: null,
    phone: null,
    isAdmin: false,
    isBot: true,
    botPersona: persona || null,
    onboardingDone: true,
    userType: 'USER',
    city: cityName || null,
    cityId: cityId || null,
    district: null,
    districtId: null,
    bio: generateBotBio({ locale, sportName: sportList[0]?.name || 'spor', cityName: cityName || '' }),
    instagram: null, tiktok: null, facebook: null,
    twitter: null, youtube: null, linkedin: null, discord: null, twitch: null,
    snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
    sports: sportList,
    level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
    gender: (gender || 'MALE').toUpperCase(),
    preferredTime: null,
    preferredStyle: null,
    birthDate: new Date(1988 + Math.floor(Math.random() * 15), Math.floor(Math.random() * 12), Math.floor(Math.random() * 28) + 1).toISOString(),
    totalMatches: 0,
    currentStreak: 0,
    longestStreak: 0,
    totalPoints: 0,
    followerCount: 0,
    followingCount: 0,
    averageRating: 0,
    ratingCount: 0,
    isBanned: false,
    noShowCount: 0,
    isPrivate: false,
    createdAt: new Date().toISOString(),
  };
  store.users.push(bot);
  const { password, ...safe } = bot;
  res.status(201).json({ data: safe });
});

router.patch('/bots/:id', (req, res) => {
  const bot = store.users.find(u => u.id === req.params.id && u.isBot);
  if (!bot) return res.status(404).json({ message: 'Bot bulunamadı.' });

  const allowed = ['name', 'gender', 'cityId', 'cityName', 'bio', 'avatarUrl', 'botPersona', 'sports', 'level'];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      if (key === 'sports' && Array.isArray(req.body.sports)) {
        bot.sports = req.body.sports.map(s => {
          const found = store.SPORTS.find(sp => sp.id === s || sp.name === s);
          return found || { id: s, name: s, icon: '🏅' };
        });
      } else {
        bot[key] = req.body[key];
      }
    }
  }

  // Regenerate profile if requested
  if (req.body.regenerate) {
    const locale = mapCountryCodeToLocale(req.body.countryCode || 'TR');
    bot.avatarUrl = buildBotAvatarUrl({ gender: bot.gender, seed: `${bot.name}-${bot.cityId}-${bot.sports[0]?.name || 'sport'}` });
    bot.bio = generateBotBio({ locale, sportName: bot.sports[0]?.name || 'spor', cityName: bot.city || '' });
  }

  const { password, ...safe } = bot;
  res.json({ data: safe });
});

router.delete('/bots/:id', (req, res) => {
  const idx = store.users.findIndex(u => u.id === req.params.id && u.isBot);
  if (idx === -1) return res.status(404).json({ message: 'Bot bulunamadı.' });

  const botId = store.users[idx].id;
  store.users.splice(idx, 1);

  // Cascade
  store.listings.splice(0, store.listings.length, ...store.listings.filter(l => l.userId !== botId));
  store.posts.splice(0, store.posts.length, ...store.posts.filter(p => p.userId !== botId));
  store.botTasks.splice(0, store.botTasks.length, ...store.botTasks.filter(t => t.listingBotId !== botId && t.responderBotId !== botId));

  res.json({ message: 'Bot ve ilişkili veriler silindi.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. COUNTRY MANAGEMENT & ACTIVATION (Seed Country)
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/countries', (req, res) => {
  const items = store.COUNTRIES.map(c => {
    const botCount = store.users.filter(u => u.isBot && u.countryCode === c.code).length;
    const taskCount = store.botTasks.filter(t => t.countryCode === c.code).length;
    return { ...c, botCount, taskCount };
  });
  res.json({ data: items });
});

/**
 * POST /api/admin/countries/:id/activate
 * "Ülkeyi canlendır" — creates 2 bots per city in that country + runs bot tasks
 *
 * Uses the Flutter app's states.json (asset file) OR the store's predefined city data.
 * Body: { sportId?, listingDateTime?, botsPerCity? }
 */
router.post('/countries/:id/activate', (req, res) => {
  const country = store.COUNTRIES.find(c => c.id === req.params.id);
  if (!country) return res.status(404).json({ message: 'Ülke bulunamadı.' });

  const { sportId, listingDateTime, botsPerCity = 2 } = req.body;
  const perCity = Math.min(10, Math.max(2, parseInt(botsPerCity) || 2));

  // Load cities from states.json (Flutter asset)
  let cities = [];
  try {
    // Try multiple paths: Docker volume mount (/app/assets) or dev relative path
    const possiblePaths = [
      path.join(__dirname, '..', 'assets', 'i18n'),    // /app/assets/i18n (Docker volume)
      path.join(__dirname, '..', '..', 'assets', 'i18n'), // dev relative path
    ];
    let statesData = null;
    let countriesData = null;
    for (const base of possiblePaths) {
      const sp = path.join(base, 'states.json');
      const cp = path.join(base, 'countries.json');
      if (fs.existsSync(sp) && fs.existsSync(cp)) {
        statesData = JSON.parse(fs.readFileSync(sp, 'utf-8').replace(/^\uFEFF/, ''));
        countriesData = JSON.parse(fs.readFileSync(cp, 'utf-8').replace(/^\uFEFF/, ''));
        break;
      }
    }
    if (statesData && countriesData) {
      const countryEntry = countriesData.find(c => c.iso2 === country.code);

      if (countryEntry && statesData[String(countryEntry.id)]) {
        cities = statesData[String(countryEntry.id)].map(s => ({
          id: `state_${s.id}`,
          name: s.n,
          stateCode: s.sc || '',
        }));
      }
    }
  } catch (err) {
    console.warn('states.json okunamadı, fallback kullanılıyor:', err.message);
  }

  // Fallback: use store CITIES if matching
  if (cities.length === 0 && country.code === 'TR') {
    cities = store.CITIES.map(c => ({ id: c.id, name: c.name, stateCode: '' }));
  }

  if (cities.length === 0) {
    return res.status(400).json({ message: `${country.name} için şehir verisi bulunamadı.` });
  }

  const locale = mapCountryCodeToLocale(country.code);
  const names = LOCALIZED_NAMES[country.code] || DEFAULT_NAMES;

  // Select sports
  const allSports = store.SPORTS;
  const selectedSport = sportId ? allSports.find(s => s.id === sportId) : null;
  const randomSports = allSports.filter(s => s.id !== (selectedSport?.id)).sort(() => Math.random() - 0.5).slice(0, 5);
  const sportPool = selectedSport ? [selectedSport, ...randomSports] : allSports.sort(() => Math.random() - 0.5).slice(0, Math.min(6, allSports.length));

  const dateTime = listingDateTime ? new Date(listingDateTime) : getFutureDate(1);

  let maleIdx = 0, femaleIdx = 0, botsCreated = 0, tasksCreated = 0;
  const taskIds = [];

  for (let ci = 0; ci < cities.length; ci++) {
    const city = cities[ci];
    const citySport = sportPool[ci % sportPool.length];

    // Create bot pairs for this city
    const pairsToCreate = Math.floor(perCity / 2);
    for (let p = 0; p < pairsToCreate; p++) {
      const maleName = names.male[(maleIdx++) % names.male.length];
      const femaleName = names.female[(femaleIdx++) % names.female.length];

      const maleBot = {
        id: uuid(),
        email: `bot_${Date.now()}_m_${city.id.slice(0, 8)}_${citySport.id.slice(0, 4)}@sporpartner.internal`,
        name: maleName,
        username: `bot_${maleName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_${maleIdx}`,
        password: null,
        avatarUrl: buildBotAvatarUrl({ gender: 'MALE', seed: `${maleName}-${city.id}-${citySport.name}` }),
        coverUrl: null, phone: null,
        isAdmin: false, isBot: true, botPersona: null,
        onboardingDone: true, userType: 'USER',
        city: city.name, cityId: city.id, countryCode: country.code,
        district: null, districtId: null,
        bio: generateBotBio({ locale, sportName: citySport.name, cityName: city.name }),
        instagram: null, tiktok: null, facebook: null, twitter: null, youtube: null,
        linkedin: null, discord: null, twitch: null, snapchat: null, telegram: null,
        whatsapp: null, vk: null, litmatch: null,
        sports: [citySport],
        level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
        gender: 'MALE',
        preferredTime: null, preferredStyle: null,
        birthDate: new Date(1990 + (maleIdx % 15), maleIdx % 12, 1).toISOString(),
        totalMatches: 0, currentStreak: 0, longestStreak: 0, totalPoints: 0,
        followerCount: 0, followingCount: 0, averageRating: 0, ratingCount: 0,
        isBanned: false, noShowCount: 0, isPrivate: false,
        createdAt: new Date().toISOString(),
      };

      const femaleBot = {
        id: uuid(),
        email: `bot_${Date.now()}_f_${city.id.slice(0, 8)}_${citySport.id.slice(0, 4)}@sporpartner.internal`,
        name: femaleName,
        username: `bot_${femaleName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_${femaleIdx}`,
        password: null,
        avatarUrl: buildBotAvatarUrl({ gender: 'FEMALE', seed: `${femaleName}-${city.id}-${citySport.name}` }),
        coverUrl: null, phone: null,
        isAdmin: false, isBot: true, botPersona: null,
        onboardingDone: true, userType: 'USER',
        city: city.name, cityId: city.id, countryCode: country.code,
        district: null, districtId: null,
        bio: generateBotBio({ locale, sportName: citySport.name, cityName: city.name }),
        instagram: null, tiktok: null, facebook: null, twitter: null, youtube: null,
        linkedin: null, discord: null, twitch: null, snapchat: null, telegram: null,
        whatsapp: null, vk: null, litmatch: null,
        sports: [citySport],
        level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
        gender: 'FEMALE',
        preferredTime: null, preferredStyle: null,
        birthDate: new Date(1992 + (femaleIdx % 13), femaleIdx % 12, 15).toISOString(),
        totalMatches: 0, currentStreak: 0, longestStreak: 0, totalPoints: 0,
        followerCount: 0, followingCount: 0, averageRating: 0, ratingCount: 0,
        isBanned: false, noShowCount: 0, isPrivate: false,
        createdAt: new Date().toISOString(),
      };

      store.users.push(maleBot, femaleBot);
      botsCreated += 2;

      // Create bot task — female bots create listings, male bots respond
      const task = {
        id: uuid(),
        listingBotId: femaleBot.id,
        responderBotId: maleBot.id,
        cityId: city.id,
        cityName: city.name,
        countryCode: country.code,
        sportId: citySport.id,
        sportName: citySport.name,
        status: 'PENDING',
        listingDateTime: dateTime.toISOString(),
        listingId: null,
        interestId: null,
        matchId: null,
        delaySeconds: 5 + Math.floor(Math.random() * 25),
        errorMessage: null,
        scheduledAt: new Date().toISOString(),
        executedAt: null,
        createdAt: new Date().toISOString(),
      };
      store.botTasks.push(task);
      tasksCreated++;
      taskIds.push(task.id);
    }
  }

  // Mark country as active
  country.isActive = true;

  // Execute tasks in background (non-blocking)
  executeBotTasks(taskIds).catch(err => console.error('Bot task execution error:', err));

  res.json({
    success: true,
    message: `${country.flag} ${country.name}: ${botsCreated} bot + ${tasksCreated} görev oluşturuldu (${cities.length} şehir)`,
    data: {
      botsCreated,
      tasksCreated,
      cities: cities.length,
      sportsUsed: sportPool.map(s => `${s.icon} ${s.name}`),
    },
  });
});

router.post('/countries/:id/deactivate', (req, res) => {
  const country = store.COUNTRIES.find(c => c.id === req.params.id);
  if (!country) return res.status(404).json({ message: 'Ülke bulunamadı.' });

  // Remove all bots for this country
  const botIds = store.users.filter(u => u.isBot && u.countryCode === country.code).map(u => u.id);
  const botIdSet = new Set(botIds);

  store.users.splice(0, store.users.length, ...store.users.filter(u => !u.isBot || u.countryCode !== country.code));
  store.listings.splice(0, store.listings.length, ...store.listings.filter(l => !botIdSet.has(l.userId)));
  store.posts.splice(0, store.posts.length, ...store.posts.filter(p => !botIdSet.has(p.userId)));
  store.interests.splice(0, store.interests.length, ...store.interests.filter(i => !botIdSet.has(i.userId)));
  store.matches.splice(0, store.matches.length, ...store.matches.filter(m => !botIdSet.has(m.user1Id) && !botIdSet.has(m.user2Id)));
  store.botTasks.splice(0, store.botTasks.length, ...store.botTasks.filter(t => t.countryCode !== country.code));

  country.isActive = false;

  res.json({
    message: `${country.flag} ${country.name} deaktif edildi. ${botIds.length} bot silindi.`,
    data: { botsRemoved: botIds.length },
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. BOT TASK MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/bot-tasks', (req, res) => {
  const status = req.query.status; // 'PENDING' | 'LISTING_CREATED' | 'RESPONSE_SENT' | 'MATCH_DONE' | 'FAILED'
  const countryCode = req.query.countryCode;

  let filtered = store.botTasks;
  if (status) filtered = filtered.filter(t => t.status === status);
  if (countryCode) filtered = filtered.filter(t => t.countryCode === countryCode);

  const items = filtered.map(t => ({
    ...t,
    listingBot: (() => { const u = store.users.find(x => x.id === t.listingBotId); return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl } : null; })(),
    responderBot: (() => { const u = store.users.find(x => x.id === t.responderBotId); return u ? { id: u.id, name: u.name, avatarUrl: u.avatarUrl } : null; })(),
  }));

  res.json({ data: items });
});

router.post('/bot-tasks/:id/execute', (req, res) => {
  const task = store.botTasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ message: 'Görev bulunamadı.' });
  if (task.status !== 'PENDING' && task.status !== 'FAILED') {
    return res.status(400).json({ message: `Görev zaten ${task.status} durumunda.` });
  }
  task.status = 'PENDING';
  executeBotTasks([task.id]).catch(console.error);
  res.json({ message: 'Görev yeniden başlatıldı.', data: task });
});

router.delete('/bot-tasks', (req, res) => {
  const { id, clearAll } = req.body;
  if (clearAll) {
    const before = store.botTasks.length;
    store.botTasks = store.botTasks.filter(t => t.status === 'PENDING' || t.status === 'LISTING_CREATED' || t.status === 'RESPONSE_SENT');
    const removed = before - store.botTasks.length;
    return res.json({ message: `${removed} g\u00f6rev silindi.` });
  }
  if (id) {
    const idx = store.botTasks.findIndex(t => t.id === id);
    if (idx !== -1) store.botTasks.splice(idx, 1);
    return res.json({ message: 'Görev silindi.' });
  }
  res.status(400).json({ message: 'id veya clearAll gerekli.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. BOT TASK EXECUTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════
async function executeBotTasks(taskIds) {
  for (const taskId of taskIds) {
    const task = store.botTasks.find(t => t.id === taskId);
    if (!task) continue;

    const listingBot = store.users.find(u => u.id === task.listingBotId);
    const responderBot = store.users.find(u => u.id === task.responderBotId);
    if (!listingBot || !responderBot) {
      task.status = 'FAILED';
      task.errorMessage = 'Bot kullanıcıları bulunamadı.';
      task.executedAt = new Date().toISOString();
      continue;
    }

    try {
      const locale = mapCountryCodeToLocale(task.countryCode || 'TR');
      const coords = estimateBotCoordinates({ citySeed: task.cityId || listingBot.cityId || task.id, countryCode: task.countryCode });

      // Step 1: Create listing
      const sportObj = store.SPORTS.find(s => s.id === task.sportId) || listingBot.sports[0];
      if (!sportObj) throw new Error('Bot\'un sporu yok');

      const listing = {
        id: uuid(),
        type: 'RIVAL',
        title: generateListingDesc({ name: listingBot.name, sport: sportObj.name, locale, city: task.cityName }),
        description: generateListingDesc({ name: listingBot.name, sport: sportObj.name, locale, city: task.cityName }),
        sportId: sportObj.id,
        sportName: sportObj.name,
        cityId: task.cityId || listingBot.cityId,
        cityName: task.cityName || listingBot.city || '',
        districtId: null, districtName: null,
        venueId: null, venueName: null,
        level: listingBot.level || 'BEGINNER',
        gender: 'ANY',
        date: task.listingDateTime || getFutureDate(1).toISOString(),
        imageUrls: [],
        status: 'ACTIVE',
        ageMin: null, ageMax: null,
        isRecurring: false, isAnonymous: false, isUrgent: false, isQuick: false,
        responseCount: 0,
        maxParticipants: 2,
        latitude: coords.latitude,
        longitude: coords.longitude,
        userId: listingBot.id,
        userName: listingBot.name,
        userAvatar: listingBot.avatarUrl,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(),
      };
      store.listings.push(listing);
      task.listingId = listing.id;
      task.status = 'LISTING_CREATED';

      // Step 2: Wait
      await sleep(task.delaySeconds ? task.delaySeconds * 1000 : 5000);

      // Step 3: Create interest (response)
      const interest = {
        id: uuid(),
        listingId: listing.id,
        userId: responderBot.id,
        userName: responderBot.name,
        userAvatar: responderBot.avatarUrl,
        message: generateResponseMsg(responderBot.name, locale),
        status: 'PENDING',
        createdAt: new Date().toISOString(),
      };
      store.interests.push(interest);
      listing.responseCount++;
      task.interestId = interest.id;
      task.status = 'RESPONSE_SENT';

      // Step 4: Auto-match (accept interest)
      interest.status = 'ACCEPTED';
      listing.status = 'MATCHED';

      const match = {
        id: uuid(),
        listingId: listing.id,
        user1Id: listingBot.id,
        user2Id: responderBot.id,
        status: 'SCHEDULED',
        u1Approved: false, u2Approved: false,
        scheduledAt: listing.date,
        completedAt: null,
        createdAt: new Date().toISOString(),
      };
      store.matches.push(match);
      task.matchId = match.id;
      task.status = 'MATCH_DONE';
      task.executedAt = new Date().toISOString();

      // Step 5: shadow post for social proof
      const shadowContent = generateShadowMatchText({
        locale,
        listingBotName: listingBot.name,
        responderBotName: responderBot.name,
        sportName: sportObj.name,
        cityName: task.cityName,
      });
      store.posts.push({
        id: uuid(),
        userId: listingBot.id,
        type: 'POST',
        content: shadowContent,
        imageUrls: [],
        likeCount: 0,
        commentCount: 0,
        createdAt: new Date().toISOString(),
      });

      // Update bot stats
      listingBot.totalMatches = (listingBot.totalMatches || 0) + 1;
      responderBot.totalMatches = (responderBot.totalMatches || 0) + 1;

      console.log(`✅ Task ${taskId}: ${listingBot.name} ↔ ${responderBot.name} (${task.cityName}) — MATCH_DONE`);
    } catch (err) {
      task.status = 'FAILED';
      task.errorMessage = err.message || String(err);
      task.executedAt = new Date().toISOString();
      console.error(`❌ Task ${taskId} failed:`, err.message);
    }
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. CHALLENGES MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/challenges', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const status = req.query.status; // 'PENDING' | 'ACCEPTED' | 'DECLINED' | 'CANCELLED' | 'ALL'

  let filtered = [...store.challenges];
  if (status && status !== 'ALL') {
    filtered = filtered.filter(c => c.status === status);
  }

  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit).map(c => {
    const sender = store.users.find(u => u.id === c.senderId);
    const receiver = store.users.find(u => u.id === c.receiverId);
    return {
      ...c,
      senderName: sender?.name || 'Bilinmiyor',
      receiverName: receiver?.name || 'Bilinmiyor',
    };
  });

  res.json({ data: { items, total, page, pageSize: limit, totalPages: Math.ceil(total / limit) } });
});

router.delete('/challenges/:id', (req, res) => {
  const idx = store.challenges.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Meydan okuma bulunamadı.' });
  store.challenges.splice(idx, 1);
  res.json({ message: 'Meydan okuma silindi.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 11. MATCHES MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/matches', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const status = req.query.status; // 'PENDING' | 'CONFIRMED' | 'COMPLETED' | 'CANCELLED' | 'ALL'

  let filtered = [...store.matches];
  if (status && status !== 'ALL') {
    filtered = filtered.filter(m => m.status === status);
  }

  filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit).map(m => {
    const user1 = store.users.find(u => u.id === m.user1Id);
    const user2 = store.users.find(u => u.id === m.user2Id);
    return {
      ...m,
      user1Name: user1?.name || 'Bilinmiyor',
      user2Name: user2?.name || 'Bilinmiyor',
    };
  });

  res.json({ data: { items, total, page, pageSize: limit, totalPages: Math.ceil(total / limit) } });
});

router.delete('/matches/:id', (req, res) => {
  const idx = store.matches.findIndex(m => m.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Eşleşme bulunamadı.' });
  store.matches.splice(idx, 1);
  res.json({ message: 'Eşleşme silindi.' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 12. BOT ECOSYSTEM — Grup Bazlı Canlandırma Motoru (In-Memory)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Kadın ağırlıklı spor dalları ───────────────────────────────────────────────
const FEMALE_SPORTS = ['yoga', 'pilates', 'hiking', 'running', 'swimming', 'cycling', 'dance', 'fitness'];

/**
 * GET /api/admin/ecosystems — Tüm ekosistemler
 */
router.get('/ecosystems', (req, res) => {
  const result = store.botEcosystems.map(eco => {
    const groups = store.botGroups.filter(g => g.ecosystemId === eco.id);
    const botIds = groups.flatMap(g => g.memberIds);
    const activeListings = store.listings.filter(l => botIds.includes(l.userId) && l.status === 'ACTIVE').length;
    const matchedListings = store.listings.filter(l => botIds.includes(l.userId) && l.status === 'MATCHED').length;
    return {
      ...eco,
      groupCount: groups.length,
      totalBots: botIds.length,
      activeListings,
      matchedListings,
    };
  });
  res.json({ data: result });
});

/**
 * POST /api/admin/ecosystems — Yeni ekosistem oluştur
 * Body: { scope: 'CITY'|'COUNTRY'|'WORLD', countryCode, cityId, cityName,
 *         sportIds, botsPerGroup: 7-8, maxParticipants: 3-6, groupsPerCity: 1-5 }
 */
router.post('/ecosystems', (req, res) => {
  try {
    const {
      scope = 'CITY',
      countryCode = 'TR',
      cityId, cityName,
      sportIds = [],
      botsPerGroup = 8,
      maxParticipants = 4,
      groupsPerCity = 1,
    } = req.body;

    if (scope === 'CITY' && (!cityId || !cityName)) {
      return res.status(400).json({ message: 'Şehir seçilmeli (cityId, cityName).' });
    }

    const perGroup = Math.min(10, Math.max(6, parseInt(botsPerGroup) || 8));
    const maxPart = Math.min(6, Math.max(3, parseInt(maxParticipants) || 4));
    const grpPerCity = Math.min(5, Math.max(1, parseInt(groupsPerCity) || 1));

    // Determine cities
    let cities = [];
    if (scope === 'CITY') {
      cities = [{ id: cityId, name: cityName, countryCode }];
    } else if (scope === 'COUNTRY') {
      cities = store.CITIES.map(c => ({ id: c.id, name: c.name, countryCode }));
    } else { // WORLD
      for (const country of store.COUNTRIES) {
        cities.push(...store.CITIES.map(c => ({ id: `${country.code}_${c.id}`, name: c.name, countryCode: country.code })));
      }
      // Limit for local dev
      cities = cities.slice(0, 15);
    }

    if (cities.length === 0) return res.status(400).json({ message: 'Şehir bulunamadı.' });

    // Get sports (prefer female-oriented)
    const allSports = store.SPORTS;
    let selectedSports = sportIds.length > 0
      ? allSports.filter(s => sportIds.includes(s.id))
      : allSports.filter(s => FEMALE_SPORTS.includes(s.id));
    if (selectedSports.length === 0) selectedSports = allSports.slice(0, 6);

    const locale = mapCountryCodeToLocale(countryCode || 'TR');
    const names = LOCALIZED_NAMES[countryCode] || DEFAULT_NAMES;

    let totalBots = 0, totalGroups = 0, totalListings = 0;
    const ecosystemIds = [];

    for (const city of cities) {
      // Check existing ecosystem
      const existing = store.botEcosystems.find(e => e.cityId === city.id && e.status === 'ACTIVE');
      if (existing) continue;

      const ecoId = 'eco_' + uuid();
      const ecoRecord = {
        id: ecoId,
        scope,
        countryCode: city.countryCode || countryCode,
        cityId: city.id,
        cityName: city.name,
        sportIds: selectedSports.map(s => s.id),
        maxParticipants: maxPart,
        botsPerGroup: perGroup,
        groupsPerCity: grpPerCity,
        status: 'ACTIVE',
        totalBots: 0,
        totalListings: 0,
        totalMatches: 0,
        createdAt: new Date().toISOString(),
      };
      store.botEcosystems.push(ecoRecord);
      ecosystemIds.push(ecoId);

      // Create groups for this city
      for (let g = 0; g < grpPerCity; g++) {
        const groupId = 'botgrp_' + uuid();
        const femalePct = 0.9; // %90 kadın
        const femaleCount = Math.round(perGroup * femalePct);
        const maleCount = perGroup - femaleCount;
        const memberIds = [];
        const members = [];

        for (let i = 0; i < perGroup; i++) {
          const isFemale = i < femaleCount;
          const gender = isFemale ? 'FEMALE' : 'MALE';
          const nameList = isFemale ? (names.female || names.FEMALE || DEFAULT_NAMES.female) : (names.male || names.MALE || DEFAULT_NAMES.male);
          const bName = nameList[(i + g * perGroup) % nameList.length];
          const sport = selectedSports[(i + g) % selectedSports.length];
          const botId = 'bot_' + uuid();

          // Fake follower/following counts (100-200)
          const fakeFollowers = 100 + Math.floor(Math.random() * 101);
          const fakeFollowing = 100 + Math.floor(Math.random() * 101);

          const socialPlatforms = ['instagram', 'tiktok', 'facebook', 'twitter'];
          const socialLinks = {};
          for (const p of socialPlatforms) {
            socialLinks[p] = `@${bName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_sport`;
          }

          const bot = {
            id: botId,
            email: `bot_${Date.now()}_${i}_${g}@sporpartner.internal`,
            name: bName,
            username: `bot_${bName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()}_${Date.now() % 10000}`,
            password: null,
            avatarUrl: buildBotAvatarUrl({ gender, seed: `${bName}-${city.id}-${sport.name}-${g}` }),
            coverUrl: buildBotAvatarUrl({ gender, seed: `cover-${bName}-${city.id}-${g}` }),
            phone: null,
            isAdmin: false,
            isBot: true,
            botGroupId: groupId,
            onboardingDone: true,
            userType: 'USER',
            city: city.name,
            cityId: city.id,
            countryCode: city.countryCode || countryCode,
            district: null,
            districtId: null,
            bio: generateBotBio({ locale, sportName: sport.name, cityName: city.name }),
            // Social links visible but not clickable (formalite)
            instagram: socialLinks.instagram,
            tiktok: socialLinks.tiktok,
            facebook: socialLinks.facebook,
            twitter: socialLinks.twitter,
            youtube: null, linkedin: null, discord: null, twitch: null,
            snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
            sports: [{ id: sport.id, name: sport.name, icon: sport.icon }],
            level: ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'][Math.floor(Math.random() * 3)],
            gender,
            preferredTime: ['MORNING', 'AFTERNOON', 'EVENING'][Math.floor(Math.random() * 3)],
            preferredStyle: 'CASUAL',
            birthDate: new Date(1990 + (i % 15), i % 12, 1 + (i % 28)).toISOString(),
            totalMatches: Math.floor(Math.random() * 20),
            currentStreak: Math.floor(Math.random() * 5),
            longestStreak: Math.floor(Math.random() * 10),
            totalPoints: Math.floor(Math.random() * 300),
            followerCount: fakeFollowers,
            followingCount: fakeFollowing,
            averageRating: parseFloat((3.5 + Math.random() * 1.5).toFixed(1)),
            ratingCount: 5 + Math.floor(Math.random() * 20),
            isBanned: false,
            noShowCount: 0,
            isPrivate: true, // Bot profiles are PRIVATE
            createdAt: new Date().toISOString(),
          };

          store.users.push(bot);
          memberIds.push(botId);
          members.push({ id: botId, name: bName, gender, sportId: sport.id });
          totalBots++;
        }

        // Create group record
        const group = {
          id: groupId,
          ecosystemId: ecoId,
          cityId: city.id,
          cityName: city.name,
          countryCode: city.countryCode || countryCode,
          leaderId: memberIds[0], // First female bot is leader
          memberIds,
          sportIds: selectedSports.map(s => s.id),
          maxParticipants: maxPart,
          status: 'ACTIVE',
          createdAt: new Date().toISOString(),
        };
        store.botGroups.push(group);
        totalGroups++;

        // Leader creates initial listing
        const leader = store.users.find(u => u.id === memberIds[0]);
        if (leader) {
          const sport = selectedSports[g % selectedSports.length];
          const futureDate = new Date(Date.now() + 24 * 3600 * 1000); // 24h later
          // Set to reasonable Pilates/Yoga hours (9:00-18:00)
          futureDate.setHours(9 + Math.floor(Math.random() * 9), 0, 0, 0);

          const listingId = 'listing_' + uuid();
          store.listings.push({
            id: listingId,
            type: 'PARTNER',
            title: generateListingDesc({ name: leader.name, sport: sport.name, locale, city: city.name }),
            description: generateListingDesc({ name: leader.name, sport: sport.name, locale, city: city.name }),
            sportId: sport.id,
            sportName: sport.name,
            cityId: city.id,
            cityName: city.name,
            districtId: null, districtName: null,
            venueId: null, venueName: null,
            level: leader.level || 'INTERMEDIATE',
            gender: 'ANY',
            date: futureDate.toISOString(),
            imageUrls: [],
            maxParticipants: maxPart,
            acceptedCount: 0,
            status: 'ACTIVE',
            ageMin: null, ageMax: null,
            isRecurring: false, isAnonymous: false, isUrgent: false, isQuick: false,
            responseCount: 0,
            userId: leader.id,
            userName: leader.name,
            userAvatar: leader.avatarUrl,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(futureDate.getTime() + 7 * 86400000).toISOString(),
          });
          totalListings++;
        }
      }

      // Update ecosystem record
      ecoRecord.totalBots = totalBots;
      ecoRecord.totalListings = totalListings;
    }

    res.json({
      success: true,
      message: `${cities.length} şehirde ${totalGroups} grup, ${totalBots} bot, ${totalListings} ilan oluşturuldu.`,
      data: { ecosystemIds, citiesAnimated: cities.length, totalGroups, totalBots, totalListings },
    });
  } catch (e) {
    console.error('Ecosystem create error:', e);
    res.status(500).json({ message: e.message });
  }
});

/**
 * POST /api/admin/ecosystems/:id/tick — Ekosistem saatlik güncelleme
 * 4 Faz: Başvurular → Kabuller (grup öncelikli + 4h kuralı) → Puanlama → Yeni İlanlar
 */
router.post('/ecosystems/:id/tick', (req, res) => {
  try {
    const eco = store.botEcosystems.find(e => e.id === req.params.id);
    if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });
    if (eco.status !== 'ACTIVE') return res.status(400).json({ message: 'Ekosistem aktif değil.' });

    const result = runLocalEcosystemTick(eco);
    res.json({ success: true, data: result });
  } catch (e) {
    console.error('Ecosystem tick error:', e);
    res.status(500).json({ message: e.message });
  }
});

/**
 * POST /api/admin/ecosystems/tick-all — Tüm aktif ekosistemlerin güncellenmesi
 */
router.post('/ecosystems/tick-all', (req, res) => {
  try {
    const active = store.botEcosystems.filter(e => e.status === 'ACTIVE');
    const results = [];
    for (const eco of active) {
      try {
        const r = runLocalEcosystemTick(eco);
        results.push({ ecoId: eco.id, cityName: eco.cityName, ...r });
      } catch (err) {
        results.push({ ecoId: eco.id, cityName: eco.cityName, error: err.message });
      }
    }
    res.json({ success: true, data: results, total: active.length });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

/**
 * PATCH /api/admin/ecosystems/:id — Ekosistem güncelle (pause/resume)
 */
router.patch('/ecosystems/:id', (req, res) => {
  const eco = store.botEcosystems.find(e => e.id === req.params.id);
  if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

  const { status } = req.body;
  if (status && ['ACTIVE', 'PAUSED'].includes(status)) eco.status = status;
  res.json({ data: eco });
});

/**
 * DELETE /api/admin/ecosystems/:id — Ekosistem sil (tüm botlar + veriler temizlenir)
 */
router.delete('/ecosystems/:id', (req, res) => {
  const eco = store.botEcosystems.find(e => e.id === req.params.id);
  if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

  // Find all groups & bot IDs
  const groups = store.botGroups.filter(g => g.ecosystemId === eco.id);
  const botIds = new Set(groups.flatMap(g => g.memberIds));

  // Remove bots' data
  for (const botId of botIds) {
    // Remove ratings
    for (let i = store.ratings.length - 1; i >= 0; i--) {
      if (store.ratings[i].raterId === botId || store.ratings[i].rateeId === botId) store.ratings.splice(i, 1);
    }
    // Remove interests
    for (let i = store.interests.length - 1; i >= 0; i--) {
      if (store.interests[i].userId === botId) store.interests.splice(i, 1);
    }
    // Remove listings
    for (let i = store.listings.length - 1; i >= 0; i--) {
      if (store.listings[i].userId === botId) store.listings.splice(i, 1);
    }
    // Remove matches
    for (let i = store.matches.length - 1; i >= 0; i--) {
      if (store.matches[i].user1Id === botId || store.matches[i].user2Id === botId) store.matches.splice(i, 1);
    }
    // Remove posts
    for (let i = store.posts.length - 1; i >= 0; i--) {
      if (store.posts[i].userId === botId) store.posts.splice(i, 1);
    }
    // Remove user
    const uIdx = store.users.findIndex(u => u.id === botId);
    if (uIdx !== -1) store.users.splice(uIdx, 1);
  }

  // Remove groups
  for (let i = store.botGroups.length - 1; i >= 0; i--) {
    if (store.botGroups[i].ecosystemId === eco.id) store.botGroups.splice(i, 1);
  }

  // Remove ecosystem
  const eIdx = store.botEcosystems.findIndex(e => e.id === eco.id);
  if (eIdx !== -1) store.botEcosystems.splice(eIdx, 1);

  res.json({ message: `${eco.cityName} ekosistemi silindi. ${botIds.size} bot temizlendi.`, data: { botsRemoved: botIds.size } });
});

/**
 * POST /api/admin/ecosystems/:id/toggle-bots-privacy — Bot profillerini public/private yap
 */
router.post('/ecosystems/:id/toggle-bots-privacy', (req, res) => {
  const eco = store.botEcosystems.find(e => e.id === req.params.id);
  if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

  const { isPrivate } = req.body;
  const groups = store.botGroups.filter(g => g.ecosystemId === eco.id);
  const botIds = new Set(groups.flatMap(g => g.memberIds));
  let updated = 0;
  for (const bot of store.users) {
    if (botIds.has(bot.id)) {
      bot.isPrivate = !!isPrivate;
      updated++;
    }
  }
  res.json({ message: `${updated} bot profili ${isPrivate ? 'gizli' : 'herkese açık'} yapıldı.` });
});

/**
 * GET /api/admin/ecosystems/:id/groups — Ekosistem grup detayları
 */
router.get('/ecosystems/:id/groups', (req, res) => {
  const eco = store.botEcosystems.find(e => e.id === req.params.id);
  if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

  const groups = store.botGroups.filter(g => g.ecosystemId === eco.id).map(g => {
    const members = g.memberIds.map(id => {
      const u = store.users.find(x => x.id === id);
      return u ? { id: u.id, name: u.name, gender: u.gender, avatarUrl: u.avatarUrl, isPrivate: u.isPrivate } : null;
    }).filter(Boolean);
    const activeListings = store.listings.filter(l => g.memberIds.includes(l.userId) && l.status === 'ACTIVE').length;
    return { ...g, members, activeListings };
  });
  res.json({ data: groups });
});

// ── Local Ecosystem Tick Engine ─────────────────────────────────────────────
function runLocalEcosystemTick(eco) {
  const stats = { newApplications: 0, newAcceptances: 0, newMatches: 0, newRatings: 0, newListings: 0 };

  const groups = store.botGroups.filter(g => g.ecosystemId === eco.id && g.status === 'ACTIVE');
  if (groups.length === 0) return stats;

  const allBotIds = new Set(groups.flatMap(g => g.memberIds));
  const locale = mapCountryCodeToLocale(eco.countryCode || 'TR');

  // ── FAZ 1: BAŞVURULAR — Grup üyeleri birbirlerinin ilanlarına başvurur ──
  for (const group of groups) {
    const activeListings = store.listings.filter(l =>
      group.memberIds.includes(l.userId) && l.status === 'ACTIVE'
    );

    for (const listing of activeListings) {
      // Group members apply first (except owner)
      const existingApplicants = new Set(
        store.interests.filter(i => i.listingId === listing.id).map(i => i.userId)
      );
      existingApplicants.add(listing.userId); // Owner can't apply

      const candidates = group.memberIds.filter(id => !existingApplicants.has(id));
      // Apply 2-3 per tick
      const toApply = candidates.slice(0, 2 + Math.floor(Math.random() * 2));

      for (const botId of toApply) {
        const bot = store.users.find(u => u.id === botId);
        if (!bot) continue;

        store.interests.push({
          id: uuid(),
          listingId: listing.id,
          userId: bot.id,
          userName: bot.name,
          userAvatar: bot.avatarUrl,
          message: generateResponseMsg(bot.name, locale),
          status: 'PENDING',
          createdAt: new Date().toISOString(),
        });
        listing.responseCount = (listing.responseCount || 0) + 1;
        stats.newApplications++;
      }
    }
  }

  // ── FAZ 2: KABULLER — Grup üyeleri önce kabul, son kişi 4 saat kuralı ──
  for (const group of groups) {
    const activeListings = store.listings.filter(l =>
      group.memberIds.includes(l.userId) && l.status === 'ACTIVE'
    );

    for (const listing of activeListings) {
      const slotsNeeded = Math.max(1, (listing.maxParticipants || 4) - 1);
      const currentAccepted = listing.acceptedCount || 0;
      if (currentAccepted >= slotsNeeded) continue;

      const pendingInterests = store.interests.filter(i =>
        i.listingId === listing.id && i.status === 'PENDING'
      );

      // Sort: group members first, then outsiders
      const groupMemberSet = new Set(group.memberIds);
      pendingInterests.sort((a, b) => {
        const aInGroup = groupMemberSet.has(a.userId) ? 0 : 1;
        const bInGroup = groupMemberSet.has(b.userId) ? 0 : 1;
        return aInGroup - bInGroup;
      });

      for (const interest of pendingInterests) {
        const acc = listing.acceptedCount || 0;
        if (acc >= slotsNeeded) break;

        const isLastSlot = (acc === slotsNeeded - 1);
        const listingDate = listing.date ? new Date(listing.date) : null;
        const hoursLeft = listingDate ? (listingDate.getTime() - Date.now()) / 3600000 : 999;

        // Last slot: wait until 4 hours before listing date
        if (isLastSlot && hoursLeft > 4) continue;

        // Accept
        interest.status = 'ACCEPTED';
        listing.acceptedCount = acc + 1;

        // Create match
        const matchId = 'match_' + uuid();
        store.matches.push({
          id: matchId,
          listingId: listing.id,
          user1Id: listing.userId,
          user2Id: interest.userId,
          status: 'SCHEDULED',
          u1Approved: false, u2Approved: false,
          scheduledAt: listing.date,
          completedAt: null,
          createdAt: new Date().toISOString(),
        });
        stats.newAcceptances++;
        stats.newMatches++;

        // Update bot match stats
        const u1 = store.users.find(u => u.id === listing.userId);
        const u2 = store.users.find(u => u.id === interest.userId);
        if (u1) u1.totalMatches = (u1.totalMatches || 0) + 1;
        if (u2) u2.totalMatches = (u2.totalMatches || 0) + 1;

        // If listing full, mark MATCHED + reject rest
        if (listing.acceptedCount >= slotsNeeded) {
          listing.status = 'MATCHED';
          store.interests
            .filter(i => i.listingId === listing.id && i.status === 'PENDING')
            .forEach(i => { i.status = 'REJECTED'; });
          break;
        }
      }
    }
  }

  // ── FAZ 3: PUANLAMA — Tamamlanan maçlarda botlar birbirini puanlar ──
  // (Kural: Bir kullanıcı bir diğerini aynı spor dalında sadece 1 kez puanlar, sonra düzenler)
  const scheduledMatches = store.matches.filter(m =>
    m.status === 'SCHEDULED' && allBotIds.has(m.user1Id) && allBotIds.has(m.user2Id)
  );

  for (const m of scheduledMatches) {
    // Auto-complete
    m.status = 'COMPLETED';
    m.u1Approved = true;
    m.u2Approved = true;
    m.completedAt = new Date().toISOString();

    const listing = store.listings.find(l => l.id === m.listingId);
    const sportId = listing?.sportId || null;

    for (const [raterId, rateeId] of [[m.user1Id, m.user2Id], [m.user2Id, m.user1Id]]) {
      // Check: one rating per sport per user pair
      const existingRating = store.ratings.find(r =>
        r.raterId === raterId && r.rateeId === rateeId && r.sportId === sportId
      );

      if (existingRating) {
        // Edit existing (not duplicate)
        existingRating.score = 3 + Math.floor(Math.random() * 3);
        existingRating.matchId = m.id;
        existingRating.updatedAt = new Date().toISOString();
      } else {
        const score = 3 + Math.floor(Math.random() * 3); // 3-5
        const comments = [
          'Harika partner! 🎾', 'Çok keyifli maçtı!', 'Tekrar oynamak isterim',
          'Great game!', 'Super Spiel!', 'Отличная игра!', '素晴らしい試合!',
        ];
        store.ratings.push({
          id: uuid(),
          matchId: m.id,
          raterId,
          rateeId,
          score,
          comment: comments[Math.floor(Math.random() * comments.length)],
          sportId,
          createdAt: new Date().toISOString(),
        });

        // Update ratee stats
        const ratee = store.users.find(u => u.id === rateeId);
        if (ratee) {
          const prevTotal = (ratee.averageRating || 0) * (ratee.ratingCount || 0);
          const newCount = (ratee.ratingCount || 0) + 1;
          ratee.averageRating = parseFloat(((prevTotal + score) / newCount).toFixed(2));
          ratee.ratingCount = newCount;
        }
        stats.newRatings++;
      }
    }
  }

  // ── FAZ 4: YENİ İLANLAR — Eşleşen ilanların yerine yeni ilan aç ──
  const allSports = store.SPORTS.filter(s => (eco.sportIds || []).includes(s.id));
  const validSports = allSports.length > 0 ? allSports : store.SPORTS.filter(s => FEMALE_SPORTS.includes(s.id));

  for (const group of groups) {
    // Female bots create listings (max 1 active per bot)
    const femaleBots = group.memberIds
      .map(id => store.users.find(u => u.id === id))
      .filter(u => u && u.gender === 'FEMALE');

    for (const bot of femaleBots) {
      const hasActive = store.listings.some(l => l.userId === bot.id && l.status === 'ACTIVE');
      if (hasActive) continue;

      // Rotate sport weekly
      const weekNumber = Math.floor(Date.now() / (7 * 86400000));
      const sportIndex = (weekNumber + femaleBots.indexOf(bot)) % validSports.length;
      const sport = validSports[sportIndex] || validSports[0];

      const futureDate = new Date(Date.now() + 24 * 3600 * 1000);
      futureDate.setHours(9 + Math.floor(Math.random() * 9), 0, 0, 0);

      store.listings.push({
        id: 'listing_' + uuid(),
        type: 'PARTNER',
        title: generateListingDesc({ name: bot.name, sport: sport.name, locale, city: eco.cityName }),
        description: generateListingDesc({ name: bot.name, sport: sport.name, locale, city: eco.cityName }),
        sportId: sport.id, sportName: sport.name,
        cityId: eco.cityId, cityName: eco.cityName,
        districtId: null, districtName: null,
        venueId: null, venueName: null,
        level: bot.level || 'INTERMEDIATE',
        gender: 'ANY',
        date: futureDate.toISOString(),
        imageUrls: [],
        maxParticipants: eco.maxParticipants || 4,
        acceptedCount: 0,
        status: 'ACTIVE',
        ageMin: null, ageMax: null,
        isRecurring: false, isAnonymous: false, isUrgent: false, isQuick: false,
        responseCount: 0,
        userId: bot.id, userName: bot.name, userAvatar: bot.avatarUrl,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(futureDate.getTime() + 7 * 86400000).toISOString(),
      });
      stats.newListings++;
    }
  }

  // Update ecosystem stats
  eco.totalMatches = (eco.totalMatches || 0) + stats.newMatches;
  eco.totalListings = (eco.totalListings || 0) + stats.newListings;
  eco.lastTickAt = new Date().toISOString();

  return stats;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 13. SINGLE REVIEW PER SPORT (Yorum kuralı)
// ═══════════════════════════════════════════════════════════════════════════════
// Kural: Bir kullanıcı bir diğerini aynı spor dalında yalnızca 1 kez yorumlayabilir.
// Bu kural hem botlar hem gerçek kullanıcılar için geçerlidir.
// NOT: Bu endpoint varolan rating endpoint'lerini tamamlar.

/**
 * GET /api/admin/ecosystems/:id/ratings — Ekosistem puanlama istatistikleri
 */
router.get('/ecosystems/:id/ratings', (req, res) => {
  const eco = store.botEcosystems.find(e => e.id === req.params.id);
  if (!eco) return res.status(404).json({ message: 'Ekosistem bulunamadı.' });

  const groups = store.botGroups.filter(g => g.ecosystemId === eco.id);
  const botIds = new Set(groups.flatMap(g => g.memberIds));

  const ecoRatings = store.ratings.filter(r => botIds.has(r.raterId) || botIds.has(r.rateeId));
  const avgScore = ecoRatings.length > 0
    ? parseFloat((ecoRatings.reduce((s, r) => s + r.score, 0) / ecoRatings.length).toFixed(2))
    : 0;

  res.json({
    data: {
      totalRatings: ecoRatings.length,
      averageScore: avgScore,
      recentRatings: ecoRatings.slice(-20).map(r => ({
        ...r,
        raterName: store.users.find(u => u.id === r.raterId)?.name || 'Bilinmiyor',
        rateeName: store.users.find(u => u.id === r.rateeId)?.name || 'Bilinmiyor',
      })),
    },
  });
});

module.exports = router;
