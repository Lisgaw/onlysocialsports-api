'use strict';
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');

// ─── Sabit sporlar ────────────────────────────────────────────────────────────
// ID'ler Flutter sport_constants.dart ile birebir eşleştirilmiştir.
const SPORTS = [
  { id: 'football',         name: 'Futbol',            icon: '⚽',  category: 'Top Sporları' },
  { id: 'basketball',       name: 'Basketbol',         icon: '🏀',  category: 'Top Sporları' },
  { id: 'volleyball',       name: 'Voleybol',          icon: '🏐',  category: 'Top Sporları' },
  { id: 'tennis',           name: 'Tenis',             icon: '🎾',  category: 'Raket Sporları' },
  { id: 'padel',            name: 'Padel',             icon: '🏓',  category: 'Raket Sporları' },
  { id: 'fitness',          name: 'Fitness',           icon: '💪',  category: 'Fitness ve Güç' },
  { id: 'swimming',         name: 'Yüzme',             icon: '🏊',  category: 'Su Sporları' },
  { id: 'running',          name: 'Koşu',              icon: '🏃',  category: 'Kardiyo' },
  { id: 'hiking',           name: 'Yürüyüş',           icon: '🥾',  category: 'Doğa ve Outdoor' },
  { id: 'yoga',             name: 'Yoga',              icon: '🧘',  category: 'Esneklik ve Zihin' },
  { id: 'pilates',          name: 'Pilates',           icon: '🤸',  category: 'Esneklik ve Zihin' },
  { id: 'cricket',          name: 'Kriket',            icon: '🏏',  category: 'Top Sporları' },
  { id: 'badminton',        name: 'Badminton',         icon: '🏸',  category: 'Raket Sporları' },
  { id: 'table_tennis',     name: 'Masa Tenisi',       icon: '🏓',  category: 'Raket Sporları' },
  { id: 'baseball',         name: 'Beyzbol',           icon: '⚾',  category: 'Top Sporları' },
  { id: 'kabaddi',          name: 'Kabaddi',           icon: '🤼',  category: 'Dövüş Sporları' },
  { id: 'martial_arts',     name: 'Dövüş Sanatları',   icon: '🥋',  category: 'Dövüş Sporları' },
  { id: 'archery',          name: 'Okçuluk',           icon: '🏹',  category: 'Doğa ve Outdoor' },
  { id: 'equestrian',       name: 'Binicilik',         icon: '🏇',  category: 'Doğa ve Outdoor' },
  { id: 'sand_surfing',     name: 'Kum Sörfü',         icon: '🏄',  category: 'Su Sporları' },
  { id: 'cycling',          name: 'Bisiklet',          icon: '🚴',  category: 'Doğa ve Outdoor' },
  { id: 'american_football',name: 'Amerikan Futbolu',  icon: '🏈',  category: 'Top Sporları' },
  { id: 'rugby',            name: 'Rugby',             icon: '🏉',  category: 'Top Sporları' },
  { id: 'ice_hockey',       name: 'Buz Hokeyi',        icon: '🏒',  category: 'Kış Sporları' },
  { id: 'handball',         name: 'Hentbol',           icon: '🤾',  category: 'Top Sporları' },
  { id: 'skateboarding',    name: 'Kaykay',            icon: '🛹',  category: 'Urban Sporlar' },
  { id: 'skating',          name: 'Paten',             icon: '⛸️', category: 'Urban Sporlar' },
  { id: 'surfing',          name: 'Sörf',              icon: '🏄',  category: 'Su Sporları' },
  { id: 'crossfit',         name: 'Crossfit',          icon: '🏋️', category: 'Fitness ve Güç' },
  { id: 'pickleball',       name: 'Pickleball',        icon: '🏓',  category: 'Raket Sporları' },
  { id: 'billiards',        name: 'Bilardo',           icon: '🎱',  category: 'Masa Sporları' },
  { id: 'darts',            name: 'Dart',              icon: '🎯',  category: 'Masa Sporları' },
  { id: 'bowling',          name: 'Bowling',           icon: '🎳',  category: 'Masa Sporları' },
  { id: 'fishing',          name: 'Balık Tutma',       icon: '🎣',  category: 'Su Sporları' },
  { id: 'paintball',        name: 'Paintball',         icon: '🔫',  category: 'Aksiyon Sporları' },
  { id: 'dance',            name: 'Dans',              icon: '💃',  category: 'Müzik ve Dans' },
];

// ─── Şehir / İlçe ─────────────────────────────────────────────────────────────
const CITIES = [
  { id: 'c1', name: 'İstanbul' },
  { id: 'c2', name: 'Ankara'   },
  { id: 'c3', name: 'İzmir'    },
  { id: 'c4', name: 'Bursa'    },
  { id: 'c5', name: 'Antalya'  },
];

const DISTRICTS = {
  c1: [
    { id: 'd1', name: 'Kadıköy',   cityId: 'c1', city: { name: 'İstanbul' } },
    { id: 'd2', name: 'Beşiktaş',  cityId: 'c1', city: { name: 'İstanbul' } },
    { id: 'd3', name: 'Şişli',     cityId: 'c1', city: { name: 'İstanbul' } },
    { id: 'd4', name: 'Üsküdar',   cityId: 'c1', city: { name: 'İstanbul' } },
  ],
  c2: [
    { id: 'd5', name: 'Çankaya',   cityId: 'c2', city: { name: 'Ankara' } },
    { id: 'd6', name: 'Keçiören',  cityId: 'c2', city: { name: 'Ankara' } },
  ],
  c3: [
    { id: 'd7', name: 'Konak',     cityId: 'c3', city: { name: 'İzmir' } },
    { id: 'd8', name: 'Bornova',   cityId: 'c3', city: { name: 'İzmir' } },
  ],
  c4: [{ id: 'd9', name: 'Osmangazi', cityId: 'c4', city: { name: 'Bursa' } }],
  c5: [{ id: 'd10', name: 'Muratpaşa', cityId: 'c5', city: { name: 'Antalya' } }],
};

// ─── Ülke veritabanı (country activation için) ──────────────────────────────
const COUNTRIES = [
  { id: 'country_tr', name: 'Türkiye',       code: 'TR', flag: '🇹🇷', isActive: false },
  { id: 'country_de', name: 'Almanya',       code: 'DE', flag: '🇩🇪', isActive: false },
  { id: 'country_gb', name: 'İngiltere',     code: 'GB', flag: '🇬🇧', isActive: false },
  { id: 'country_fr', name: 'Fransa',        code: 'FR', flag: '🇫🇷', isActive: false },
  { id: 'country_nl', name: 'Hollanda',      code: 'NL', flag: '🇳🇱', isActive: false },
  { id: 'country_us', name: 'ABD',           code: 'US', flag: '🇺🇸', isActive: false },
  { id: 'country_es', name: 'İspanya',       code: 'ES', flag: '🇪🇸', isActive: false },
  { id: 'country_it', name: 'İtalya',        code: 'IT', flag: '🇮🇹', isActive: false },
  { id: 'country_ru', name: 'Rusya',         code: 'RU', flag: '🇷🇺', isActive: false },
  { id: 'country_jp', name: 'Japonya',       code: 'JP', flag: '🇯🇵', isActive: false },
  { id: 'country_kr', name: 'Güney Kore',    code: 'KR', flag: '🇰🇷', isActive: false },
  { id: 'country_br', name: 'Brezilya',      code: 'BR', flag: '🇧🇷', isActive: false },
  { id: 'country_pt', name: 'Portekiz',      code: 'PT', flag: '🇵🇹', isActive: false },
  { id: 'country_in', name: 'Hindistan',     code: 'IN', flag: '🇮🇳', isActive: false },
  { id: 'country_au', name: 'Avustralya',    code: 'AU', flag: '🇦🇺', isActive: false },
  { id: 'country_ca', name: 'Kanada',        code: 'CA', flag: '🇨🇦', isActive: false },
  { id: 'country_sa', name: 'Suudi Arabistan', code: 'SA', flag: '🇸🇦', isActive: false },
  { id: 'country_eg', name: 'Mısır',         code: 'EG', flag: '🇪🇬', isActive: false },
  { id: 'country_az', name: 'Azerbaycan',    code: 'AZ', flag: '🇦🇿', isActive: false },
  { id: 'country_pk', name: 'Pakistan',      code: 'PK', flag: '🇵🇰', isActive: false },
  { id: 'country_gr', name: 'Yunanistan',    code: 'GR', flag: '🇬🇷', isActive: false },
  { id: 'country_bg', name: 'Bulgaristan',   code: 'BG', flag: '🇧🇬', isActive: false },
  { id: 'country_ge', name: 'Gürcistan',     code: 'GE', flag: '🇬🇪', isActive: false },
  { id: 'country_ar', name: 'Arjantin',      code: 'AR', flag: '🇦🇷', isActive: false },
];

// ─── In-memory tablolar ────────────────────────────────────────────────────────

const users = [];
const refreshTokens = new Set();
const listings = [];
const matches = [];
const conversations = [];
const messages = [];
const challenges = [];
const notifications = [];
const follows = [];
const blockedUsers = [];
const reports = [];
const interests = [];   // listing interest / applications
const ratings = [];
const communities = [];
const groups = [];
const groupMembers = [];
const posts = [];
const postReactions = [];   // {id, postId, userId, type: 'LIKE'|'LOVE'|'FIRE'|'STRONG'|'WOW'|'CLAP', createdAt}
const comments = [];
const commentLikes = [];
const botTasks = [];     // bot task orchestration
const otps = [];         // match OTP verification codes
const noshows = [];      // no-show reports
const botEcosystems = [];  // bot ecosystem records (city-level)
const botGroups = [];      // bot friend groups (7-8 bots per group)

// ─── Seed kullanıcılar ─────────────────────────────────────────────────────────
function seedUsers() {
  const hash1 = bcrypt.hashSync('Test123!', 10);
  const hash2 = bcrypt.hashSync('Admin123!', 10);

  const u1 = {
    id: 'user_1',
    email: 'test@sporpartner.com',
    name: 'Test Kullanıcı',
    username: 'testuser',
    password: hash1,
    avatarUrl: null,
    coverUrl: null,
    phone: null,
    isAdmin: false,
    onboardingDone: true,
    userType: 'USER',
    city: 'İstanbul',
    cityId: 'c1',
    district: 'Kadıköy',
    districtId: 'd1',
    bio: 'Futbol ve basketbol seviyorum!',
    instagram: null, tiktok: null, facebook: null,
    twitter: null, youtube: null, linkedin: null, discord: null, twitch: null,
    snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
    sports: [SPORTS[0], SPORTS[1]],
    level: 'INTERMEDIATE',
    gender: 'MALE',
    preferredTime: 'EVENING',
    preferredStyle: 'CASUAL',
    birthDate: '1995-06-15T00:00:00.000Z',
    totalMatches: 5,
    currentStreak: 2,
    longestStreak: 5,
    totalPoints: 120,
    followerCount: 3,
    followingCount: 2,
    averageRating: 4.2,
    ratingCount: 3,
    isBanned: false,
    noShowCount: 0,
    isPrivate: false,
    createdAt: new Date().toISOString(),
  };

  const u2 = {
    id: 'user_2',
    email: 'admin@sporpartner.com',
    name: 'Admin Kullanıcı',
    username: 'adminuser',
    password: hash2,
    avatarUrl: null,
    coverUrl: null,
    phone: null,
    isAdmin: true,
    onboardingDone: true,
    userType: 'USER',
    city: 'Ankara',
    cityId: 'c2',
    district: 'Çankaya',
    districtId: 'd5',
    bio: 'Tenis meraklısı.',
    instagram: null, tiktok: null, facebook: null,
    twitter: null, youtube: null, linkedin: null, discord: null, twitch: null,
    snapchat: null, telegram: null, whatsapp: null, vk: null, litmatch: null,
    sports: [SPORTS[2], SPORTS[4]],
    level: 'ADVANCED',
    gender: 'FEMALE',
    preferredTime: 'MORNING',
    preferredStyle: 'COMPETITIVE',
    birthDate: '1990-03-20T00:00:00.000Z',
    totalMatches: 12,
    currentStreak: 4,
    longestStreak: 10,
    totalPoints: 340,
    followerCount: 8,
    followingCount: 5,
    averageRating: 4.7,
    ratingCount: 9,
    isBanned: false,
    noShowCount: 0,
    isPrivate: false,
    createdAt: new Date().toISOString(),
  };

  users.push(u1, u2);

  // Seed listings
  listings.push({
    id: 'listing_1',
    type: 'RIVAL',
    title: 'Kadıköy\'de Futbol Rakibi Arıyorum',
    description: 'Hafta sonu maç yapmak istiyorum. Seviye orta.',
    sportId: 'football',
    sportName: 'Futbol',
    cityId: 'c1',
    cityName: 'İstanbul',
    districtId: 'd1',
    districtName: 'Kadıköy',
    venueId: null,
    venueName: null,
    level: 'INTERMEDIATE',
    gender: 'ANY',
    date: new Date(Date.now() + 3 * 24 * 3600 * 1000).toISOString(),
    imageUrls: [],
    status: 'ACTIVE',
    ageMin: null,
    ageMax: null,
    isRecurring: false,
    isAnonymous: false,
    isUrgent: false,
    isQuick: false,
    responseCount: 2,
    userId: 'user_2',
    userName: 'Admin Kullanıcı',
    userAvatar: null,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
  });

  listings.push({
    id: 'listing_2',
    type: 'PARTNER',
    title: 'Tenis Antrenman Partneri',
    description: 'Sabah antrenman için partner arıyorum.',
    sportId: 'tennis',
    sportName: 'Tenis',
    cityId: 'c2',
    cityName: 'Ankara',
    districtId: 'd5',
    districtName: 'Çankaya',
    venueId: null,
    venueName: null,
    level: 'ADVANCED',
    gender: 'ANY',
    date: new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString(),
    imageUrls: [],
    status: 'ACTIVE',
    ageMin: null,
    ageMax: null,
    isRecurring: true,
    isAnonymous: false,
    isUrgent: false,
    isQuick: false,
    responseCount: 1,
    userId: 'user_1',
    userName: 'Test Kullanıcı',
    userAvatar: null,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(),
  });

  // Seed communities
  communities.push({
    id: 'comm_1',
    type: 'CLUB',
    name: 'İstanbul Futbol Kulübü',
    description: 'İstanbul\'daki futbol severler için topluluk.',
    avatarUrl: null,
    website: null,
    isPrivate: false,
    sport: { id: 'football', name: 'Futbol', icon: '⚽' },
    city: { id: 'c1', name: 'İstanbul' },
    _count: { members: 24 },
    isMember: false,
    isPending: false,
  });

  communities.push({
    id: 'comm_2',
    type: 'GROUP',
    name: 'Ankara Koşu Grubu',
    description: 'Sabah koşuları için grup.',
    avatarUrl: null,
    website: null,
    isPrivate: false,
    sport: { id: 'running', name: 'Koşu', icon: '🏃' },
    city: { id: 'c2', name: 'Ankara' },
    _count: { members: 35 },
    isMember: false,
    isPending: false,
  });

  // Seed groups
  groups.push({
    id: 'group_1',
    name: 'Kadıköy Basketbol',
    description: 'Kadıköy\'de haftalık basketbol.',
    isPublic: true,
    avatarUrl: null,
    sport: { id: 'basketball', name: 'Basketbol', icon: '🏀' },
    city: { id: 'c1', name: 'İstanbul' },
    _count: { members: 12 },
  });
}

seedUsers();

module.exports = {
  SPORTS,
  CITIES,
  DISTRICTS,
  COUNTRIES,
  users,
  refreshTokens,
  listings,
  matches,
  conversations,
  messages,
  challenges,
  notifications,
  follows,
  blockedUsers,
  reports,
  interests,
  ratings,
  communities,
  groups,
  groupMembers,
  posts,
  postReactions,
  comments,
  commentLikes,
  botTasks,
  otps,
  noshows,
  botEcosystems,
  botGroups,
};
