'use strict';
const { v4: uuid } = require('uuid');

// ─── Hash seed (deterministic) ─────────────────────────────────────────────────
function hashSeed(seed) {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash << 5) - hash + seed.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// ─── Bot persona (deterministic per bot ID) ─────────────────────────────────────
// Returns one of 4 personality types, consistent for the lifetime of a bot.
function getBotPersona(botId) {
  const PERSONAS = ['competitive', 'social', 'trainer', 'casual'];
  return PERSONAS[hashSeed(String(botId || '')) % 4];
}

// ─── Country code → locale mapping ─────────────────────────────────────────────
function mapCountryCodeToLocale(code) {
  const c = (code || 'TR').toUpperCase();
  if (['TR'].includes(c)) return 'tr';
  if (['RU', 'BY', 'KZ', 'KG'].includes(c)) return 'ru';
  if (['DE', 'AT', 'CH'].includes(c)) return 'de';
  if (['FR', 'BE', 'LU'].includes(c)) return 'fr';
  if (['ES', 'MX', 'AR', 'CO', 'CL', 'PE'].includes(c)) return 'es';
  if (['JP'].includes(c)) return 'ja';
  if (['KR'].includes(c)) return 'ko';
  if (['PT', 'BR'].includes(c)) return 'pt';
  if (['IT'].includes(c)) return 'it';
  if (['AR', 'SA', 'EG', 'AE', 'IQ'].includes(c)) return 'ar';
  return 'en';
}

// ─── Deterministic + region-aware human avatar URL ───────────────────────────
// Requirement: bot avatars should look like real human photos (not illustrated).
// We use deterministic RandomUser portrait indices so each bot keeps a stable
// avatar while still varying by country/region profile.
const AVATAR_REGION_BY_COUNTRY = {
  // East Asia
  JP: 'EAST_ASIA',
  KR: 'EAST_ASIA',
  CN: 'EAST_ASIA',
  TW: 'EAST_ASIA',
  HK: 'EAST_ASIA',
  // South Asia
  IN: 'SOUTH_ASIA',
  PK: 'SOUTH_ASIA',
  BD: 'SOUTH_ASIA',
  LK: 'SOUTH_ASIA',
  NP: 'SOUTH_ASIA',
  // Middle East / nearby
  TR: 'MIDDLE_EAST',
  SA: 'MIDDLE_EAST',
  AE: 'MIDDLE_EAST',
  EG: 'MIDDLE_EAST',
  IQ: 'MIDDLE_EAST',
  IR: 'MIDDLE_EAST',
  AZ: 'MIDDLE_EAST',
  // Americas
  US: 'AMERICAS',
  CA: 'AMERICAS',
  MX: 'AMERICAS',
  BR: 'AMERICAS',
  AR: 'AMERICAS',
  CL: 'AMERICAS',
  CO: 'AMERICAS',
  PE: 'AMERICAS',
  // Europe (default for many countries in this project)
  DE: 'EUROPE',
  FR: 'EUROPE',
  GB: 'EUROPE',
  IT: 'EUROPE',
  ES: 'EUROPE',
  PT: 'EUROPE',
  NL: 'EUROPE',
  BE: 'EUROPE',
  LU: 'EUROPE',
  CH: 'EUROPE',
  AT: 'EUROPE',
  RU: 'EUROPE',
  BY: 'EUROPE',
  BG: 'EUROPE',
  GE: 'EUROPE',
  UA: 'EUROPE',
  GR: 'EUROPE',
};

const AVATAR_INDEX_POOLS = {
  GLOBAL: {
    male: [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23],
    female: [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24],
  },
  EUROPE: {
    male: [25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47],
    female: [26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48],
  },
  EAST_ASIA: {
    male: [49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71],
    female: [50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72],
  },
  SOUTH_ASIA: {
    male: [73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 95],
    female: [74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96],
  },
  MIDDLE_EAST: {
    male: [6, 18, 30, 42, 54, 66, 78, 90, 12, 24, 36, 48],
    female: [9, 21, 33, 45, 57, 69, 81, 93, 15, 27, 39, 51],
  },
  AMERICAS: {
    male: [10, 20, 32, 44, 56, 68, 80, 92, 14, 26, 38, 50],
    female: [11, 23, 35, 47, 59, 71, 83, 95, 17, 29, 41, 53],
  },
};

function resolveAvatarRegion(countryCode, locale) {
  const cc = String(countryCode || '').toUpperCase();
  if (cc && AVATAR_REGION_BY_COUNTRY[cc]) return AVATAR_REGION_BY_COUNTRY[cc];

  const lang = normalizeLocale(locale);
  if (lang === 'ja' || lang === 'ko' || lang === 'zh') return 'EAST_ASIA';
  if (lang === 'hi' || lang === 'ur' || lang === 'bn') return 'SOUTH_ASIA';
  if (lang === 'tr' || lang === 'ar' || lang === 'fa') return 'MIDDLE_EAST';
  if (lang === 'es' || lang === 'pt') return 'AMERICAS';
  if (lang === 'de' || lang === 'fr' || lang === 'it' || lang === 'ru') return 'EUROPE';
  return 'GLOBAL';
}

function buildBotAvatarUrl({ gender, seed, countryCode, locale }) {
  const isFemale = (gender || '').toUpperCase() === 'FEMALE';
  const group = isFemale ? 'women' : 'men';
  const safeSeed = String(seed || uuid());
  const region = resolveAvatarRegion(countryCode, locale);
  const regionPools = AVATAR_INDEX_POOLS[region] || AVATAR_INDEX_POOLS.GLOBAL;
  const pool = isFemale ? regionPools.female : regionPools.male;
  const idx = pool[hashSeed(`${safeSeed}-${region}-${group}`) % pool.length];
  return `https://randomuser.me/api/portraits/${group}/${idx}.jpg`;
}

// ─── Localized bot names by country code ────────────────────────────────────────
const LOCALIZED_NAMES = {
  TR: { male: ['Ahmet Y.', 'Mehmet K.', 'Ali R.', 'Mustafa B.', 'Emre S.', 'Burak T.', 'Murat D.', 'Hasan Ö.'], female: ['Ayşe M.', 'Fatma K.', 'Zeynep B.', 'Elif S.', 'Merve D.', 'Derya T.', 'Selin A.', 'Büşra Y.'] },
  DE: { male: ['Max M.', 'Felix S.', 'Lukas B.', 'Jonas W.', 'Leon K.', 'Tim H.', 'Paul F.', 'Niklas R.'], female: ['Anna S.', 'Lena M.', 'Sophie B.', 'Marie K.', 'Laura W.', 'Julia H.', 'Lisa F.', 'Sarah R.'] },
  GB: { male: ['James W.', 'Oliver S.', 'Harry B.', 'Jack T.', 'George M.', 'Charlie K.', 'Thomas R.', 'William H.'], female: ['Emma W.', 'Olivia S.', 'Amelia B.', 'Isla T.', 'Sophie M.', 'Mia K.', 'Charlotte R.', 'Emily H.'] },
  FR: { male: ['Lucas M.', 'Hugo D.', 'Louis B.', 'Nathan P.', 'Léo R.', 'Gabriel S.', 'Jules T.', 'Raphaël V.'], female: ['Emma D.', 'Léa M.', 'Chloé B.', 'Manon P.', 'Camille R.', 'Inès S.', 'Zoé T.', 'Jade V.'] },
  NL: { male: ['Sem V.', 'Daan B.', 'Lucas M.', 'Levi K.', 'Finn D.', 'Milan S.', 'Bram J.', 'Noah W.'], female: ['Emma V.', 'Sophie B.', 'Julia M.', 'Anna K.', 'Lotte D.', 'Sara S.', 'Mila J.', 'Lisa W.'] },
  US: { male: ['James S.', 'John W.', 'Robert B.', 'Michael T.', 'David K.', 'Chris M.', 'Daniel H.', 'Matthew R.'], female: ['Emily S.', 'Sarah W.', 'Jessica B.', 'Ashley T.', 'Jennifer K.', 'Amanda M.', 'Megan H.', 'Rachel R.'] },
  AZ: { male: ['Əli M.', 'Rəşad K.', 'Tural B.', 'Orxan S.', 'Elşən D.', 'Farid T.', 'Murad A.', 'Nicat Y.'], female: ['Aygün M.', 'Günel K.', 'Ləman B.', 'Nərmin S.', 'Səbinə D.', 'Fidan T.', 'Aynur A.', 'Rəna Y.'] },
  RU: { male: ['Дмитрий К.', 'Алексей С.', 'Иван П.', 'Михаил В.', 'Сергей Н.', 'Андрей М.', 'Никита Л.', 'Артём Б.'], female: ['Анна К.', 'Мария С.', 'Елена П.', 'Ольга В.', 'Наталья Н.', 'Екатерина М.', 'Ирина Л.', 'Дарья Б.'] },
  SA: { male: ['Mohammed A.', 'Ahmed S.', 'Abdullah K.', 'Khalid M.', 'Faisal R.', 'Omar T.', 'Sultan B.', 'Fahad N.'], female: ['Fatima A.', 'Noura S.', 'Sara K.', 'Maryam M.', 'Lama R.', 'Haya T.', 'Reem B.', 'Amal N.'] },
  IT: { male: ['Marco R.', 'Luca B.', 'Alessandro M.', 'Francesco T.', 'Andrea S.', 'Matteo P.', 'Lorenzo G.', 'Davide F.'], female: ['Giulia R.', 'Francesca B.', 'Sara M.', 'Chiara T.', 'Valentina S.', 'Alessia P.', 'Elena G.', 'Martina F.'] },
  ES: { male: ['Carlos M.', 'Javier S.', 'Miguel R.', 'Alejandro B.', 'David T.', 'Pablo K.', 'Daniel G.', 'Adrián F.'], female: ['María M.', 'Lucía S.', 'Carmen R.', 'Ana B.', 'Laura T.', 'Marta K.', 'Paula G.', 'Sara F.'] },
  JP: { male: ['Yuto T.', 'Haruto S.', 'Sota M.', 'Ren K.', 'Kaito N.', 'Riku H.', 'Hinata Y.', 'Hayato O.'], female: ['Yui T.', 'Hana S.', 'Aoi M.', 'Sakura K.', 'Rin N.', 'Mio H.', 'Yuna Y.', 'Koharu O.'] },
  KR: { male: ['Minjun K.', 'Seoho L.', 'Jihoon P.', 'Hyunwoo C.', 'Donghyun J.', 'Sungmin Y.', 'Jaeho S.', 'Wonjin H.'], female: ['Jiyeon K.', 'Soyeon L.', 'Hayun P.', 'Minji C.', 'Yuna J.', 'Seoyeon Y.', 'Chaeyoung S.', 'Somin H.'] },
  BR: { male: ['Lucas S.', 'Gabriel O.', 'Mateus F.', 'Pedro A.', 'Gustavo M.', 'Rafael C.', 'Bruno L.', 'Thiago R.'], female: ['Ana S.', 'Julia O.', 'Maria F.', 'Camila A.', 'Beatriz M.', 'Larissa C.', 'Isabela L.', 'Fernanda R.'] },
  PT: { male: ['João S.', 'Pedro M.', 'Miguel R.', 'Tiago B.', 'Diogo T.', 'André K.', 'Rui G.', 'Nuno F.'], female: ['Ana S.', 'Maria M.', 'Inês R.', 'Sofia B.', 'Mariana T.', 'Catarina K.', 'Beatriz G.', 'Joana F.'] },
  IN: { male: ['Arjun S.', 'Rohan K.', 'Vikram P.', 'Aditya M.', 'Karan B.', 'Rahul T.', 'Varun G.', 'Ankit D.'], female: ['Priya S.', 'Ananya K.', 'Divya P.', 'Sneha M.', 'Pooja B.', 'Neha T.', 'Kavya G.', 'Meera D.'] },
  GR: { male: ['Giorgos P.', 'Nikos K.', 'Dimitris M.', 'Kostas S.', 'Yannis T.', 'Alexandros V.', 'Panagiotis R.', 'Christos B.'], female: ['Maria P.', 'Eleni K.', 'Katerina M.', 'Sofia S.', 'Dimitra T.', 'Anna V.', 'Christina R.', 'Ioanna B.'] },
  EG: { male: ['Ahmed M.', 'Omar S.', 'Mohamed K.', 'Youssef A.', 'Hassan B.', 'Ali T.', 'Khalid R.', 'Amr N.'], female: ['Fatma M.', 'Nour S.', 'Sara K.', 'Mariam A.', 'Hana B.', 'Dina T.', 'Aya R.', 'Yasmin N.'] },
  AU: { male: ['Jack M.', 'Oliver S.', 'Liam B.', 'Noah T.', 'William K.', 'James R.', 'Thomas H.', 'Ethan W.'], female: ['Charlotte M.', 'Olivia S.', 'Amelia B.', 'Isla T.', 'Mia K.', 'Ava R.', 'Grace H.', 'Chloe W.'] },
  CA: { male: ['Liam M.', 'Noah S.', 'Ethan B.', 'Lucas T.', 'Benjamin K.', 'Oliver R.', 'James H.', 'Alexander W.'], female: ['Emma M.', 'Olivia S.', 'Ava B.', 'Sophie T.', 'Isabella K.', 'Mia R.', 'Charlotte H.', 'Amelia W.'] },
  PK: { male: ['Ali K.', 'Hassan M.', 'Usman A.', 'Bilal S.', 'Hamza R.', 'Zain T.', 'Fahad B.', 'Ahmed N.'], female: ['Ayesha K.', 'Fatima M.', 'Sana A.', 'Hira S.', 'Maryam R.', 'Zara T.', 'Amna B.', 'Nadia N.'] },
  BG: { male: ['Georgi I.', 'Dimitar P.', 'Ivan S.', 'Nikolay K.', 'Stefan M.', 'Alexander T.', 'Boris V.', 'Plamen R.'], female: ['Maria I.', 'Elena P.', 'Iva S.', 'Daniela K.', 'Tsvetana M.', 'Nadya T.', 'Desislava V.', 'Rositsa R.'] },
  GE: { male: ['Giorgi T.', 'Lasha M.', 'Nikoloz K.', 'Davit S.', 'Levan B.', 'Goga P.', 'Vakhtang R.', 'Zurab A.'], female: ['Nino T.', 'Mariam M.', 'Tamar K.', 'Ana S.', 'Eka B.', 'Lika P.', 'Salome R.', 'Maka A.'] },
};

const DEFAULT_NAMES = {
  male: ['Alex K.', 'Max S.', 'Sam B.', 'Leo T.', 'Dan M.', 'Ben R.', 'Tom H.', 'Jack W.'],
  female: ['Anna K.', 'Lisa S.', 'Emma B.', 'Sara T.', 'Mia M.', 'Amy R.', 'Eva H.', 'Zoe W.'],
};

// ─── Sport name localization ────────────────────────────────────────────────
const SPORT_NAME_EN_BY_ID = {
  football: 'Football',
  basketball: 'Basketball',
  volleyball: 'Volleyball',
  tennis: 'Tennis',
  padel: 'Padel',
  fitness: 'Fitness',
  swimming: 'Swimming',
  running: 'Running',
  hiking: 'Hiking',
  yoga: 'Yoga',
  pilates: 'Pilates',
  cricket: 'Cricket',
  badminton: 'Badminton',
  table_tennis: 'Table Tennis',
  baseball: 'Baseball',
  kabaddi: 'Kabaddi',
  martial_arts: 'Martial Arts',
  archery: 'Archery',
  equestrian: 'Equestrian',
  sand_surfing: 'Sand Surfing',
  cycling: 'Cycling',
  american_football: 'American Football',
  rugby: 'Rugby',
  ice_hockey: 'Ice Hockey',
  handball: 'Handball',
  skateboarding: 'Skateboarding',
  skating: 'Skating',
  surfing: 'Surfing',
  crossfit: 'CrossFit',
  pickleball: 'Pickleball',
  billiards: 'Billiards',
  darts: 'Darts',
  bowling: 'Bowling',
  fishing: 'Fishing',
  paintball: 'Paintball',
  dance: 'Dance',
  okey: 'Okey',
  tavla: 'Backgammon',
  satranc: 'Chess',
  karting: 'Karting',
};

const SPORT_NAME_LOCALE_OVERRIDES = {
  tr: {
    football: 'Futbol',
    basketball: 'Basketbol',
    volleyball: 'Voleybol',
    tennis: 'Tenis',
    padel: 'Padel',
    fitness: 'Fitness',
    swimming: 'Yüzme',
    running: 'Koşu',
    hiking: 'Yürüyüş',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Kriket',
    badminton: 'Badminton',
    table_tennis: 'Masa Tenisi',
    baseball: 'Beyzbol',
    kabaddi: 'Kabaddi',
    martial_arts: 'Dövüş Sanatları',
    archery: 'Okçuluk',
    equestrian: 'Binicilik',
    sand_surfing: 'Kum Sörfü',
    cycling: 'Bisiklet',
    american_football: 'Amerikan Futbolu',
    rugby: 'Rugby',
    ice_hockey: 'Buz Hokeyi',
    handball: 'Hentbol',
    skateboarding: 'Kaykay',
    skating: 'Paten',
    surfing: 'Sörf',
    crossfit: 'Crossfit',
    pickleball: 'Pickleball',
    billiards: 'Bilardo',
    darts: 'Dart',
    bowling: 'Bowling',
    fishing: 'Balık Tutma',
    paintball: 'Paintball',
    dance: 'Dans',
    okey: 'Okey',
    tavla: 'Tavla',
    satranc: 'Satranç',
    karting: 'Karting',
  },
  en: {
    football: 'Football',
    basketball: 'Basketball',
    volleyball: 'Volleyball',
    tennis: 'Tennis',
    padel: 'Padel',
    fitness: 'Fitness',
    swimming: 'Swimming',
    running: 'Running',
    hiking: 'Hiking',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Cricket',
    badminton: 'Badminton',
    table_tennis: 'Table Tennis',
    baseball: 'Baseball',
    kabaddi: 'Kabaddi',
    martial_arts: 'Martial Arts',
    archery: 'Archery',
    equestrian: 'Equestrian',
    sand_surfing: 'Sand Surfing',
    cycling: 'Cycling',
    american_football: 'American Football',
    rugby: 'Rugby',
    ice_hockey: 'Ice Hockey',
    handball: 'Handball',
    skateboarding: 'Skateboarding',
    skating: 'Skating',
    surfing: 'Surfing',
    crossfit: 'Crossfit',
    pickleball: 'Pickleball',
    billiards: 'Billiards',
    darts: 'Darts',
    bowling: 'Bowling',
    fishing: 'Fishing',
    paintball: 'Paintball',
    dance: 'Dance',
    okey: 'Okey',
    tavla: 'Backgammon',
    satranc: 'Chess',
    karting: 'Karting',
  },
  ar: {
    football: 'كرة القدم',
    basketball: 'كرة السلة',
    volleyball: 'الكرة الطائرة',
    tennis: 'التنس',
    padel: 'البادل',
    fitness: 'اللياقة البدنية',
    swimming: 'السباحة',
    running: 'الجري',
    hiking: 'المشي',
    yoga: 'اليوغا',
    pilates: 'البيلاتس',
    cricket: 'الكريكيت',
    badminton: 'الريشة الطائرة',
    table_tennis: 'تنس الطاولة',
    baseball: 'البيسبول',
    kabaddi: 'الكبادي',
    martial_arts: 'الفنون القتالية',
    archery: 'الرماية بالقوس',
    equestrian: 'الفروسية',
    sand_surfing: 'ركوب الأمواج الرملية',
    cycling: 'ركوب الدراجات',
    american_football: 'كرة القدم الأمريكية',
    rugby: 'الرغبي',
    ice_hockey: 'هوكي الجليد',
    handball: 'كرة اليد',
    skateboarding: 'التزلج على الألواح',
    skating: 'التزلج',
    surfing: 'ركوب الأمواج',
    crossfit: 'كروسفيت',
    pickleball: 'بيكلبول',
    billiards: 'البلياردو',
    darts: 'رمي السهام',
    bowling: 'البولينغ',
    fishing: 'صيد السمك',
    paintball: 'بينتبول',
    dance: 'رقص',
    okey: 'أوكي',
    tavla: 'طاولة الزهر',
    satranc: 'شطرنج',
    karting: 'كارتينج',
  },
  de: {
    football: 'Fußball',
    basketball: 'Basketball',
    volleyball: 'Volleyball',
    tennis: 'Tennis',
    padel: 'Padel',
    fitness: 'Fitness',
    swimming: 'Schwimmen',
    running: 'Laufen',
    hiking: 'Wandern',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Cricket',
    badminton: 'Badminton',
    table_tennis: 'Tischtennis',
    baseball: 'Baseball',
    kabaddi: 'Kabaddi',
    martial_arts: 'Kampfkunst',
    archery: 'Bogenschießen',
    equestrian: 'Reiten',
    sand_surfing: 'Sandsurfen',
    cycling: 'Radfahren',
    american_football: 'American Football',
    rugby: 'Rugby',
    ice_hockey: 'Eishockey',
    handball: 'Handball',
    skateboarding: 'Skateboarding',
    skating: 'Eislaufen',
    surfing: 'Surfen',
    crossfit: 'CrossFit',
    pickleball: 'Pickleball',
    billiards: 'Billard',
    darts: 'Darts',
    bowling: 'Bowling',
    fishing: 'Angeln',
    paintball: 'Paintball',
    dance: 'Tanz',
    okey: 'Okey',
    tavla: 'Backgammon',
    satranc: 'Schach',
    karting: 'Karting',
  },
  es: {
    football: 'Fútbol',
    basketball: 'Baloncesto',
    volleyball: 'Voleibol',
    tennis: 'Tenis',
    padel: 'Pádel',
    fitness: 'Fitness',
    swimming: 'Natación',
    running: 'Correr',
    hiking: 'Senderismo',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Críquet',
    badminton: 'Bádminton',
    table_tennis: 'Tenis de mesa',
    baseball: 'Béisbol',
    kabaddi: 'Kabaddi',
    martial_arts: 'Artes marciales',
    archery: 'Tiro con arco',
    equestrian: 'Equitación',
    sand_surfing: 'Surf de arena',
    cycling: 'Ciclismo',
    american_football: 'Fútbol americano',
    rugby: 'Rugby',
    ice_hockey: 'Hockey sobre hielo',
    handball: 'Balonmano',
    skateboarding: 'Skateboarding',
    skating: 'Patinaje',
    surfing: 'Surf',
    crossfit: 'CrossFit',
    pickleball: 'Pickleball',
    billiards: 'Billar',
    darts: 'Dardos',
    bowling: 'Bolos',
    fishing: 'Pesca',
    paintball: 'Paintball',
    dance: 'Baile',
    okey: 'Okey',
    tavla: 'Backgammon',
    satranc: 'Ajedrez',
    karting: 'Karting',
  },
  fr: {
    football: 'Football',
    basketball: 'Basketball',
    volleyball: 'Volley-ball',
    tennis: 'Tennis',
    padel: 'Padel',
    fitness: 'Fitness',
    swimming: 'Natation',
    running: 'Course à pied',
    hiking: 'Randonnée',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Cricket',
    badminton: 'Badminton',
    table_tennis: 'Tennis de table',
    baseball: 'Baseball',
    kabaddi: 'Kabaddi',
    martial_arts: 'Arts martiaux',
    archery: 'Tir à l\'arc',
    equestrian: 'Équitation',
    sand_surfing: 'Surf des sables',
    cycling: 'Cyclisme',
    american_football: 'Football américain',
    rugby: 'Rugby',
    ice_hockey: 'Hockey sur glace',
    handball: 'Handball',
    skateboarding: 'Skateboard',
    skating: 'Patinage',
    surfing: 'Surf',
    crossfit: 'CrossFit',
    pickleball: 'Pickleball',
    billiards: 'Billard',
    darts: 'Fléchettes',
    bowling: 'Bowling',
    fishing: 'Pêche',
    paintball: 'Paintball',
    dance: 'Danse',
    okey: 'Okey',
    tavla: 'Backgammon',
    satranc: 'Échecs',
    karting: 'Karting',
  },
  pt: {
    football: 'Futebol',
    basketball: 'Basquete',
    volleyball: 'Vôlei',
    tennis: 'Tênis',
    padel: 'Padel',
    fitness: 'Fitness',
    swimming: 'Natação',
    running: 'Corrida',
    hiking: 'Caminhada',
    yoga: 'Yoga',
    pilates: 'Pilates',
    cricket: 'Críquete',
    badminton: 'Badminton',
    table_tennis: 'Tênis de mesa',
    baseball: 'Beisebol',
    kabaddi: 'Kabaddi',
    martial_arts: 'Artes marciais',
    archery: 'Tiro com arco',
    equestrian: 'Equitação',
    sand_surfing: 'Surfe na areia',
    cycling: 'Ciclismo',
    american_football: 'Futebol americano',
    rugby: 'Rúgbi',
    ice_hockey: 'Hóquei no gelo',
    handball: 'Handebol',
    skateboarding: 'Skate',
    skating: 'Patinação',
    surfing: 'Surfe',
    crossfit: 'CrossFit',
    pickleball: 'Pickleball',
    billiards: 'Bilhar',
    darts: 'Dardos',
    bowling: 'Boliche',
    fishing: 'Pesca',
    paintball: 'Paintball',
    dance: 'Dança',
    okey: 'Okey',
    tavla: 'Gamão',
    satranc: 'Xadrez',
    karting: 'Karting',
  },
  ru: {
    football: 'Футбол',
    basketball: 'Баскетбол',
    volleyball: 'Волейбол',
    tennis: 'Теннис',
    padel: 'Падель',
    fitness: 'Фитнес',
    swimming: 'Плавание',
    running: 'Бег',
    hiking: 'Пешие прогулки',
    yoga: 'Йога',
    pilates: 'Пилатес',
    cricket: 'Крикет',
    badminton: 'Бадминтон',
    table_tennis: 'Настольный теннис',
    baseball: 'Бейсбол',
    kabaddi: 'Кабадди',
    martial_arts: 'Боевые искусства',
    archery: 'Стрельба из лука',
    equestrian: 'Верховая езда',
    sand_surfing: 'Сэндсёрфинг',
    cycling: 'Велоспорт',
    american_football: 'Американский футбол',
    rugby: 'Регби',
    ice_hockey: 'Хоккей',
    handball: 'Гандбол',
    skateboarding: 'Скейтбординг',
    skating: 'Катание на коньках',
    surfing: 'Сёрфинг',
    crossfit: 'Кроссфит',
    pickleball: 'Пиклбол',
    billiards: 'Бильярд',
    darts: 'Дартс',
    bowling: 'Боулинг',
    fishing: 'Рыбалка',
    paintball: 'Пейнтбол',
    dance: 'Танцы',
    okey: 'Окей',
    tavla: 'Нарды',
    satranc: 'Шахматы',
    karting: 'Картинг',
  },
  ja: {
    football: 'サッカー',
    basketball: 'バスケットボール',
    volleyball: 'バレーボール',
    tennis: 'テニス',
    padel: 'パデル',
    fitness: 'フィットネス',
    swimming: '水泳',
    running: 'ランニング',
    hiking: 'ハイキング',
    yoga: 'ヨガ',
    pilates: 'ピラティス',
    cricket: 'クリケット',
    badminton: 'バドミントン',
    table_tennis: '卓球',
    baseball: '野球',
    kabaddi: 'カバディ',
    martial_arts: '武道',
    archery: 'アーチェリー',
    equestrian: '乗馬',
    sand_surfing: 'サンドサーフィン',
    cycling: 'サイクリング',
    american_football: 'アメリカンフットボール',
    rugby: 'ラグビー',
    ice_hockey: 'アイスホッケー',
    handball: 'ハンドボール',
    skateboarding: 'スケートボード',
    skating: 'スケート',
    surfing: 'サーフィン',
    crossfit: 'クロスフィット',
    pickleball: 'ピックルボール',
    billiards: 'ビリヤード',
    darts: 'ダーツ',
    bowling: 'ボウリング',
    fishing: '釣り',
    paintball: 'ペイントボール',
    dance: 'ダンス',
    okey: 'オーケー',
    tavla: 'バックギャモン',
    satranc: 'チェス',
    karting: 'カート',
  },
  zh: {
    football: '足球',
    basketball: '篮球',
    volleyball: '排球',
    tennis: '网球',
    padel: '板式网球',
    fitness: '健身',
    swimming: '游泳',
    running: '跑步',
    hiking: '徒步',
    yoga: '瑜伽',
    pilates: '普拉提',
    cricket: '板球',
    badminton: '羽毛球',
    table_tennis: '乒乓球',
    baseball: '棒球',
    kabaddi: '卡巴迪',
    martial_arts: '武术',
    archery: '射箭',
    equestrian: '马术',
    sand_surfing: '沙地冲浪',
    cycling: '骑行',
    american_football: '美式橄榄球',
    rugby: '橄榄球',
    ice_hockey: '冰球',
    handball: '手球',
    skateboarding: '滑板',
    skating: '滑冰',
    surfing: '冲浪',
    crossfit: 'CrossFit',
    pickleball: '匹克球',
    billiards: '台球',
    darts: '飞镖',
    bowling: '保龄球',
    fishing: '钓鱼',
    paintball: '彩弹',
    dance: '舞蹈',
    okey: 'Okey',
    tavla: '双陆棋',
    satranc: '国际象棋',
    karting: '卡丁车',
  },
  hi: {
    football: 'फुटबॉल',
    basketball: 'बास्केटबॉल',
    volleyball: 'वॉलीबॉल',
    tennis: 'टेनिस',
    padel: 'पैडल',
    fitness: 'फिटनेस',
    swimming: 'तैराकी',
    running: 'दौड़',
    hiking: 'पैदल यात्रा',
    yoga: 'योग',
    pilates: 'पिलाटीज़',
    cricket: 'क्रिकेट',
    badminton: 'बैडमिंटन',
    table_tennis: 'टेबल टेनिस',
    baseball: 'बेसबॉल',
    kabaddi: 'कबड्डी',
    martial_arts: 'मार्शल आर्ट्स',
    archery: 'तीरंदाज़ी',
    equestrian: 'घुड़सवारी',
    sand_surfing: 'सैंड सर्फिंग',
    cycling: 'साइकिलिंग',
    american_football: 'अमेरिकी फुटबॉल',
    rugby: 'रग्बी',
    ice_hockey: 'आइस हॉकी',
    handball: 'हैंडबॉल',
    skateboarding: 'स्केटबोर्डिंग',
    skating: 'स्केटिंग',
    surfing: 'सर्फिंग',
    crossfit: 'क्रॉसफिट',
    pickleball: 'पिकलबॉल',
    billiards: 'बिलियर्ड्स',
    darts: 'डार्ट्स',
    bowling: 'बॉलिंग',
    fishing: 'मछली पकड़ना',
    paintball: 'पेंटबॉल',
    dance: 'नृत्य',
    okey: 'ओके',
    tavla: 'बैकगैमोन',
    satranc: 'शतरंज',
    karting: 'कार्टिंग',
  },
  bn: {
    football: 'ফুটবল',
    basketball: 'বাস্কেটবল',
    volleyball: 'ভলিবল',
    tennis: 'টেনিস',
    padel: 'প্যাডেল',
    fitness: 'ফিটনেস',
    swimming: 'সাঁতার',
    running: 'দৌড়',
    hiking: 'হাইকিং',
    yoga: 'যোগব্যায়াম',
    pilates: 'পাইলেটস',
    cricket: 'ক্রিকেট',
    badminton: 'ব্যাডমিন্টন',
    table_tennis: 'টেবিল টেনিস',
    baseball: 'বেসবল',
    kabaddi: 'কাবাডি',
    martial_arts: 'মার্শাল আর্ট',
    archery: 'তীরন্দাজি',
    equestrian: 'ঘোড়সওয়ারি',
    sand_surfing: 'স্যান্ড সার্ফিং',
    cycling: 'সাইক্লিং',
    american_football: 'আমেরিকান ফুটবল',
    rugby: 'রাগবি',
    ice_hockey: 'আইস হকি',
    handball: 'হ্যান্ডবল',
    skateboarding: 'স্কেটবোর্ডিং',
    skating: 'স্কেটিং',
    surfing: 'সার্ফিং',
    crossfit: 'ক্রসফিট',
    pickleball: 'পিকলবল',
    billiards: 'বিলিয়ার্ড',
    darts: 'ডার্টস',
    bowling: 'বোলিং',
    fishing: 'মাছ ধরা',
    paintball: 'পেইন্টবল',
    dance: 'নৃত্য',
    okey: 'ওকে',
    tavla: 'ব্যাকগ্যামন',
    satranc: 'দাবা',
    karting: 'কার্টিং',
  },
};

function normalizeLocale(locale) {
  return String(locale || 'en').toLowerCase().split('-')[0];
}

function translateSportName(sportId, locale, rawName) {
  const id = String(sportId || '').trim().toLowerCase();
  const lang = normalizeLocale(locale);
  const localizedByLang = SPORT_NAME_LOCALE_OVERRIDES[lang] || {};

  if (id && localizedByLang[id]) return localizedByLang[id];
  if (id && SPORT_NAME_EN_BY_ID[id]) return SPORT_NAME_EN_BY_ID[id];

  const raw = String(rawName || '').trim();
  if (!raw) return id || 'sport';

  const trEntries = Object.entries(SPORT_NAME_LOCALE_OVERRIDES.tr || {});
  const mappedByRaw = trEntries.find(([, trName]) => String(trName).toLowerCase() === raw.toLowerCase());
  if (mappedByRaw) {
    const detectedId = mappedByRaw[0];
    if (localizedByLang[detectedId]) return localizedByLang[detectedId];
    if (SPORT_NAME_EN_BY_ID[detectedId]) return SPORT_NAME_EN_BY_ID[detectedId];
  }

  return raw;
}

// ─── Localized bio generation ──────────────────────────────────────────────────
function generateBotBio({ locale, sportName, cityName, persona, botId }) {
  const s = sportName || 'spor';
  const c = cityName || '';
  const templates = {
    tr: [
      `${c || 'Şehir merkezinde'} ${s} için düzenli partner arıyorum.`,
      `${s} antrenmanlarını aksatmayan biriyle eşleşmek istiyorum.`,
      `${c ? c + ' çevresinde ' : 'Bu hafta '}${s} maçı yapalım.`,
      `${s} için pozitif ve dakik bir eşleşme arıyorum.`,
    ],
    en: [
      `Looking for a consistent ${s} partner ${c ? 'around ' + c : 'this week'}.`,
      `I enjoy structured ${s} sessions and reliable teammates.`,
      `${c ? c + ' area' : 'Local area'} ${s} matches work best for me.`,
      `Open to friendly but focused ${s} matches.`,
    ],
    ru: [
      `Ищу постоянного партнера по ${s}${c ? ' в районе ' + c : ''}.`,
      `Люблю регулярные тренировки по ${s} и пунктуальность.`,
      `Открыт к матчам по ${s} в удобное время.`,
    ],
    de: [
      `Ich suche einen regelmäßigen Partner für ${s}${c ? ' in ' + c : ''}.`,
      `Strukturierte ${s}-Einheiten und Zuverlässigkeit sind mir wichtig.`,
      `Offen für freundliche, aber fokussierte ${s}-Matches.`,
    ],
    fr: [
      `Je cherche un partenaire régulier pour ${s}${c ? ' vers ' + c : ''}.`,
      `J'aime les sessions ${s} bien organisées et ponctuelles.`,
    ],
    es: [
      `Busco compañero constante para ${s}${c ? ' por ' + c : ''}.`,
      `Me gustan las sesiones de ${s} organizadas y puntuales.`,
    ],
    ja: [
      `${c ? c + '周辺で' : ''}${s}の定期パートナーを探しています。`,
      `${s}を継続して一緒に練習できる方を希望します。`,
    ],
    ko: [
      `${c ? c + ' 근처에서 ' : ''}${s}를 함께할 고정 파트너를 찾고 있어요.`,
      `${s}를 꾸준히 할 수 있는 분이면 좋아요.`,
    ],
    pt: [
      `Procuro parceiro regular para ${s}${c ? ' em ' + c : ''}.`,
      `Gosto de sessões de ${s} organizadas e pontuais.`,
    ],
    it: [
      `Cerco un partner regolare per ${s}${c ? ' a ' + c : ''}.`,
      `Mi piacciono le sessioni di ${s} organizzate e puntuali.`,
    ],
    ar: [
      `أبحث عن شريك منتظم لـ ${s}${c ? ' في ' + c : ''}.`,
      `أحب جلسات ${s} المنظمة والالتزام بالمواعيد.`,
    ],
  };
  const pool = templates[locale] || templates.en;
  const resolvedPersona = persona || (botId ? getBotPersona(botId) : null);
  const base = pool[hashSeed(`${s}-${c}-${resolvedPersona || ''}`) % pool.length];
  if (persona) return `${base} Style: ${persona}.`;
  return base;
}

// ─── Listing description ───────────────────────────────────────────────────────
function generateListingDesc({ name, sport, locale, city, botId }) {
  const s = sport || 'sport';
  const templates = {
    tr: [
      `Bu hafta ${s} için partner arıyorum.`,
      `${city ? city + ' tarafında ' : ''}${s} için eşleşmek isteyen yazabilir.`,
      `${s} için seviyeden bağımsız bir eşleşme arıyorum.`,
      `${name} olarak ${s} için yeni bir eşleşme açtım.`,
      `${s} oynamak isteyen var mı? ${city ? city + "'de " : ''}buluşabiliriz.`,
      `${city ? city + ' bölgesinde ' : ''}düzenli ${s} partneri arıyorum.`,
      `${s} antrenmanı için motive birini arıyorum, seviye fark etmez.`,
      `${name} bu hafta ${s} için yeni eşleşmelere açık.`,
      `${s} oynayan biri varsa ${city ? city + "'de " : ''}birlikte buluşalım!`,
      `${s} için haftalık antrenman grubu kurmak istiyorum.`,
      `Rekabetçi olmayan, eğlenceli bir ${s} maçı arıyorum.`,
      `${city ? city + "'deki " : ''}${s} pistini birlikte deneyimlemek isteyen?`,
    ],
    en: [
      `Looking for a partner for ${s} this week.`,
      `${city ? 'Around ' + city + ', ' : ''}I am open to a ${s} match.`,
      `All levels are welcome for this ${s} session.`,
      `${name} is looking for a ${s} match.`,
      `Anyone interested in ${s}? We can meet${city ? ' in ' + city : ' up'}.`,
      `Looking for a regular ${s} partner${city ? ' in ' + city : ''}.`,
      `Looking for a motivated ${s} partner. Skill level doesn't matter.`,
      `${name} has ${s} slots open this week.`,
      `If you play ${s}${city ? ' in ' + city : ''}, let's connect!`,
      `Want to build a weekly ${s} training group.`,
      `Looking for a casual, fun ${s} game — no pressure!`,
      `${city ? 'Anyone near ' + city + ' who ' : 'Anyone who '}wants to try the ${s} courts?`,
    ],
    ru: [
      `Ищу партнера по ${s} на этой неделе.`,
      `${name} ищет соперника по ${s}.`,
      `${city ? 'В районе ' + city + ' ' : ''}ищу партнёра по ${s}, уровень не важен.`,
      `Тренируюсь по ${s} регулярно, ищу напарника.`,
      `${name} открыт для встреч по ${s} в удобное время.`,
      `Ищу мотивированного человека для ${s}. Пишите!`,
    ],
    de: [
      `Ich suche diese Woche einen Partner für ${s}.`,
      `${name} sucht ein Match für ${s}.`,
      `${city ? 'In ' + city + ' ' : ''}suche ich einen ${s}-Partner, jedes Niveau ok.`,
      `Ich trainiere ${s} regelmäßig und suche einen Mitspieler.`,
      `Wer hat Lust auf ${s}${city ? ' in ' + city : ''}?`,
      `${name} sucht einen flexiblen Partner für ${s}.`,
    ],
    fr: [
      `Je cherche un partenaire pour ${s} cette semaine.`,
      `${name} cherche un match de ${s}.`,
      `${city ? 'À ' + city + ', ' : ''}je cherche un partenaire de ${s}, tous niveaux.`,
      `Je joue ${s} régulièrement et cherche un partenaire.`,
      `Quelqu'un pour ${s}${city ? ' à ' + city : ''} ?`,
      `${name} cherche un partenaire flexible pour ${s}.`,
    ],
    es: [
      `Busco compañero para ${s} esta semana.`,
      `${name} busca un partido de ${s}.`,
      `${city ? 'En ' + city + ', ' : ''}busco compañero de ${s}, todos los niveles.`,
      `Entreno ${s} regularmente y busco compañero.`,
      `¿Alguien para ${s}${city ? ' en ' + city : ''}?`,
      `${name} busca un compañero flexible para ${s}.`,
    ],
    ja: [
      `今週${s}のパートナーを募集しています。`,
      `${name}が${s}のマッチ相手を探しています。`,
      `${city ? city + 'で' : ''}${s}の練習相手を探しています。どなたでも歓迎。`,
      `${s}を定期的にやっています。一緒にやれる方を探しています。`,
      `${s}の試合相手を募集中${city ? '（' + city + '）' : ''}。`,
      `${name}、${s}のパートナーを柔軟に探しています。`,
    ],
    ko: [
      `이번 주 ${s} 파트너를 찾고 있어요.`,
      `${name} 님이 ${s} 매치 상대를 찾고 있어요.`,
      `${city ? city + '에서 ' : ''}${s} 연습 상대를 찾고 있어요. 레벨 무관.`,
      `${s} 정기적으로 하는데, 같이 하실 분 구합니다.`,
      `${s} 시합 상대 구해요${city ? ' (' + city + ')' : ''}.`,
      `${name} 님, 유연하게 ${s} 파트너 찾습니다.`,
    ],
    pt: [
      `Procuro parceiro para ${s} esta semana.`,
      `${name} procura uma partida de ${s}.`,
      `${city ? 'Em ' + city + ', ' : ''}procuro parceiro de ${s}, todos os níveis.`,
      `Treino ${s} regularmente e procuro parceiro.`,
      `Alguém para ${s}${city ? ' em ' + city : ''}?`,
      `${name} procura um parceiro flexível para ${s}.`,
    ],
    it: [
      `Cerco un partner per ${s} questa settimana.`,
      `${name} cerca un match di ${s}.`,
      `${city ? 'A ' + city + ', ' : ''}cerco un partner per ${s}, qualsiasi livello.`,
      `Mi alleno in ${s} regolarmente e cerco un compagno.`,
      `Qualcuno per ${s}${city ? ' a ' + city : ''}?`,
      `${name} cerca un partner flessibile per ${s}.`,
    ],
    ar: [
      `أبحث عن شريك لـ ${s} هذا الأسبوع.`,
      `${name} يبحث عن مباراة ${s}.`,
      `${city ? 'في ' + city + '، ' : ''}أبحث عن شريك ${s}، جميع المستويات.`,
      `أتدرب على ${s} بانتظام وأبحث عن شريك.`,
      `هل من يريد ${s}${city ? ' في ' + city : ''}؟`,
      `${name} يبحث عن شريك مرن لـ ${s}.`,
    ],
  };
  const pool = templates[locale] || templates.en;
  const persona = getBotPersona(botId);
  return pool[hashSeed(`${name || ''}-${s}-${city || ''}-${persona}`) % pool.length];
}

// ─── Response message ──────────────────────────────────────────────────────────
function generateResponseMsg(name, locale) {
  const templates = {
    tr: [
      'Merhaba, ilanın ilgimi çekti. Katılmak isterim.',
      'Müsaitim, istersen detayları konuşalım.',
      'Bu eşleşme bana uygun görünüyor.',
      `${name} olarak başvuruyorum, uygun olursa sevinirim.`,
    ],
    en: [
      'Hi, this listing looks great. I would like to join.',
      'I am available. We can discuss the details.',
      'This match looks like a good fit for me.',
      `${name} here, I would be happy to join if it works for you.`,
    ],
    ru: ['Привет, объявление заинтересовало. Хочу присоединиться.', `${name} на связи, буду рад присоединиться.`],
    de: ['Hallo, die Anzeige passt gut für mich. Ich möchte mitmachen.', `${name} hier, ich wäre gern dabei.`],
    fr: ['Bonjour, cette annonce m\'intéresse. Je veux participer.', `${name} ici, je serais ravi de participer.`],
    es: ['Hola, este anuncio me interesa. Me gustaría participar.', `${name} por aquí, encantado de unirme.`],
    ja: ['こんにちは、この募集に参加したいです。', `${name}です。参加できると嬉しいです。`],
    ko: ['안녕하세요, 이 모집에 참여하고 싶어요.', `${name}입니다. 참여할 수 있으면 좋겠어요.`],
    pt: ['Olá, este anúncio me interessou. Gostaria de participar.', `${name} aqui, ficaria feliz em participar.`],
    it: ['Ciao, questo annuncio mi interessa. Vorrei partecipare.', `${name} qui, sarei felice di partecipare.`],
    ar: ['مرحبًا، هذا الإعلان يهمني. أود المشاركة.', `${name} هنا، سأكون سعيدًا بالانضمام.`],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ─── Shadow match post text ────────────────────────────────────────────────────
function generateShadowMatchText({ locale, listingBotName, responderBotName, sportName, cityName }) {
  const s = sportName || 'sport';
  const L = listingBotName;
  const R = responderBotName;
  const city = cityName ? ` (${cityName})` : '';
  const templates = {
    tr: [
      `${L} ve ${R} bugün ${s} maçını tamamladı!${city}`,
      `${L} ile ${R} arasında harika bir ${s} müsabakası gerçekleşti!${city}`,
      `${R}, ${L} ile ${s} sahasında karşılaştı ve güzel bir maç çıktı!${city}`,
      `${s} sahalarından haber: ${L} ve ${R} bu hafta eşleşti!${city}`,
      `${L} ve ${R} ${s} için buluştu, çok keyifli bir gün geçirdiler!${city}`,
      `${s} maçı tamamlandı: ${L} vs ${R}, her iki taraf da harika oynadı!${city}`,
      `${R} ve ${L}, ${s} antrenmanında birbirlerine rakip oldu!${city}`,
      `${L} ile ${R}'nin ${s} maçı bitti — ikisi de müthiş performans sergiledi!${city}`,
    ],
    en: [
      `${L} and ${R} completed a ${s} match today!${city}`,
      `${L} and ${R} had a fantastic ${s} game together!${city}`,
      `${R} challenged ${L} on the ${s} court — great match!${city}`,
      `${s} update: ${L} and ${R} faced each other this week!${city}`,
      `${L} and ${R} met up for ${s} and had a wonderful time!${city}`,
      `Match complete: ${L} vs ${R} in ${s} — both played brilliantly!${city}`,
      `${R} and ${L} went head to head in ${s} training!${city}`,
      `${L} and ${R}'s ${s} match is done — incredible performance by both!${city}`,
    ],
    ru: [
      `${L} и ${R} завершили матч по ${s} сегодня!${city}`,
      `${L} и ${R} провели отличную игру в ${s}!${city}`,
      `${R} бросил вызов ${L} на корте по ${s}!${city}`,
      `${s}: ${L} против ${R} — оба показали великолепную игру!${city}`,
      `${L} и ${R} встретились для игры в ${s} — незабываемо!${city}`,
    ],
    de: [
      `${L} und ${R} haben heute ihr ${s}-Match abgeschlossen!${city}`,
      `${L} und ${R} hatten ein tolles ${s}-Spiel!${city}`,
      `${R} forderte ${L} beim ${s} heraus — was für ein Match!${city}`,
      `${s}-Update: ${L} und ${R} standen sich diese Woche gegenüber!${city}`,
      `${L} und ${R} spielten ${s} — beide zeigten eine großartige Leistung!${city}`,
    ],
    fr: [
      `${L} et ${R} ont terminé leur match de ${s} aujourd'hui !${city}`,
      `${L} et ${R} ont eu une super partie de ${s} !${city}`,
      `${R} a défié ${L} sur le terrain de ${s} — quel match !${city}`,
      `${s} : ${L} contre ${R} — tous deux ont excellé !${city}`,
      `${L} et ${R} se sont retrouvés pour ${s} — mémorable !${city}`,
    ],
    es: [
      `${L} y ${R} completaron su partido de ${s} hoy!${city}`,
      `${L} y ${R} tuvieron un juego de ${s} fantástico!${city}`,
      `${R} desafió a ${L} en el campo de ${s} — ¡qué partido!${city}`,
      `${s}: ${L} contra ${R} — los dos jugaron de maravilla!${city}`,
      `${L} y ${R} se encontraron para ${s} — ¡inolvidable!${city}`,
    ],
    ja: [
      `${L}さんと${R}さんが${s}のマッチを今日完了しました！${city}`,
      `${L}さんと${R}さんが素晴らしい${s}のゲームを楽しみました！${city}`,
      `${R}さんが${L}さんに${s}で挑戦 — 見事な試合でした！${city}`,
      `${s}: ${L} vs ${R} — 両者とも素晴らしいプレーでした！${city}`,
      `${L}さんと${R}さんが${s}のために集まり、忘れられない時間を過ごしました！${city}`,
    ],
    ko: [
      `${L}님과 ${R}님이 오늘 ${s} 매치를 완료했어요!${city}`,
      `${L}님과 ${R}님이 멋진 ${s} 경기를 했어요!${city}`,
      `${R}님이 ${L}님에게 ${s}로 도전했어요 — 대단한 경기!${city}`,
      `${s}: ${L} vs ${R} — 두 분 모두 훌륭했어요!${city}`,
      `${L}님과 ${R}님이 ${s}를 위해 만났어요 — 잊지 못할 시간!${city}`,
    ],
    pt: [
      `${L} e ${R} completaram a partida de ${s} hoje!${city}`,
      `${L} e ${R} tiveram um jogo incrível de ${s}!${city}`,
      `${R} desafiou ${L} na quadra de ${s} — que partida!${city}`,
      `${s}: ${L} contra ${R} — os dois jogaram brilhantemente!${city}`,
      `${L} e ${R} se reuniram para ${s} — inesquecível!${city}`,
    ],
    it: [
      `${L} e ${R} hanno completato la loro partita di ${s} oggi!${city}`,
      `${L} e ${R} hanno avuto una fantastica gara di ${s}!${city}`,
      `${R} ha sfidato ${L} nel campo di ${s} — che partita!${city}`,
      `${s}: ${L} contro ${R} — entrambi hanno giocato brillantemente!${city}`,
      `${L} e ${R} si sono incontrati per ${s} — indimenticabile!${city}`,
    ],
    ar: [
      `أكمل ${L} و${R} مباراتهما في ${s} اليوم!${city}`,
      `خاض ${L} و${R} مباراة رائعة في ${s}!${city}`,
      `تحدى ${R} اللاعب ${L} في ملعب ${s} — ما أروع هذه المباراة!${city}`,
      `${s}: ${L} ضد ${R} — لعب كلاهما بشكل رائع!${city}`,
      `التقى ${L} و${R} من أجل ${s} — لقاء لا يُنسى!${city}`,
    ],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ─── Deterministic GPS coordinates ─────────────────────────────────────────────
const COUNTRY_CENTERS = {
  TR: { lat: 39.0, lon: 35.0 },
  DE: { lat: 51.2, lon: 10.4 },
  FR: { lat: 46.2, lon: 2.2 },
  ES: { lat: 40.4, lon: -3.7 },
  GB: { lat: 54.0, lon: -2.0 },
  RU: { lat: 55.8, lon: 37.6 },
  JP: { lat: 35.7, lon: 139.7 },
  KR: { lat: 37.6, lon: 127.0 },
  US: { lat: 39.8, lon: -98.6 },
  CA: { lat: 56.1, lon: -106.3 },
  BR: { lat: -14.2, lon: -51.9 },
  AR: { lat: -38.4, lon: -63.6 },
  IN: { lat: 21.1, lon: 78.0 },
  AU: { lat: -25.2, lon: 133.8 },
  NL: { lat: 52.1, lon: 5.3 },
  IT: { lat: 41.9, lon: 12.6 },
  GR: { lat: 39.1, lon: 22.9 },
  PT: { lat: 39.4, lon: -8.2 },
  EG: { lat: 26.8, lon: 30.8 },
  PK: { lat: 30.4, lon: 69.3 },
  SA: { lat: 23.9, lon: 45.1 },
  AZ: { lat: 40.1, lon: 47.6 },
  GE: { lat: 42.3, lon: 43.4 },
  BG: { lat: 42.7, lon: 25.5 },
};

function estimateBotCoordinates({ citySeed, countryCode }) {
  const code = (countryCode || 'TR').toUpperCase();
  const center = COUNTRY_CENTERS[code] || COUNTRY_CENTERS.TR;
  const latHash = hashSeed(`${citySeed}-lat`);
  const lonHash = hashSeed(`${citySeed}-lon`);
  const latOffset = ((latHash % 1000) / 1000 - 0.5) * 0.8;
  const lonOffset = ((lonHash % 1000) / 1000 - 0.5) * 1.2;
  const latitude  = Number(Math.max(-85, Math.min(85, center.lat + latOffset)).toFixed(6));
  const longitude = Number(Math.max(-179, Math.min(179, center.lon + lonOffset)).toFixed(6));
  return { latitude, longitude };
}

// ─── Future date helper ────────────────────────────────────────────────────────
function getFutureDate(daysAhead) {
  const d = new Date();
  d.setDate(d.getDate() + daysAhead);
  d.setHours(10 + Math.floor(Math.random() * 8), 0, 0, 0);
  return d;
}

// ─── Bot social post content ───────────────────────────────────────────────────
function generateBotSocialPost({ locale, sportName, cityName, botName, botId }) {
  const s = sportName || 'sport';
  const c = cityName || '';
  const n = botName || '';
  const templates = {
    tr: [
      `${c ? c + ' parkında ' : 'Bugün '}${s} antrenmanı yaptım, harika hissediyorum! 💪`,
      `${s} için yeni bir partner arıyorum, ilgilenen yazabilir.`,
      `${s} sevenler burada mı? ${c ? c + "'de " : ''}birlikte pratik yapalım!`,
      `Bu hafta ${s} maçım vardı, çok keyifliydi. Siz de deneyin!`,
      `${n ? n + " olarak " : ""}${s} tutkunuyum, yeni arkadaşlar arıyorum 🎯`,
      `${c ? c + " şehrinde " : ""}${s} etkinliği düzenlemek istiyorum, kim var?`,
      `${s} antrenmanından yeni döndüm, harika bir gündü ☀️`,
      `${s} için düzenli grup arıyorum. Seviye önemli değil!`,
      `${s} oynamayı bu yıl yeniden keşfettim, inanılmaz bir duygu! 🏅`,
      `${c ? c + "'deki " : ""}${s} sahası bugün gerçekten muhteşemdi.`,
      `${s} sonrası o kas ağrısı... benim için en güzel his 😄`,
      `Her sporseverin ${s} denemesi gerekiyor diyorum.`,
      `${s} arkadaşları nerede? Yeni hafta, yeni enerji! 🔋`,
      `${c ? c + " çevresinde " : ""}${s} oynayan bir grup arıyorum.`,
      `${s} ile başlayan güne dolu dolu devam! Katılmak isteyen?`,
    ],
    en: [
      `Just had an amazing ${s} session${c ? ' in ' + c : ''}! Feeling great 💪`,
      `Looking for a ${s} partner${c ? ' around ' + c : ''}. Anyone interested?`,
      `${s} fans, where are you? Let's train together!`,
      `Had a great ${s} match this week. You should try it!`,
      `Passionate about ${s}, looking for new friends 🎯`,
      `Want to organize a ${s} event${c ? ' in ' + c : ''}. Who's in?`,
      `Just came back from ${s} training, what a great day ☀️`,
      `Looking for a regular ${s} group. All levels welcome!`,
      `Rediscovered ${s} this year and it's absolutely amazing! 🏅`,
      `The ${s} courts${c ? ' in ' + c : ''} were incredible today.`,
      `Post-${s} muscle soreness... honestly the best feeling 😄`,
      `Everyone should try ${s} at least once in their life.`,
      `${s} friends, where are you? New week, new energy! 🔋`,
      `Looking for a ${s} group${c ? ' near ' + c : ''} to join.`,
      `Started the day with ${s} and feeling unstoppable. Anyone else?`,
    ],
    ru: [
      `Только что закончил тренировку по ${s}${c ? ' в ' + c : ''}, отличное настроение! 💪`,
      `Ищу партнера по ${s}${c ? ' в ' + c : ''}. Есть желающие?`,
      `Кто любит ${s}? Давайте тренироваться вместе!`,
      `На этой неделе был матч по ${s}, очень понравилось. Советую!`,
      `Ищу новых друзей и партнёров по ${s} 🎯`,
      `Хочу организовать тренировку по ${s}${c ? ' в ' + c : ''}. Кто в теме?`,
      `Только что вернулся с ${s} — прекрасный день ☀️`,
      `Все должны попробовать ${s} хотя бы раз!`,
      `${s} даёт такой заряд энергии 🔋 Кто разделяет?`,
      `${c ? c + ": " : ""}ищу стабильную группу для ${s}.`,
    ],
    de: [
      `Gerade ein tolles ${s}-Training beendet${c ? ' in ' + c : ''}! Fühle mich super 💪`,
      `Suche einen ${s}-Partner${c ? ' in ' + c : ''}. Interesse?`,
      `${s}-Fans, wo seid ihr? Lasst uns zusammen trainieren!`,
      `Diese Woche ein tolles ${s}-Match gehabt. Empfehle es!`,
      `Suche neue Freunde und Partner für ${s} 🎯`,
      `Möchte ein ${s}-Event${c ? ' in ' + c : ''} organisieren. Wer ist dabei?`,
      `Gerade vom ${s}-Training zurück — was für ein Tag ☀️`,
      `Jeder sollte ${s} einmal ausprobieren!`,
      `${s} gibt mir so viel Energie 🔋 Geht es euch genauso?`,
      `${c ? c + ": " : ""}Suche eine feste Gruppe für ${s}.`,
    ],
    fr: [
      `Viens de finir un super entraînement de ${s}${c ? ' à ' + c : ''}! Je me sens bien 💪`,
      `Je cherche un partenaire de ${s}${c ? ' à ' + c : ''}. Intéressé(e)?`,
      `Fans de ${s}, où êtes-vous? Entraînons-nous ensemble!`,
      `J'ai eu un super match de ${s} cette semaine. Essayez!`,
      `Je cherche de nouveaux amis pour ${s} 🎯`,
      `Je veux organiser un événement ${s}${c ? ' à ' + c : ''}. Qui est partant?`,
      `Je reviens du ${s} — quelle belle journée ☀️`,
      `Tout le monde devrait essayer le ${s} au moins une fois!`,
      `Le ${s} me donne tellement d'énergie 🔋 Et vous?`,
      `${c ? c + " : " : ""}Je cherche un groupe régulier de ${s}.`,
    ],
    es: [
      `¡Acabo de terminar un entrenamiento de ${s}${c ? ' en ' + c : ''}! Me siento genial 💪`,
      `Busco compañero de ${s}${c ? ' en ' + c : ''}. ¿Alguien interesado?`,
      `¡Fans de ${s}, estáis ahí? ¡Entrenemos juntos!`,
      `Tuve un gran partido de ${s} esta semana. ¡Pruébenlo!`,
      `Buscando nuevos amigos para ${s} 🎯`,
      `¡Quiero organizar un evento de ${s}${c ? ' en ' + c : ''}. ¿Quién se apunta?`,
      `Recién llegado del ${s} — ¡qué día tan bueno ☀️`,
      `¡Todo el mundo debería probar ${s} al menos una vez!`,
      `El ${s} me da tanta energía 🔋 ¿A alguien más le pasa?`,
      `${c ? c + ": " : ""}Busco un grupo estable de ${s}.`,
    ],
    ja: [
      `${c ? c + 'で' : ''}${s}の練習が終わりました！最高の気分です 💪`,
      `${s}のパートナーを探しています${c ? '（' + c + '周辺）' : ''}。興味ある方いますか？`,
      `${s}好きの方、一緒に練習しませんか！`,
      `今週${s}の試合があって楽しかった！おすすめです。`,
      `${s}仲間を探しています 🎯`,
      `${c ? c + 'で' : ''}${s}イベントを企画したいです。参加者募集中！`,
      `${s}から帰ってきました — 最高の一日でした ☀️`,
      `みんな一度は${s}を試してみてほしい！`,
      `${s}でエネルギーチャージ 🔋 同じ気持ちの方いますか？`,
      `${c ? c + 'の' : ''}${s}仲間を探しています。一緒にどうですか？`,
    ],
    ko: [
      `${c ? c + '에서 ' : ''}${s} 훈련 마쳤어요! 최고의 기분 💪`,
      `${s} 파트너 구해요${c ? ' (' + c + ' 근처)' : ''}. 관심있으신 분?`,
      `${s} 좋아하시는 분들, 같이 운동해요!`,
      `이번 주 ${s} 시합 했는데 정말 재밌었어요. 추천해요!`,
      `${s} 같이 할 친구 찾아요 🎯`,
      `${c ? c + '에서 ' : ''}${s} 이벤트 열고 싶어요. 같이 할 분!`,
      `${s} 끝나고 돌아왔어요 — 정말 좋은 하루 ☀️`,
      `모두가 ${s}를 한 번은 꼭 해봐야 해요!`,
      `${s}로 에너지 충전 🔋 같은 분 계세요?`,
      `${c ? c + ' 근처 ' : ''}${s} 모임 찾고 있어요.`,
    ],
    pt: [
      `Acabei de terminar um treino incrível de ${s}${c ? ' em ' + c : ''}! Sensação ótima 💪`,
      `Procuro parceiro de ${s}${c ? ' em ' + c : ''}. Alguém interessado?`,
      `Fãs de ${s}, onde estão? Vamos treinar juntos!`,
      `Tive um ótimo jogo de ${s} esta semana. Experimentem!`,
      `Procuro novos amigos para ${s} 🎯`,
      `Quero organizar um evento de ${s}${c ? ' em ' + c : ''}. Quem topa?`,
      `Acabei de voltar do ${s} — que dia incrível ☀️`,
      `Todo mundo deveria tentar ${s} pelo menos uma vez!`,
      `O ${s} me dá tanta energia 🔋 Alguém mais sente isso?`,
      `${c ? c + ": " : ""}Procuro um grupo fixo de ${s}.`,
    ],
    it: [
      `Ho appena finito un allenamento di ${s}${c ? ' a ' + c : ''}! Mi sento benissimo 💪`,
      `Cerco un partner di ${s}${c ? ' a ' + c : ''}. Qualcuno interessato?`,
      `Fan di ${s}, dove siete? Alleniamoci insieme!`,
      `Ho avuto un ottimo match di ${s} questa settimana. Provatelo!`,
      `Cerco nuovi amici per ${s} 🎯`,
      `Voglio organizzare un evento di ${s}${c ? ' a ' + c : ''}. Chi c'è?`,
      `Sono appena tornato dal ${s} — che bella giornata ☀️`,
      `Tutti dovrebbero provare il ${s} almeno una volta!`,
      `Il ${s} mi dà tanta energia 🔋 E voi?`,
      `${c ? c + ": " : ""}Cerco un gruppo stabile di ${s}.`,
    ],
    ar: [
      `انتهيت للتو من تدريب رائع على ${s}${c ? ' في ' + c : ''}! أشعر بروح عالية 💪`,
      `أبحث عن شريك لـ ${s}${c ? ' في ' + c : ''}. هل من مهتم؟`,
      `محبو ${s}، أين أنتم؟ لنتدرب معاً!`,
      `كان لدي مباراة ${s} رائعة هذا الأسبوع. جربوها!`,
      `أبحث عن أصدقاء جدد لـ ${s} 🎯`,
      `أريد تنظيم فعالية ${s}${c ? ' في ' + c : ''}. من يريد الانضمام؟`,
      `عدت للتو من ${s} — يوم رائع ☀️`,
      `على الجميع تجربة ${s} مرة واحدة على الأقل!`,
      `${s} يمنحني طاقة هائلة 🔋 هل تشاركني هذا الشعور؟`,
      `${c ? c + ": " : ""}أبحث عن مجموعة ثابتة لـ ${s}.`,
    ],
  };
  const pool = templates[locale] || templates.en;
  const weekNum = Math.floor(Date.now() / (86400000 * 7));
  const persona = getBotPersona(botId);
  return pool[hashSeed(`${n}-${s}-${c}-post-w${weekNum}-${persona}`) % pool.length];
}

// ─── Bot social topic listing (ready-made social templates) ──────────────────
function generateBotSocialTopicListing({ locale, cityName, botName, botId }) {
  const c = cityName || '';
  const n = botName || '';
  const templates = {
    tr: [
      { title: 'Hayal Kurma Ortağı', desc: 'Birlikte uçuk fikirler üretip kahve eşliğinde gelecek hayalleri kuracak birini arıyorum.' },
      { title: 'Ego Tatmin Partneri', desc: 'Bugün karşılıklı motive olup birbirimizin özgüvenini yükselteceğimiz bir partner arıyorum 😄' },
      { title: 'Motivasyon Kankası', desc: 'Ertelediğimiz işleri birlikte başlatıp birbirimizi gazlayacağımız bir ekip arkadaşı arıyorum.' },
      { title: 'Dil Pratiği Arkadaşı', desc: 'Günlük sohbetle dil pratiği yapıp keyifli vakit geçirmek isteyen var mı?' },
      { title: 'Hobi Paylaşım Ortağı', desc: 'Yeni hobiler deneyip deneyimlerimizi paylaşacağımız pozitif bir arkadaş arıyorum.' },
      { title: 'Mülakat Prova Koçu', desc: 'Kısa bir mock interview yapıp birbirimize yapıcı geri bildirim verecek birini arıyorum.' },
    ],
    en: [
      { title: 'Daydream Partner', desc: 'Looking for someone to brainstorm wild ideas and daydream over coffee.' },
      { title: 'Ego Boost Partner', desc: 'Looking for a fun partner to hype each other up and boost confidence today 😄' },
      { title: 'Motivation Buddy', desc: 'Need someone to start delayed tasks together and keep each other accountable.' },
      { title: 'Language Practice Buddy', desc: 'Anyone up for casual language practice chats and fun conversation?' },
      { title: 'Hobby Share Buddy', desc: 'Looking for a positive friend to explore new hobbies and share experiences.' },
      { title: 'Interview Practice Coach', desc: 'Looking for someone to do a short mock interview and exchange feedback.' },
    ],
    ru: [
      { title: 'Партнёр для мечтаний', desc: 'Ищу человека, с кем можно за кофе обсуждать смелые идеи и мечты.' },
      { title: 'Партнёр для буста эго', desc: 'Ищу напарника, чтобы взаимно мотивировать друг друга и поднять уверенность 😄' },
      { title: 'Мотивационный напарник', desc: 'Нужен напарник, чтобы вместе начать отложенные дела и не сдаваться.' },
      { title: 'Партнёр для языковой практики', desc: 'Кто хочет практиковать язык в лёгких и интересных беседах?' },
      { title: 'Партнёр по хобби', desc: 'Ищу позитивного человека для новых хобби и обмена опытом.' },
      { title: 'Коуч для собеседований', desc: 'Ищу человека для короткого mock-интервью и взаимной обратной связи.' },
    ],
    de: [
      { title: 'Tagtraum-Partner', desc: 'Suche jemanden, mit dem man bei Kaffee verrueckte Ideen spinnen kann.' },
      { title: 'Ego-Boost-Partner', desc: 'Suche einen lockeren Partner, um uns gegenseitig zu pushen und Selbstvertrauen aufzubauen 😄' },
      { title: 'Motivations-Buddy', desc: 'Brauche jemanden, um aufgeschobene Aufgaben gemeinsam zu starten.' },
      { title: 'Sprachpraxis-Buddy', desc: 'Hat jemand Lust auf entspannte Gespraeche zum Sprache ueben?' },
      { title: 'Hobby-Partner', desc: 'Suche eine positive Person, um neue Hobbys auszuprobieren.' },
      { title: 'Interview-Trainingspartner', desc: 'Suche jemanden fuer ein kurzes Mock-Interview mit gegenseitigem Feedback.' },
    ],
    fr: [
      { title: 'Partenaire de reves', desc: 'Je cherche quelquun pour imaginer des idees folles autour dun cafe.' },
      { title: 'Partenaire boost ego', desc: 'Je cherche un partenaire fun pour se motiver mutuellement et gagner en confiance 😄' },
      { title: 'Buddy motivation', desc: 'Besoin de quelquun pour lancer les taches repoussees ensemble.' },
      { title: 'Buddy pratique de langue', desc: 'Qui veut pratiquer les langues dans des conversations detendues ?' },
      { title: 'Partenaire hobby', desc: 'Je cherche une personne positive pour explorer de nouveaux hobbies.' },
      { title: 'Coach entretien blanc', desc: 'Je cherche quelquun pour un mini entretien blanc avec feedback mutuel.' },
    ],
    es: [
      { title: 'Compa de suenos', desc: 'Busco a alguien para imaginar ideas locas con cafe de por medio.' },
      { title: 'Partner de ego boost', desc: 'Busco un partner divertido para motivarnos y subir la confianza 😄' },
      { title: 'Compa motivacion', desc: 'Necesito a alguien para empezar tareas pendientes juntos.' },
      { title: 'Compa de idiomas', desc: 'Alguien para practicar idiomas con conversaciones relajadas?' },
      { title: 'Compa de hobbies', desc: 'Busco una persona positiva para explorar hobbies nuevos.' },
      { title: 'Coach de entrevista', desc: 'Busco a alguien para hacer una mini entrevista de practica con feedback.' },
    ],
    ja: [
      { title: '妄想パートナー', desc: 'コーヒーを飲みながら自由なアイデアを語れる相手を探しています。' },
      { title: '自信ブースト相棒', desc: 'お互いを褒めてモチベを上げる楽しい相棒を探しています 😄' },
      { title: 'モチベ仲間', desc: '先延ばししていることを一緒に始められる仲間募集。' },
      { title: '言語練習バディ', desc: '気軽なおしゃべりで言語練習したい人いませんか？' },
      { title: '趣味シェア仲間', desc: '新しい趣味を試して共有できる前向きな仲間を探しています。' },
      { title: '面接練習コーチ', desc: '短い模擬面接をして相互フィードバックできる人募集。' },
    ],
    ko: [
      { title: '상상 파트너', desc: '커피 마시면서 엉뚱한 아이디어를 함께 나눌 파트너를 찾고 있어요.' },
      { title: '자존감 부스터 파트너', desc: '서로 응원하고 자신감을 올려줄 재미있는 파트너를 찾습니다 😄' },
      { title: '동기부여 버디', desc: '미뤄둔 일을 함께 시작하고 서로 밀어줄 친구를 찾고 있어요.' },
      { title: '언어 연습 버디', desc: '가벼운 대화로 언어 연습 같이 하실 분 있나요?' },
      { title: '취미 공유 파트너', desc: '새로운 취미를 함께 탐험할 긍정적인 친구를 찾습니다.' },
      { title: '면접 연습 코치', desc: '짧은 모의 면접 후 서로 피드백할 파트너를 찾습니다.' },
    ],
    pt: [
      { title: 'Parceiro de devaneios', desc: 'Procuro alguem para imaginar ideias malucas tomando um cafe.' },
      { title: 'Parceiro de ego boost', desc: 'Procuro um parceiro divertido para nos motivarmos e aumentar a confianca 😄' },
      { title: 'Buddy de motivacao', desc: 'Preciso de alguem para comecar tarefas adiadas junto comigo.' },
      { title: 'Buddy de idiomas', desc: 'Alguem para praticar idiomas em conversas leves?' },
      { title: 'Parceiro de hobbies', desc: 'Procuro uma pessoa positiva para explorar novos hobbies.' },
      { title: 'Coach de entrevista', desc: 'Procuro alguem para um mini mock interview com feedback mutuo.' },
    ],
    it: [
      { title: 'Compagno di sogni', desc: 'Cerco qualcuno con cui immaginare idee folli davanti a un caffe.' },
      { title: 'Partner ego boost', desc: 'Cerco un partner divertente per motivarci e aumentare la fiducia 😄' },
      { title: 'Buddy motivazione', desc: 'Mi serve qualcuno per iniziare insieme i compiti rimandati.' },
      { title: 'Buddy pratica lingua', desc: 'Qualcuno per fare pratica di lingua con conversazioni leggere?' },
      { title: 'Compagno di hobby', desc: 'Cerco una persona positiva per esplorare nuovi hobby.' },
      { title: 'Coach colloquio', desc: 'Cerco qualcuno per un mini colloquio di prova con feedback reciproco.' },
    ],
    ar: [
      { title: 'شريك أحلام', desc: 'أبحث عن شخص نتبادل معه أفكارا جريئة على فنجان قهوة.' },
      { title: 'شريك تعزيز الثقة', desc: 'أبحث عن شريك ممتع لنحفز بعضنا ونرفع الثقة بالنفس 😄' },
      { title: 'رفيق تحفيز', desc: 'أحتاج شخصا نبدأ معه المهام المؤجلة وندعم بعضنا.' },
      { title: 'رفيق ممارسة لغة', desc: 'هل يوجد من يريد ممارسة اللغة في دردشة خفيفة؟' },
      { title: 'شريك هوايات', desc: 'أبحث عن شخص إيجابي لتجربة هوايات جديدة.' },
      { title: 'مدرب مقابلة', desc: 'أبحث عن شخص لعمل مقابلة تجريبية قصيرة مع تبادل الملاحظات.' },
    ],
  };

  const pool = templates[locale] || templates.en;
  const weekBucket = Math.floor(Date.now() / (86400000 * 7));
  const persona = getBotPersona(botId);
  const idx = hashSeed(`${n}-${c}-${locale}-w${weekBucket}-topic-${persona}`) % pool.length;
  const picked = pool[idx];
  return {
    title: picked.title,
    content: `${picked.desc}${c ? ` (${c})` : ''}`,
  };
}

function generateBotSocialListing({ locale, sportName, cityName, botName, botId }) {
  // Mix sports-oriented social posts with ready-made social topic templates.
  if (Math.random() < 0.45) {
    const topic = generateBotSocialTopicListing({ locale, cityName, botName, botId });
    return { kind: 'TOPIC', title: topic.title, content: topic.content };
  }
  return {
    kind: 'SPORT',
    title: null,
    content: generateBotSocialPost({ locale, sportName, cityName, botName, botId }),
  };
}

// ─── Bot comment on social post ────────────────────────────────────────────────
function appendCommentEmojiFlavor(baseText, seed) {
  const clean = String(baseText || '').trim();
  if (!clean) return clean;

  const withEmoji = (hashSeed(`${seed}-emoji`) % 100) < 74;
  if (!withEmoji) return clean;

  const emojiPool = ['❤️', '🔥', '👏', '🙌', '✨', '💪', '🤝', '😊'];
  const pickEmoji = (salt, exclude) => {
    let start = hashSeed(`${seed}-${salt}`) % emojiPool.length;
    for (let i = 0; i < emojiPool.length; i++) {
      const candidate = emojiPool[(start + i) % emojiPool.length];
      if (exclude && candidate === exclude) continue;
      if (clean.endsWith(candidate)) continue;
      return candidate;
    }
    return emojiPool[start];
  };

  const first = pickEmoji('emoji-1');
  const addSecond = (hashSeed(`${seed}-emoji-2`) % 100) < 20;

  let suffix = ` ${first}`;
  if (addSecond) {
    const second = pickEmoji('emoji-3', first);
    if (second && second !== first) suffix += ` ${second}`;
  }

  return `${clean}${suffix}`;
}

function generateBotComment({ locale, sportName, posterName, botId, postId, attempt = 0 }) {
  const language = String(locale || 'en').toLowerCase();
  const s = sportName || null;
  const pn = posterName || '';
  const weekBucket = Math.floor(Date.now() / (86400000 * 7));
  const persona = getBotPersona(botId);
  const seedBase = `${language}-${s || 'generic'}-${botId || ''}-${postId || ''}-${weekBucket}-${attempt}-${persona}`;

  if (!s) {
    const genericTemplates = {
      tr: [
        'Harika konu secimi, cok eglenceli gorunuyor! 😄',
        'Bu ilan dikkatimi cekti, detaylari konusalim mi?',
        `${pn ? pn + ', bu ' : 'Bu '}fikir gercekten hosuma gitti!`,
        'Ben de katilmak isterim, cok keyifli duruyor 🙌',
        'Bu paylasim tam zamaninda geldi, tam aradığım şey bu!',
        `${pn ? pn + ', b' : 'B'}irlikte harika vakit gecirebiliriz!`,
        'Ne guzel bir fikir! Detaylari ogrenebilir miyim?',
        'Boyle ilanlar gormek keyif veriyor, tesekkurler!',
        'Evet, ben varim! Haber vermeni bekliyorum 🙌',
        'Bu konu beni cok heyecanlandirdi, devam edelim!',
      ],
      en: [
        'Great topic choice, this looks fun! 😄',
        'This listing caught my attention, shall we discuss details?',
        `${pn ? pn + ', this ' : 'This '}idea is really interesting!`,
        'I would love to join, sounds awesome 🙌',
        'This post came at the perfect time, exactly what I was looking for!',
        `${pn ? pn + ', w' : 'W'}e could have a great time together!`,
        'What a great idea! Could I get more details?',
        'Love seeing posts like this, thanks for sharing!',
        'Yes, count me in! Let me know 🙌',
        'This topic got me excited, let\'s keep going!',
      ],
      ru: [
        'Отличная тема, выглядит очень интересно! 😄',
        'Это объявление привлекло мое внимание, обсудим детали?',
        `${pn ? pn + ', эта ' : 'Эта '}идея мне очень понравилась!`,
        'Я бы с удовольствием присоединился 🙌',
        'Пост пришёл в нужное время, именно то, что искал!',
        `${pn ? pn + ', м' : 'М'}ы можем отлично провести время вместе!`,
        'Какая отличная идея! Можно узнать подробности?',
        'Рад видеть такие посты! Спасибо. Я в деле 🙌',
      ],
      de: [
        'Tolles Thema, sieht richtig spannend aus! 😄',
        'Diese Anzeige hat meine Aufmerksamkeit geweckt, Details?',
        `${pn ? pn + ', diese ' : 'Diese '}Idee finde ich super!`,
        'Ich waere gern dabei 🙌',
        'Dieser Beitrag kam genau zur richtigen Zeit!',
        `${pn ? pn + ', w' : 'W'}ir koennten toll zusammen Spass haben!`,
        'Was fuer eine tolle Idee! Koennte ich mehr Details erfahren?',
        'Freue mich, solche Posts zu sehen. Ich mache mit 🙌',
      ],
      fr: [
        'Tres bon theme, ca a l air sympa ! 😄',
        'Cette annonce a attire mon attention, on en parle ?',
        `${pn ? pn + ', cette ' : 'Cette '}idee me plait beaucoup !`,
        'Je veux bien participer 🙌',
        'Ce post est tombe au bon moment, exactement ce que je cherchais!',
        `${pn ? pn + ', n' : 'N'}ous pourrions passer un super moment ensemble!`,
        'Quelle super idee ! Je peux avoir plus de details ?',
        'Content de voir ce genre de posts, merci! Je suis partant 🙌',
      ],
      es: [
        'Gran tema, se ve muy divertido! 😄',
        'Este anuncio me llamo la atencion, vemos detalles?',
        `${pn ? pn + ', esta ' : 'Esta '}idea me encanto!`,
        'Me gustaria unirme 🙌',
        'Esta publicacion llego en el momento justo, es lo que buscaba!',
        `${pn ? pn + ', p' : 'P'}odriamos pasarla genial juntos!`,
        'Que gran idea! Puedo obtener mas detalles?',
        'Me alegra ver estos posts, gracias! Cuenten conmigo 🙌',
      ],
      ja: [
        'いいテーマですね、とても面白そうです！ 😄',
        'この募集が気になりました。詳細を話しませんか？',
        `${pn ? pn + 'さん、この' : 'この'}アイデアすごくいいです！`,
        'ぜひ参加したいです 🙌',
        'このポストはタイミングばっちり！まさに探していたものです！',
        `${pn ? pn + 'さん、一' : '一'}緒に素晴らしい時間が過ごせそうです！`,
        'なんて良いアイデア！詳細を教えていただけますか？',
        'こういう投稿を見るのは嬉しいです。参加します 🙌',
      ],
      ko: [
        '주제 정말 좋아요, 재미있어 보여요! 😄',
        '이 모집 눈에 띄네요, 자세히 이야기해요?',
        `${pn ? pn + '님, 이 ' : '이 '}아이디어 정말 좋아요!`,
        '저도 참여하고 싶어요 🙌',
        '딱 필요한 때 올라온 글이에요, 찾던 거예요!',
        `${pn ? pn + '님, 같이' : '같이'} 정말 즐거운 시간 보낼 수 있을 것 같아요!`,
        '정말 좋은 아이디어네요! 자세한 내용 알 수 있을까요?',
        '이런 글 보니 기분 좋네요, 감사해요! 참여할게요 🙌',
      ],
      pt: [
        'Otimo tema, parece super divertido! 😄',
        'Este anuncio chamou minha atencao, vamos falar dos detalhes?',
        `${pn ? pn + ', essa ' : 'Essa '}ideia me agradou muito!`,
        'Quero participar tambem 🙌',
        'Este post chegou na hora certa, e exatamente o que eu procurava!',
        `${pn ? pn + ', p' : 'P'}oderiamos passar um otimo tempo juntos!`,
        'Que otima ideia! Posso saber mais detalhes?',
        'Que bom ver posts assim, obrigado! Pode me contar 🙌',
      ],
      it: [
        'Ottimo tema, sembra davvero divertente! 😄',
        'Questo annuncio ha attirato la mia attenzione, dettagli?',
        `${pn ? pn + ', questa ' : 'Questa '}idea mi piace molto!`,
        'Mi piacerebbe partecipare 🙌',
        'Questo post e arrivato al momento giusto, e esattamente cio che cercavo!',
        `${pn ? pn + ', p' : 'P'}otremmo passare un ottimo momento insieme!`,
        'Che bella idea! Potrei avere piu dettagli?',
        'Bello vedere post come questo, grazie! Ci sono 🙌',
      ],
      ar: [
        'فكرة جميلة جدا وتبدو ممتعة! 😄',
        'هذا الإعلان لفت انتباهي، هل نتحدث عن التفاصيل؟',
        `${pn ? pn + '، هذه ' : 'هذه '}الفكرة أعجبتني جدا!`,
        'أرغب بالمشاركة أيضا 🙌',
        'هذا المنشور جاء في الوقت المناسب، هذا ما كنت أبحث عنه!',
        `${pn ? pn + '، يمكننا' : 'يمكننا'} قضاء وقت رائع معاً!`,
        'يا لها من فكرة رائعة! هل يمكنني معرفة المزيد من التفاصيل؟',
        'يسعدني رؤية مثل هذه المنشورات. أنا معكم 🙌',
      ],
    };
    const pool = genericTemplates[language] || genericTemplates.en;
    const base = pool[hashSeed(`${seedBase}-generic-body`) % pool.length];
    return appendCommentEmojiFlavor(base, `${seedBase}-generic-flavor`);
  }

  const templates = {
    tr: [
      `Harika paylaşım! ${s} tutkunlarına selamlar 🙌`,
      `Ben de ${s} yapıyorum, seninle antrenman yapmayı isterim!`,
      `${pn ? pn + ', bu ' : 'Bu '}paylaşım ilgimi çekti, devam et!`,
      `${s} için çok güzel bir motivasyon, teşekkürler!`,
      `Süper! Ben de aynı his içindeyim, ${s} harika 💪`,
      `${pn ? pn + ' ' : ''}ne zaman ve nerede? Katılmak isterim!`,
      `Bence de ${s} en iyi spor 🏆`,
      `Devam et, böyle paylaşımlar çok motive edici!`,
      `${s} sevgisi her yerden belli! Keşke ben de orada olsaydım.`,
      `${pn ? pn + ', b' : 'B'}u enerji bulaşıcı! ${s} için seni takip ediyorum 🔥`,
      `${s} hakkında bu kadar samimi paylaşım gören nadir! Süper 👏`,
      `Bende de aynı heves var, belki bir gün birlikte ${s} oynayabiliriz!`,
      `${s} dünyasına hoş geldin! Keyifler daim olsun!`,
      `Tam aradığım enerji! ${s} için kim buradaysa buraya! 💯`,
      `Güzel motivasyon! ${s} buluşması organize edelim mi? 😄`,
    ],
    en: [
      `Great post! Shoutout to all ${s} fans 🙌`,
      `I do ${s} too! Would love to train with you.`,
      `${pn ? pn + ', this ' : 'This '}post caught my eye. Keep it up!`,
      `Such great motivation for ${s}, thanks!`,
      `Awesome! Feeling the same way, ${s} is amazing 💪`,
      `${pn ? pn + ' ' : ''}when and where? I'd love to join!`,
      `I agree, ${s} is the best sport 🏆`,
      `Keep going, posts like this are so motivating!`,
      `The love for ${s} is real! Wish I was there.`,
      `${pn ? pn + ', t' : 'T'}his energy is contagious! Following for ${s} updates 🔥`,
      `Rarely see such honest posts about ${s}! Superb 👏`,
      `I have the same passion — maybe we can play ${s} together someday!`,
      `Welcome to the ${s} community! May the joy last forever!`,
      `This is exactly the energy I needed! Anyone else into ${s}? 💯`,
      `Great motivation! Should we organize a ${s} meetup? 😄`,
    ],
    ru: [
      `Отличный пост! Привет всем любителям ${s} 🙌`,
      `Я тоже занимаюсь ${s}! Хотел бы потренироваться вместе.`,
      `${pn ? pn + ', этот ' : 'Этот '}пост меня зацепил. Продолжай!`,
      `Такая хорошая мотивация для ${s}, спасибо!`,
      `Супер! Полностью согласен, ${s} — это здорово 💪`,
      `${pn ? pn + ', к' : 'К'}огда и где? Я бы с удовольствием присоединился!`,
      `Согласен, ${s} — лучший вид спорта 🏆`,
      `Продолжай! Такие посты очень мотивируют.`,
      `Та же страсть к ${s}! Может, сыграем вместе когда-нибудь?`,
      `Эта энергия заразительна! Слежу за ${s}-контентом 🔥`,
    ],
    de: [
      `Toller Beitrag! Grüße an alle ${s}-Fans 🙌`,
      `Ich mache auch ${s}! Würde gerne mit dir trainieren.`,
      `${pn ? pn + ', dieser ' : 'Dieser '}Beitrag hat mich angesprochen. Weiter so!`,
      `So eine tolle Motivation für ${s}, danke!`,
      `Super! Fühle genau dasselbe, ${s} ist großartig 💪`,
      `${pn ? pn + ', w' : 'W'}ann und wo? Ich würde gerne mitmachen!`,
      `Ich stimme zu, ${s} ist der beste Sport 🏆`,
      `Weiter so! Solche Posts motivieren sehr.`,
      `Die gleiche Leidenschaft für ${s}! Vielleicht spielen wir eines Tages zusammen?`,
      `Diese Energie ist ansteckend! Folge für ${s}-Content 🔥`,
    ],
    fr: [
      `Super post ! Salut à tous les fans de ${s} 🙌`,
      `Je fais aussi du ${s} ! J'aimerais m'entraîner avec toi.`,
      `${pn ? pn + ', ce ' : 'Ce '}post m'a accroché. Continue!`,
      `Quelle bonne motivation pour ${s}, merci!`,
      `Super ! Je ressens la même chose, ${s} c'est génial 💪`,
      `${pn ? pn + ', q' : 'Q'}uand et où ? J'adorerais participer !`,
      `Je suis d'accord, ${s} est le meilleur sport 🏆`,
      `Continue ! Des posts comme ça motivent vraiment.`,
      `La même passion pour ${s} ! On joue ensemble un jour ?`,
      `Cette énergie est contagieuse ! Je suis pour ${s} 🔥`,
    ],
    es: [
      `¡Gran publicación! Saludos a todos los fans de ${s} 🙌`,
      `¡Yo también hago ${s}! Me encantaría entrenar contigo.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicación me llamó la atención. ¡Sigue así!`,
      `¡Qué buena motivación para ${s}, gracias!`,
      `¡Genial! Siento lo mismo, ${s} es increíble 💪`,
      `${pn ? pn + ', ¿' : '¿'}cuándo y dónde? ¡Me encantaría unirme!`,
      `Estoy de acuerdo, ${s} es el mejor deporte 🏆`,
      `¡Sigue así! Posts como este motivan mucho.`,
      `¡La misma pasión por ${s}! ¿Jugamos juntos algún día?`,
      `¡Esta energía es contagiosa! Sigo el contenido de ${s} 🔥`,
    ],
    ja: [
      `素晴らしい投稿！${s}ファンのみんなによろしく 🙌`,
      `私も${s}やってます！一緒に練習したいです。`,
      `${pn ? pn + 'さん、この' : 'この'}投稿が気になりました。続けてください！`,
      `${s}のモチベーションになります、ありがとう！`,
      `最高！同じ気持ちです、${s}は素晴らしい 💪`,
      `${pn ? pn + 'さん、い' : 'い'}つ・どこで？ぜひ参加したいです！`,
      `同意します、${s}は最高のスポーツです 🏆`,
      `続けてください！こういう投稿は本当に励みになります。`,
      `同じ${s}愛好家！いつか一緒にプレーできるといいですね！`,
      `このエネルギーは伝染します！${s}の最新情報をフォロー中 🔥`,
    ],
    ko: [
      `좋은 게시물이에요! ${s} 팬 모두 화이팅 🙌`,
      `저도 ${s} 해요! 같이 훈련하고 싶어요.`,
      `${pn ? pn + '님, 이 ' : '이 '}게시물 눈에 띄었어요. 계속 해주세요!`,
      `${s} 동기부여 되네요, 감사해요!`,
      `최고! 같은 기분이에요, ${s} 최고 💪`,
      `${pn ? pn + '님, 언제 어디서요' : '언제 어디서요'}? 꼭 참여하고 싶어요!`,
      `맞아요, ${s}가 최고의 운동이에요 🏆`,
      `계속 해주세요! 이런 게시물이 정말 동기부여 돼요.`,
      `같은 ${s} 열정! 언젠가 같이 할 수 있으면 좋겠어요!`,
      `이 에너지 전염성 있어요! ${s} 소식 팔로우 중 🔥`,
    ],
    pt: [
      `Ótima postagem! Saudações a todos os fãs de ${s} 🙌`,
      `Eu também faço ${s}! Adoraria treinar com você.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicação me chamou atenção. Continue assim!`,
      `Que boa motivação para ${s}, obrigado!`,
      `Incrível! Sinto o mesmo, ${s} é fantástico 💪`,
      `${pn ? pn + ', q' : 'Q'}uando e onde? Adoraria participar!`,
      `Concordo, ${s} é o melhor esporte 🏆`,
      `Continue! Posts assim motivam muito.`,
      `A mesma paixão por ${s}! Quem sabe jogamos juntos um dia?`,
      `Essa energia é contagiante! Acompanhando o conteúdo de ${s} 🔥`,
    ],
    it: [
      `Ottimo post! Saluti a tutti i fan di ${s} 🙌`,
      `Faccio anch'io ${s}! Mi piacerebbe allenarmi con te.`,
      `${pn ? pn + ', questo ' : 'Questo '}post mi ha colpito. Continua così!`,
      `Che bella motivazione per ${s}, grazie!`,
      `Super! Provo la stessa cosa, ${s} è fantastico 💪`,
      `${pn ? pn + ', q' : 'Q'}uando e dove? Mi piacerebbe partecipare!`,
      `Sono d'accordo, ${s} è il miglior sport 🏆`,
      `Vai avanti! Post come questo motivano tantissimo.`,
      `La stessa passione per ${s}! Magari giochiamo insieme un giorno?`,
      `Questa energia è contagiosa! Seguo il contenuto di ${s} 🔥`,
    ],
    ar: [
      `منشور رائع! تحية لجميع محبي ${s} 🙌`,
      `أنا أيضاً أمارس ${s}! أود التدرب معك.`,
      `${pn ? pn + '، هذا ' : 'هذا '}المنشور لفت انتباهي. استمر!`,
      `هذا تحفيز رائع لـ ${s}، شكراً!`,
      `رائع! أشعر بنفس الشيء، ${s} مذهل 💪`,
      `${pn ? pn + '، متى وأين؟' : 'متى وأين؟'} أود المشاركة!`,
      `أوافقك، ${s} هو أفضل رياضة 🏆`,
      `استمر! مثل هذه المنشورات محفزة جداً.`,
      `نفس الشغف بـ ${s}! ربما نلعب معاً يوماً ما!`,
      `هذه الطاقة معدية! أتابع محتوى ${s} 🔥`,
    ],
  };
  const pool = templates[language] || templates.en;
  const base = pool[hashSeed(`${seedBase}-sport-body`) % pool.length];
  return appendCommentEmojiFlavor(base, `${seedBase}-sport-flavor`);
}

module.exports = {
  hashSeed,
  getBotPersona,
  mapCountryCodeToLocale,
  buildBotAvatarUrl,
  translateSportName,
  LOCALIZED_NAMES,
  DEFAULT_NAMES,
  generateBotBio,
  generateListingDesc,
  generateResponseMsg,
  generateShadowMatchText,
  generateBotSocialPost,
  generateBotSocialTopicListing,
  generateBotSocialListing,
  generateBotComment,
  estimateBotCoordinates,
  getFutureDate,
};
