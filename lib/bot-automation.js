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
};

const SPORT_NAME_LOCALE_OVERRIDES = {
  tr: {
    football: 'Futbol', basketball: 'Basketbol', volleyball: 'Voleybol', tennis: 'Tenis',
    padel: 'Padel', fitness: 'Fitness', swimming: 'Yuzme', running: 'Kosu', hiking: 'Yuruyus',
    yoga: 'Yoga', pilates: 'Pilates', cricket: 'Kriket', badminton: 'Badminton',
    table_tennis: 'Masa Tenisi', baseball: 'Beyzbol', kabaddi: 'Kabaddi',
    martial_arts: 'Dovus Sanatlari', archery: 'Okculuk', equestrian: 'Binicilik',
    sand_surfing: 'Kum Sorfu', cycling: 'Bisiklet', american_football: 'Amerikan Futbolu',
    rugby: 'Rugby', ice_hockey: 'Buz Hokeyi', handball: 'Hentbol', skateboarding: 'Kaykay',
    skating: 'Paten', surfing: 'Sorf', crossfit: 'Crossfit', pickleball: 'Pickleball',
    billiards: 'Bilardo', darts: 'Dart', bowling: 'Bowling', fishing: 'Balik Tutma',
    paintball: 'Paintball', dance: 'Dans', okey: 'Okey', tavla: 'Tavla', satranc: 'Satranc',
  },
  de: {
    football: 'Fussball', basketball: 'Basketball', volleyball: 'Volleyball', tennis: 'Tennis',
    running: 'Laufen', hiking: 'Wandern', swimming: 'Schwimmen', cycling: 'Radfahren',
    table_tennis: 'Tischtennis', yoga: 'Yoga', pilates: 'Pilates', fitness: 'Fitness',
    okey: 'Okey', tavla: 'Backgammon', satranc: 'Schach',
  },
  ru: {
    football: 'Futbol', basketball: 'Basketbol', volleyball: 'Voleybol', tennis: 'Tennis',
    running: 'Beg', hiking: 'Pokhod', swimming: 'Plavanie', cycling: 'Velosport',
    table_tennis: 'Nastolny tennis', yoga: 'Yoga', pilates: 'Pilates', fitness: 'Fitnes',
    okey: 'Okei', tavla: 'Nardy', satranc: 'Shakhmaty',
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
function generateBotBio({ locale, sportName, cityName, persona }) {
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
  const base = pool[hashSeed(`${s}-${c}-${persona || ''}`) % pool.length];
  if (persona) return `${base} Style: ${persona}.`;
  return base;
}

// ─── Listing description ───────────────────────────────────────────────────────
function generateListingDesc({ name, sport, locale, city }) {
  const s = sport || 'sport';
  const templates = {
    tr: [
      `Bu hafta ${s} için partner arıyorum.`,
      `${city ? city + ' tarafında ' : ''}${s} için eşleşmek isteyen yazabilir.`,
      `${s} için seviyeden bağımsız bir eşleşme arıyorum.`,
      `${name} olarak ${s} için yeni bir eşleşme açtım.`,
    ],
    en: [
      `Looking for a partner for ${s} this week.`,
      `${city ? 'Around ' + city + ', ' : ''}I am open to a ${s} match.`,
      `All levels are welcome for this ${s} session.`,
      `${name} is looking for a ${s} match.`,
    ],
    ru: [`Ищу партнера по ${s} на этой неделе.`, `${name} ищет соперника по ${s}.`],
    de: [`Ich suche diese Woche einen Partner für ${s}.`, `${name} sucht ein Match für ${s}.`],
    fr: [`Je cherche un partenaire pour ${s} cette semaine.`, `${name} cherche un match de ${s}.`],
    es: [`Busco compañero para ${s} esta semana.`, `${name} busca un partido de ${s}.`],
    ja: [`今週${s}のパートナーを募集しています。`, `${name}が${s}のマッチ相手を探しています。`],
    ko: [`이번 주 ${s} 파트너를 찾고 있어요.`, `${name} 님이 ${s} 매치 상대를 찾고 있어요.`],
    pt: [`Procuro parceiro para ${s} esta semana.`, `${name} procura uma partida de ${s}.`],
    it: [`Cerco un partner per ${s} questa settimana.`, `${name} cerca un match di ${s}.`],
    ar: [`أبحث عن شريك لـ ${s} هذا الأسبوع.`, `${name} يبحث عن مباراة ${s}.`],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
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
  const templates = {
    tr: `${listingBotName} ve ${responderBotName} bugün ${s} maçını tamamladı!${cityName ? ' (' + cityName + ')' : ''}`,
    en: `${listingBotName} and ${responderBotName} completed a ${s} match today!${cityName ? ' (' + cityName + ')' : ''}`,
    ru: `${listingBotName} и ${responderBotName} сегодня завершили матч по ${s}!${cityName ? ' (' + cityName + ')' : ''}`,
    de: `${listingBotName} und ${responderBotName} haben heute ein ${s}-Match abgeschlossen!${cityName ? ' (' + cityName + ')' : ''}`,
    fr: `${listingBotName} et ${responderBotName} ont terminé un match de ${s} aujourd'hui !${cityName ? ' (' + cityName + ')' : ''}`,
    es: `${listingBotName} y ${responderBotName} completaron hoy un partido de ${s}!${cityName ? ' (' + cityName + ')' : ''}`,
    ja: `${listingBotName}さんと${responderBotName}さんが今日、${s}のマッチを完了しました！${cityName ? ' (' + cityName + ')' : ''}`,
    ko: `${listingBotName}님과 ${responderBotName}님이 오늘 ${s} 매치를 완료했어요!${cityName ? ' (' + cityName + ')' : ''}`,
    pt: `${listingBotName} e ${responderBotName} completaram uma partida de ${s} hoje!${cityName ? ' (' + cityName + ')' : ''}`,
    it: `${listingBotName} e ${responderBotName} hanno completato un match di ${s} oggi!${cityName ? ' (' + cityName + ')' : ''}`,
    ar: `${listingBotName} و${responderBotName} أكملا مباراة ${s} اليوم!${cityName ? ' (' + cityName + ')' : ''}`,
  };
  return templates[locale] || templates.en;
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
function generateBotSocialPost({ locale, sportName, cityName, botName }) {
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
    ],
    ru: [
      `Только что закончил тренировку по ${s}${c ? ' в ' + c : ''}, отличное настроение! 💪`,
      `Ищу партнера по ${s}${c ? ' в ' + c : ''}. Есть желающие?`,
      `Кто любит ${s}? Давайте тренироваться вместе!`,
      `На этой неделе был матч по ${s}, очень понравилось. Советую!`,
      `Ищу новых друзей и партнёров по ${s} 🎯`,
    ],
    de: [
      `Gerade ein tolles ${s}-Training beendet${c ? ' in ' + c : ''}! Fühle mich super 💪`,
      `Suche einen ${s}-Partner${c ? ' in ' + c : ''}. Interesse?`,
      `${s}-Fans, wo seid ihr? Lasst uns zusammen trainieren!`,
      `Diese Woche ein tolles ${s}-Match gehabt. Empfehle es!`,
      `Suche neue Freunde und Partner für ${s} 🎯`,
    ],
    fr: [
      `Viens de finir un super entraînement de ${s}${c ? ' à ' + c : ''}! Je me sens bien 💪`,
      `Je cherche un partenaire de ${s}${c ? ' à ' + c : ''}. Intéressé(e)?`,
      `Fans de ${s}, où êtes-vous? Entraînons-nous ensemble!`,
      `J'ai eu un super match de ${s} cette semaine. Essayez!`,
      `Je cherche de nouveaux amis pour ${s} 🎯`,
    ],
    es: [
      `¡Acabo de terminar un entrenamiento de ${s}${c ? ' en ' + c : ''}! Me siento genial 💪`,
      `Busco compañero de ${s}${c ? ' en ' + c : ''}. ¿Alguien interesado?`,
      `¡Fans de ${s}, estáis ahí? ¡Entrenemos juntos!`,
      `Tuve un gran partido de ${s} esta semana. ¡Pruébenlo!`,
      `Buscando nuevos amigos para ${s} 🎯`,
    ],
    ja: [
      `${c ? c + 'で' : ''}${s}の練習が終わりました！最高の気分です 💪`,
      `${s}のパートナーを探しています${c ? '（' + c + '周辺）' : ''}。興味ある方いますか？`,
      `${s}好きの方、一緒に練習しませんか！`,
      `今週${s}の試合があって楽しかった！おすすめです。`,
      `${s}仲間を探しています 🎯`,
    ],
    ko: [
      `${c ? c + '에서 ' : ''}${s} 훈련 마쳤어요! 최고의 기분 💪`,
      `${s} 파트너 구해요${c ? ' (' + c + ' 근처)' : ''}. 관심있으신 분?`,
      `${s} 좋아하시는 분들, 같이 운동해요!`,
      `이번 주 ${s} 시합 했는데 정말 재밌었어요. 추천해요!`,
      `${s} 같이 할 친구 찾아요 🎯`,
    ],
    pt: [
      `Acabei de terminar um treino incrível de ${s}${c ? ' em ' + c : ''}! Sensação ótima 💪`,
      `Procuro parceiro de ${s}${c ? ' em ' + c : ''}. Alguém interessado?`,
      `Fãs de ${s}, onde estão? Vamos treinar juntos!`,
      `Tive um ótimo jogo de ${s} esta semana. Experimentem!`,
      `Procuro novos amigos para ${s} 🎯`,
    ],
    it: [
      `Ho appena finito un allenamento di ${s}${c ? ' a ' + c : ''}! Mi sento benissimo 💪`,
      `Cerco un partner di ${s}${c ? ' a ' + c : ''}. Qualcuno interessato?`,
      `Fan di ${s}, dove siete? Alleniamoci insieme!`,
      `Ho avuto un ottimo match di ${s} questa settimana. Provatelo!`,
      `Cerco nuovi amici per ${s} 🎯`,
    ],
    ar: [
      `انتهيت للتو من تدريب رائع على ${s}${c ? ' في ' + c : ''}! أشعر بروح عالية 💪`,
      `أبحث عن شريك لـ ${s}${c ? ' في ' + c : ''}. هل من مهتم؟`,
      `محبو ${s}، أين أنتم؟ لنتدرب معاً!`,
      `كان لدي مباراة ${s} رائعة هذا الأسبوع. جربوها!`,
      `أبحث عن أصدقاء جدد لـ ${s} 🎯`,
    ],
  };
  const pool = templates[locale] || templates.en;
  return pool[hashSeed(`${n}-${s}-${c}-post`) % pool.length];
}

// ─── Bot social topic listing (ready-made social templates) ──────────────────
function generateBotSocialTopicListing({ locale, cityName, botName }) {
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
  const dayBucket = Math.floor(Date.now() / 86400000);
  const idx = hashSeed(`${n}-${c}-${locale}-${dayBucket}-topic`) % pool.length;
  const picked = pool[idx];
  return {
    title: picked.title,
    content: `${picked.desc}${c ? ` (${c})` : ''}`,
  };
}

function generateBotSocialListing({ locale, sportName, cityName, botName }) {
  // Mix sports-oriented social posts with ready-made social topic templates.
  if (Math.random() < 0.45) {
    const topic = generateBotSocialTopicListing({ locale, cityName, botName });
    return { kind: 'TOPIC', title: topic.title, content: topic.content };
  }
  return {
    kind: 'SPORT',
    title: null,
    content: generateBotSocialPost({ locale, sportName, cityName, botName }),
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
  const dayBucket = Math.floor(Date.now() / 86400000);
  const seedBase = `${language}-${s || 'generic'}-${pn}-${botId || ''}-${postId || ''}-${dayBucket}-${attempt}`;

  if (!s) {
    const genericTemplates = {
      tr: [
        'Harika konu secimi, cok eglenceli gorunuyor! 😄',
        'Bu ilan dikkatimi cekti, detaylari konusalim mi?',
        `${pn ? pn + ', bu ' : 'Bu '}fikir gercekten hosuma gitti!`,
        'Ben de katilmak isterim, cok keyifli duruyor 🙌',
      ],
      en: [
        'Great topic choice, this looks fun! 😄',
        'This listing caught my attention, shall we discuss details?',
        `${pn ? pn + ', this ' : 'This '}idea is really interesting!`,
        'I would love to join, sounds awesome 🙌',
      ],
      ru: [
        'Отличная тема, выглядит очень интересно! 😄',
        'Это объявление привлекло мое внимание, обсудим детали?',
        `${pn ? pn + ', эта ' : 'Эта '}идея мне очень понравилась!`,
        'Я бы с удовольствием присоединился 🙌',
      ],
      de: [
        'Tolles Thema, sieht richtig spannend aus! 😄',
        'Diese Anzeige hat meine Aufmerksamkeit geweckt, Details?',
        `${pn ? pn + ', diese ' : 'Diese '}Idee finde ich super!`,
        'Ich waere gern dabei 🙌',
      ],
      fr: [
        'Tres bon theme, ca a l air sympa ! 😄',
        'Cette annonce a attire mon attention, on en parle ?',
        `${pn ? pn + ', cette ' : 'Cette '}idee me plait beaucoup !`,
        'Je veux bien participer 🙌',
      ],
      es: [
        'Gran tema, se ve muy divertido! 😄',
        'Este anuncio me llamo la atencion, vemos detalles?',
        `${pn ? pn + ', esta ' : 'Esta '}idea me encanto!`,
        'Me gustaria unirme 🙌',
      ],
      ja: [
        'いいテーマですね、とても面白そうです！ 😄',
        'この募集が気になりました。詳細を話しませんか？',
        `${pn ? pn + 'さん、この' : 'この'}アイデアすごくいいです！`,
        'ぜひ参加したいです 🙌',
      ],
      ko: [
        '주제 정말 좋아요, 재미있어 보여요! 😄',
        '이 모집 눈에 띄네요, 자세히 이야기해요?',
        `${pn ? pn + '님, 이 ' : '이 '}아이디어 정말 좋아요!`,
        '저도 참여하고 싶어요 🙌',
      ],
      pt: [
        'Otimo tema, parece super divertido! 😄',
        'Este anuncio chamou minha atencao, vamos falar dos detalhes?',
        `${pn ? pn + ', essa ' : 'Essa '}ideia me agradou muito!`,
        'Quero participar tambem 🙌',
      ],
      it: [
        'Ottimo tema, sembra davvero divertente! 😄',
        'Questo annuncio ha attirato la mia attenzione, dettagli?',
        `${pn ? pn + ', questa ' : 'Questa '}idea mi piace molto!`,
        'Mi piacerebbe partecipare 🙌',
      ],
      ar: [
        'فكرة جميلة جدا وتبدو ممتعة! 😄',
        'هذا الإعلان لفت انتباهي، هل نتحدث عن التفاصيل؟',
        `${pn ? pn + '، هذه ' : 'هذه '}الفكرة أعجبتني جدا!`,
        'أرغب بالمشاركة أيضا 🙌',
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
    ],
    ru: [
      `Отличный пост! Привет всем любителям ${s} 🙌`,
      `Я тоже занимаюсь ${s}! Хотел бы потренироваться вместе.`,
      `${pn ? pn + ', этот ' : 'Этот '}пост меня зацепил. Продолжай!`,
      `Такая хорошая мотивация для ${s}, спасибо!`,
      `Супер! Полностью согласен, ${s} — это здорово 💪`,
    ],
    de: [
      `Toller Beitrag! Grüße an alle ${s}-Fans 🙌`,
      `Ich mache auch ${s}! Würde gerne mit dir trainieren.`,
      `${pn ? pn + ', dieser ' : 'Dieser '}Beitrag hat mich angesprochen. Weiter so!`,
      `So eine tolle Motivation für ${s}, danke!`,
      `Super! Fühle genau dasselbe, ${s} ist großartig 💪`,
    ],
    fr: [
      `Super post ! Salut à tous les fans de ${s} 🙌`,
      `Je fais aussi du ${s} ! J'aimerais m'entraîner avec toi.`,
      `${pn ? pn + ', ce ' : 'Ce '}post m'a accroché. Continue!`,
      `Quelle bonne motivation pour ${s}, merci!`,
      `Super ! Je ressens la même chose, ${s} c'est génial 💪`,
    ],
    es: [
      `¡Gran publicación! Saludos a todos los fans de ${s} 🙌`,
      `¡Yo también hago ${s}! Me encantaría entrenar contigo.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicación me llamó la atención. ¡Sigue así!`,
      `¡Qué buena motivación para ${s}, gracias!`,
      `¡Genial! Siento lo mismo, ${s} es increíble 💪`,
    ],
    ja: [
      `素晴らしい投稿！${s}ファンのみんなによろしく 🙌`,
      `私も${s}やってます！一緒に練習したいです。`,
      `${pn ? pn + 'さん、この' : 'この'}投稿が気になりました。続けてください！`,
      `${s}のモチベーションになります、ありがとう！`,
      `最高！同じ気持ちです、${s}は素晴らしい 💪`,
    ],
    ko: [
      `좋은 게시물이에요! ${s} 팬 모두 화이팅 🙌`,
      `저도 ${s} 해요! 같이 훈련하고 싶어요.`,
      `${pn ? pn + '님, 이 ' : '이 '}게시물 눈에 띄었어요. 계속 해주세요!`,
      `${s} 동기부여 되네요, 감사해요!`,
      `최고! 같은 기분이에요, ${s} 최고 💪`,
    ],
    pt: [
      `Ótima postagem! Saudações a todos os fãs de ${s} 🙌`,
      `Eu também faço ${s}! Adoraria treinar com você.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicação me chamou atenção. Continue assim!`,
      `Que boa motivação para ${s}, obrigado!`,
      `Incrível! Sinto o mesmo, ${s} é fantástico 💪`,
    ],
    it: [
      `Ottimo post! Saluti a tutti i fan di ${s} 🙌`,
      `Faccio anch'io ${s}! Mi piacerebbe allenarmi con te.`,
      `${pn ? pn + ', questo ' : 'Questo '}post mi ha colpito. Continua così!`,
      `Che bella motivazione per ${s}, grazie!`,
      `Super! Provo la stessa cosa, ${s} è fantastico 💪`,
    ],
    ar: [
      `منشور رائع! تحية لجميع محبي ${s} 🙌`,
      `أنا أيضاً أمارس ${s}! أود التدرب معك.`,
      `${pn ? pn + '، هذا ' : 'هذا '}المنشور لفت انتباهي. استمر!`,
      `هذا تحفيز رائع لـ ${s}، شكراً!`,
      `رائع! أشعر بنفس الشيء، ${s} مذهل 💪`,
    ],
  };
  const pool = templates[language] || templates.en;
  const base = pool[hashSeed(`${seedBase}-sport-body`) % pool.length];
  return appendCommentEmojiFlavor(base, `${seedBase}-sport-flavor`);
}

module.exports = {
  hashSeed,
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
