'use strict';
const { v4: uuid } = require('uuid');

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Hash seed (deterministic) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function hashSeed(seed) {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash << 5) - hash + seed.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Country code Ã¢â€ â€™ locale mapping Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Deterministic + region-aware human avatar URL Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Localized bot names by country code Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
const LOCALIZED_NAMES = {
  TR: { male: ['Ahmet Y.', 'Mehmet K.', 'Ali R.', 'Mustafa B.', 'Emre S.', 'Burak T.', 'Murat D.', 'Hasan Ãƒâ€“.'], female: ['AyÃ…Å¸e M.', 'Fatma K.', 'Zeynep B.', 'Elif S.', 'Merve D.', 'Derya T.', 'Selin A.', 'BÃƒÂ¼Ã…Å¸ra Y.'] },
  DE: { male: ['Max M.', 'Felix S.', 'Lukas B.', 'Jonas W.', 'Leon K.', 'Tim H.', 'Paul F.', 'Niklas R.'], female: ['Anna S.', 'Lena M.', 'Sophie B.', 'Marie K.', 'Laura W.', 'Julia H.', 'Lisa F.', 'Sarah R.'] },
  GB: { male: ['James W.', 'Oliver S.', 'Harry B.', 'Jack T.', 'George M.', 'Charlie K.', 'Thomas R.', 'William H.'], female: ['Emma W.', 'Olivia S.', 'Amelia B.', 'Isla T.', 'Sophie M.', 'Mia K.', 'Charlotte R.', 'Emily H.'] },
  FR: { male: ['Lucas M.', 'Hugo D.', 'Louis B.', 'Nathan P.', 'LÃƒÂ©o R.', 'Gabriel S.', 'Jules T.', 'RaphaÃƒÂ«l V.'], female: ['Emma D.', 'LÃƒÂ©a M.', 'ChloÃƒÂ© B.', 'Manon P.', 'Camille R.', 'InÃƒÂ¨s S.', 'ZoÃƒÂ© T.', 'Jade V.'] },
  NL: { male: ['Sem V.', 'Daan B.', 'Lucas M.', 'Levi K.', 'Finn D.', 'Milan S.', 'Bram J.', 'Noah W.'], female: ['Emma V.', 'Sophie B.', 'Julia M.', 'Anna K.', 'Lotte D.', 'Sara S.', 'Mila J.', 'Lisa W.'] },
  US: { male: ['James S.', 'John W.', 'Robert B.', 'Michael T.', 'David K.', 'Chris M.', 'Daniel H.', 'Matthew R.'], female: ['Emily S.', 'Sarah W.', 'Jessica B.', 'Ashley T.', 'Jennifer K.', 'Amanda M.', 'Megan H.', 'Rachel R.'] },
  AZ: { male: ['Ã†Âli M.', 'RÃ‰â„¢Ã…Å¸ad K.', 'Tural B.', 'Orxan S.', 'ElÃ…Å¸Ã‰â„¢n D.', 'Farid T.', 'Murad A.', 'Nicat Y.'], female: ['AygÃƒÂ¼n M.', 'GÃƒÂ¼nel K.', 'LÃ‰â„¢man B.', 'NÃ‰â„¢rmin S.', 'SÃ‰â„¢binÃ‰â„¢ D.', 'Fidan T.', 'Aynur A.', 'RÃ‰â„¢na Y.'] },
  RU: { male: ['Äâ€ÄÂ¼ÄÂ¸Ã‘â€šÃ‘â‚¬ÄÂ¸ÄÂ¹ ÄÅ¡.', 'ÄÂÄÂ»ÄÂµÄÂºÃ‘ÂÄÂµÄÂ¹ ÄÂ¡.', 'ÄËœÄÂ²ÄÂ°ÄÂ½ ÄÅ¸.', 'ÄÅ“ÄÂ¸Ã‘â€¦ÄÂ°ÄÂ¸ÄÂ» Äâ€™.', 'ÄÂ¡ÄÂµÃ‘â‚¬ÄÂ³ÄÂµÄÂ¹ ÄÂ.', 'ÄÂÄÂ½ÄÂ´Ã‘â‚¬ÄÂµÄÂ¹ ÄÅ“.', 'ÄÂÄÂ¸ÄÂºÄÂ¸Ã‘â€šÄÂ° Äâ€º.', 'ÄÂÃ‘â‚¬Ã‘â€šÃ‘â€˜ÄÂ¼ Äâ€˜.'], female: ['ÄÂÄÂ½ÄÂ½ÄÂ° ÄÅ¡.', 'ÄÅ“ÄÂ°Ã‘â‚¬ÄÂ¸Ã‘Â ÄÂ¡.', 'Äâ€¢ÄÂ»ÄÂµÄÂ½ÄÂ° ÄÅ¸.', 'ÄÂÄÂ»Ã‘Å’ÄÂ³ÄÂ° Äâ€™.', 'ÄÂÄÂ°Ã‘â€šÄÂ°ÄÂ»Ã‘Å’Ã‘Â ÄÂ.', 'Äâ€¢ÄÂºÄÂ°Ã‘â€šÄÂµÃ‘â‚¬ÄÂ¸ÄÂ½ÄÂ° ÄÅ“.', 'ÄËœÃ‘â‚¬ÄÂ¸ÄÂ½ÄÂ° Äâ€º.', 'Äâ€ÄÂ°Ã‘â‚¬Ã‘Å’Ã‘Â Äâ€˜.'] },
  SA: { male: ['Mohammed A.', 'Ahmed S.', 'Abdullah K.', 'Khalid M.', 'Faisal R.', 'Omar T.', 'Sultan B.', 'Fahad N.'], female: ['Fatima A.', 'Noura S.', 'Sara K.', 'Maryam M.', 'Lama R.', 'Haya T.', 'Reem B.', 'Amal N.'] },
  IT: { male: ['Marco R.', 'Luca B.', 'Alessandro M.', 'Francesco T.', 'Andrea S.', 'Matteo P.', 'Lorenzo G.', 'Davide F.'], female: ['Giulia R.', 'Francesca B.', 'Sara M.', 'Chiara T.', 'Valentina S.', 'Alessia P.', 'Elena G.', 'Martina F.'] },
  ES: { male: ['Carlos M.', 'Javier S.', 'Miguel R.', 'Alejandro B.', 'David T.', 'Pablo K.', 'Daniel G.', 'AdriÃƒÂ¡n F.'], female: ['MarÃƒÂ­a M.', 'LucÃƒÂ­a S.', 'Carmen R.', 'Ana B.', 'Laura T.', 'Marta K.', 'Paula G.', 'Sara F.'] },
  JP: { male: ['Yuto T.', 'Haruto S.', 'Sota M.', 'Ren K.', 'Kaito N.', 'Riku H.', 'Hinata Y.', 'Hayato O.'], female: ['Yui T.', 'Hana S.', 'Aoi M.', 'Sakura K.', 'Rin N.', 'Mio H.', 'Yuna Y.', 'Koharu O.'] },
  KR: { male: ['Minjun K.', 'Seoho L.', 'Jihoon P.', 'Hyunwoo C.', 'Donghyun J.', 'Sungmin Y.', 'Jaeho S.', 'Wonjin H.'], female: ['Jiyeon K.', 'Soyeon L.', 'Hayun P.', 'Minji C.', 'Yuna J.', 'Seoyeon Y.', 'Chaeyoung S.', 'Somin H.'] },
  BR: { male: ['Lucas S.', 'Gabriel O.', 'Mateus F.', 'Pedro A.', 'Gustavo M.', 'Rafael C.', 'Bruno L.', 'Thiago R.'], female: ['Ana S.', 'Julia O.', 'Maria F.', 'Camila A.', 'Beatriz M.', 'Larissa C.', 'Isabela L.', 'Fernanda R.'] },
  PT: { male: ['JoÃƒÂ£o S.', 'Pedro M.', 'Miguel R.', 'Tiago B.', 'Diogo T.', 'AndrÃƒÂ© K.', 'Rui G.', 'Nuno F.'], female: ['Ana S.', 'Maria M.', 'InÃƒÂªs R.', 'Sofia B.', 'Mariana T.', 'Catarina K.', 'Beatriz G.', 'Joana F.'] },
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Sport name localization Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Localized bio generation Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateBotBio({ locale, sportName, cityName, persona }) {
  const s = sportName || 'spor';
  const c = cityName || '';
  const templates = {
    tr: [
      `${c || 'Ã…Âehir merkezinde'} ${s} iÃƒÂ§in dÃƒÂ¼zenli partner arÃ„Â±yorum.`,
      `${s} antrenmanlarÃ„Â±nÃ„Â± aksatmayan biriyle eÃ…Å¸leÃ…Å¸mek istiyorum.`,
      `${c ? c + ' ÃƒÂ§evresinde ' : 'Bu hafta '}${s} maÃƒÂ§Ã„Â± yapalÃ„Â±m.`,
      `${s} iÃƒÂ§in pozitif ve dakik bir eÃ…Å¸leÃ…Å¸me arÃ„Â±yorum.`,
    ],
    en: [
      `Looking for a consistent ${s} partner ${c ? 'around ' + c : 'this week'}.`,
      `I enjoy structured ${s} sessions and reliable teammates.`,
      `${c ? c + ' area' : 'Local area'} ${s} matches work best for me.`,
      `Open to friendly but focused ${s} matches.`,
    ],
    ru: [
      `ÄËœÃ‘â€°Ã‘Æ’ ÄÂ¿ÄÂ¾Ã‘ÂÃ‘â€šÄÂ¾Ã‘ÂÄÂ½ÄÂ½ÄÂ¾ÄÂ³ÄÂ¾ ÄÂ¿ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½ÄÂµÃ‘â‚¬ÄÂ° ÄÂ¿ÄÂ¾ ${s}${c ? ' ÄÂ² Ã‘â‚¬ÄÂ°ÄÂ¹ÄÂ¾ÄÂ½ÄÂµ ' + c : ''}.`,
      `Äâ€ºÃ‘ÂÄÂ±ÄÂ»Ã‘Â Ã‘â‚¬ÄÂµÄÂ³Ã‘Æ’ÄÂ»Ã‘ÂÃ‘â‚¬ÄÂ½Ã‘â€¹ÄÂµ Ã‘â€šÃ‘â‚¬ÄÂµÄÂ½ÄÂ¸Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂºÄÂ¸ ÄÂ¿ÄÂ¾ ${s} ÄÂ¸ ÄÂ¿Ã‘Æ’ÄÂ½ÄÂºÃ‘â€šÃ‘Æ’ÄÂ°ÄÂ»Ã‘Å’ÄÂ½ÄÂ¾Ã‘ÂÃ‘â€šÃ‘Å’.`,
      `ÄÂÃ‘â€šÄÂºÃ‘â‚¬Ã‘â€¹Ã‘â€š ÄÂº ÄÂ¼ÄÂ°Ã‘â€šÃ‘â€¡ÄÂ°ÄÂ¼ ÄÂ¿ÄÂ¾ ${s} ÄÂ² Ã‘Æ’ÄÂ´ÄÂ¾ÄÂ±ÄÂ½ÄÂ¾ÄÂµ ÄÂ²Ã‘â‚¬ÄÂµÄÂ¼Ã‘Â.`,
    ],
    de: [
      `Ich suche einen regelmÃƒÂ¤ÃƒÅ¸igen Partner fÃƒÂ¼r ${s}${c ? ' in ' + c : ''}.`,
      `Strukturierte ${s}-Einheiten und ZuverlÃƒÂ¤ssigkeit sind mir wichtig.`,
      `Offen fÃƒÂ¼r freundliche, aber fokussierte ${s}-Matches.`,
    ],
    fr: [
      `Je cherche un partenaire rÃƒÂ©gulier pour ${s}${c ? ' vers ' + c : ''}.`,
      `J'aime les sessions ${s} bien organisÃƒÂ©es et ponctuelles.`,
    ],
    es: [
      `Busco compaÃƒÂ±ero constante para ${s}${c ? ' por ' + c : ''}.`,
      `Me gustan las sesiones de ${s} organizadas y puntuales.`,
    ],
    ja: [
      `${c ? c + 'Ã¥â€˜Â¨Ã¨Â¾ÂºÃ£ÂÂ§' : ''}${s}Ã£ÂÂ®Ã¥Â®Å¡Ã¦Å“Å¸Ã£Æ’â€˜Ã£Æ’Â¼Ã£Æ’Ë†Ã£Æ’Å Ã£Æ’Â¼Ã£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š`,
      `${s}Ã£â€šâ€™Ã§Â¶â„¢Ã§Â¶Å¡Ã£Ââ€”Ã£ÂÂ¦Ã¤Â¸â‚¬Ã§Â·â€™Ã£ÂÂ«Ã§Â·Â´Ã§Â¿â€™Ã£ÂÂ§Ã£ÂÂÃ£â€šâ€¹Ã¦â€“Â¹Ã£â€šâ€™Ã¥Â¸Å’Ã¦Å“â€ºÃ£Ââ€”Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š`,
    ],
    ko: [
      `${c ? c + ' ÃªÂ·Â¼Ã¬Â²ËœÃ¬â€”ÂÃ¬â€Å“ ' : ''}${s}Ã«Â¥Â¼ Ã­â€¢Â¨ÃªÂ»ËœÃ­â€¢Â  ÃªÂ³Â Ã¬Â â€¢ Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†Ã«Â¥Â¼ Ã¬Â°Â¾ÃªÂ³Â  Ã¬ÂË†Ã¬â€“Â´Ã¬Å¡â€.`,
      `${s}Ã«Â¥Â¼ ÃªÂ¾Â¸Ã¬Â¤â‚¬Ã­ÂË† Ã­â€¢Â  Ã¬Ë†Ëœ Ã¬ÂË†Ã«Å â€ Ã«Â¶â€Ã¬ÂÂ´Ã«Â©Â´ Ã¬Â¢â€¹Ã¬â€¢â€Ã¬Å¡â€.`,
    ],
    pt: [
      `Procuro parceiro regular para ${s}${c ? ' em ' + c : ''}.`,
      `Gosto de sessÃƒÂµes de ${s} organizadas e pontuais.`,
    ],
    it: [
      `Cerco un partner regolare per ${s}${c ? ' a ' + c : ''}.`,
      `Mi piacciono le sessioni di ${s} organizzate e puntuali.`,
    ],
    ar: [
      `Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã™â€¦Ã™â€ Ã˜ÂªÃ˜Â¸Ã™â€¦ Ã™â€Ã™â‚¬ ${s}${c ? ' Ã™ÂÃ™Å  ' + c : ''}.`,
      `Ã˜Â£Ã˜Â­Ã˜Â¨ Ã˜Â¬Ã™â€Ã˜Â³Ã˜Â§Ã˜Âª ${s} Ã˜Â§Ã™â€Ã™â€¦Ã™â€ Ã˜Â¸Ã™â€¦Ã˜Â© Ã™Ë†Ã˜Â§Ã™â€Ã˜Â§Ã™â€Ã˜ÂªÃ˜Â²Ã˜Â§Ã™â€¦ Ã˜Â¨Ã˜Â§Ã™â€Ã™â€¦Ã™Ë†Ã˜Â§Ã˜Â¹Ã™Å Ã˜Â¯.`,
    ],
  };
  const pool = templates[locale] || templates.en;
  const base = pool[hashSeed(`${s}-${c}-${persona || ''}`) % pool.length];
  if (persona) return `${base} Style: ${persona}.`;
  return base;
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Listing description Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateListingDesc({ name, sport, locale, city }) {
  const s = sport || 'sport';
  const templates = {
    tr: [
      `Bu hafta ${s} iÃƒÂ§in partner arÃ„Â±yorum.`,
      `${city ? city + ' tarafÃ„Â±nda ' : ''}${s} iÃƒÂ§in eÃ…Å¸leÃ…Å¸mek isteyen yazabilir.`,
      `${s} iÃƒÂ§in seviyeden baÃ„Å¸Ã„Â±msÃ„Â±z bir eÃ…Å¸leÃ…Å¸me arÃ„Â±yorum.`,
      `${name} olarak ${s} iÃƒÂ§in yeni bir eÃ…Å¸leÃ…Å¸me aÃƒÂ§tÃ„Â±m.`,
    ],
    en: [
      `Looking for a partner for ${s} this week.`,
      `${city ? 'Around ' + city + ', ' : ''}I am open to a ${s} match.`,
      `All levels are welcome for this ${s} session.`,
      `${name} is looking for a ${s} match.`,
    ],
    ru: [`ÄËœÃ‘â€°Ã‘Æ’ ÄÂ¿ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½ÄÂµÃ‘â‚¬ÄÂ° ÄÂ¿ÄÂ¾ ${s} ÄÂ½ÄÂ° Ã‘ÂÃ‘â€šÄÂ¾ÄÂ¹ ÄÂ½ÄÂµÄÂ´ÄÂµÄÂ»ÄÂµ.`, `${name} ÄÂ¸Ã‘â€°ÄÂµÃ‘â€š Ã‘ÂÄÂ¾ÄÂ¿ÄÂµÃ‘â‚¬ÄÂ½ÄÂ¸ÄÂºÄÂ° ÄÂ¿ÄÂ¾ ${s}.`],
    de: [`Ich suche diese Woche einen Partner fÃƒÂ¼r ${s}.`, `${name} sucht ein Match fÃƒÂ¼r ${s}.`],
    fr: [`Je cherche un partenaire pour ${s} cette semaine.`, `${name} cherche un match de ${s}.`],
    es: [`Busco compaÃƒÂ±ero para ${s} esta semana.`, `${name} busca un partido de ${s}.`],
    ja: [`Ã¤Â»Å Ã©â‚¬Â±${s}Ã£ÂÂ®Ã£Æ’â€˜Ã£Æ’Â¼Ã£Æ’Ë†Ã£Æ’Å Ã£Æ’Â¼Ã£â€šâ€™Ã¥â€¹Å¸Ã©â€ºâ€ Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š`, `${name}Ã£ÂÅ’${s}Ã£ÂÂ®Ã£Æ’ÂÃ£Æ’Æ’Ã£Æ’ÂÃ§â€ºÂ¸Ã¦â€°â€¹Ã£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š`],
    ko: [`Ã¬ÂÂ´Ã«Â²Ë† Ã¬Â£Â¼ ${s} Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†Ã«Â¥Â¼ Ã¬Â°Â¾ÃªÂ³Â  Ã¬ÂË†Ã¬â€“Â´Ã¬Å¡â€.`, `${name} Ã«â€¹ËœÃ¬ÂÂ´ ${s} Ã«Â§Â¤Ã¬Â¹Ëœ Ã¬Æ’ÂÃ«Å’â‚¬Ã«Â¥Â¼ Ã¬Â°Â¾ÃªÂ³Â  Ã¬ÂË†Ã¬â€“Â´Ã¬Å¡â€.`],
    pt: [`Procuro parceiro para ${s} esta semana.`, `${name} procura uma partida de ${s}.`],
    it: [`Cerco un partner per ${s} questa settimana.`, `${name} cerca un match di ${s}.`],
    ar: [`Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã™â€Ã™â‚¬ ${s} Ã™â€¡Ã˜Â°Ã˜Â§ Ã˜Â§Ã™â€Ã˜Â£Ã˜Â³Ã˜Â¨Ã™Ë†Ã˜Â¹.`, `${name} Ã™Å Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã™â€¦Ã˜Â¨Ã˜Â§Ã˜Â±Ã˜Â§Ã˜Â© ${s}.`],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Response message Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateResponseMsg(name, locale) {
  const templates = {
    tr: [
      'Merhaba, ilanÃ„Â±n ilgimi ÃƒÂ§ekti. KatÃ„Â±lmak isterim.',
      'MÃƒÂ¼saitim, istersen detaylarÃ„Â± konuÃ…Å¸alÃ„Â±m.',
      'Bu eÃ…Å¸leÃ…Å¸me bana uygun gÃƒÂ¶rÃƒÂ¼nÃƒÂ¼yor.',
      `${name} olarak baÃ…Å¸vuruyorum, uygun olursa sevinirim.`,
    ],
    en: [
      'Hi, this listing looks great. I would like to join.',
      'I am available. We can discuss the details.',
      'This match looks like a good fit for me.',
      `${name} here, I would be happy to join if it works for you.`,
    ],
    ru: ['ÄÅ¸Ã‘â‚¬ÄÂ¸ÄÂ²ÄÂµÃ‘â€š, ÄÂ¾ÄÂ±Ã‘Å Ã‘ÂÄÂ²ÄÂ»ÄÂµÄÂ½ÄÂ¸ÄÂµ ÄÂ·ÄÂ°ÄÂ¸ÄÂ½Ã‘â€šÄÂµÃ‘â‚¬ÄÂµÃ‘ÂÄÂ¾ÄÂ²ÄÂ°ÄÂ»ÄÂ¾. ÄÂ¥ÄÂ¾Ã‘â€¡Ã‘Æ’ ÄÂ¿Ã‘â‚¬ÄÂ¸Ã‘ÂÄÂ¾ÄÂµÄÂ´ÄÂ¸ÄÂ½ÄÂ¸Ã‘â€šÃ‘Å’Ã‘ÂÃ‘Â.', `${name} ÄÂ½ÄÂ° Ã‘ÂÄÂ²Ã‘ÂÄÂ·ÄÂ¸, ÄÂ±Ã‘Æ’ÄÂ´Ã‘Æ’ Ã‘â‚¬ÄÂ°ÄÂ´ ÄÂ¿Ã‘â‚¬ÄÂ¸Ã‘ÂÄÂ¾ÄÂµÄÂ´ÄÂ¸ÄÂ½ÄÂ¸Ã‘â€šÃ‘Å’Ã‘ÂÃ‘Â.`],
    de: ['Hallo, die Anzeige passt gut fÃƒÂ¼r mich. Ich mÃƒÂ¶chte mitmachen.', `${name} hier, ich wÃƒÂ¤re gern dabei.`],
    fr: ['Bonjour, cette annonce m\'intÃƒÂ©resse. Je veux participer.', `${name} ici, je serais ravi de participer.`],
    es: ['Hola, este anuncio me interesa. Me gustarÃƒÂ­a participar.', `${name} por aquÃƒÂ­, encantado de unirme.`],
    ja: ['Ã£Ââ€œÃ£â€šâ€œÃ£ÂÂ«Ã£ÂÂ¡Ã£ÂÂ¯Ã£â‚¬ÂÃ£Ââ€œÃ£ÂÂ®Ã¥â€¹Å¸Ã©â€ºâ€ Ã£ÂÂ«Ã¥Ââ€šÃ¥Å Â Ã£Ââ€”Ã£ÂÅ¸Ã£Ââ€Ã£ÂÂ§Ã£Ââ„¢Ã£â‚¬â€š', `${name}Ã£ÂÂ§Ã£Ââ„¢Ã£â‚¬â€šÃ¥Ââ€šÃ¥Å Â Ã£ÂÂ§Ã£ÂÂÃ£â€šâ€¹Ã£ÂÂ¨Ã¥Â¬â€°Ã£Ââ€”Ã£Ââ€Ã£ÂÂ§Ã£Ââ„¢Ã£â‚¬â€š`],
    ko: ['Ã¬â€¢Ë†Ã«â€¦â€¢Ã­â€¢ËœÃ¬â€Â¸Ã¬Å¡â€, Ã¬ÂÂ´ Ã«ÂªÂ¨Ã¬Â§â€˜Ã¬â€”Â Ã¬Â°Â¸Ã¬â€”Â¬Ã­â€¢ËœÃªÂ³Â  Ã¬â€¹Â¶Ã¬â€“Â´Ã¬Å¡â€.', `${name}Ã¬Ââ€¦Ã«â€¹Ë†Ã«â€¹Â¤. Ã¬Â°Â¸Ã¬â€”Â¬Ã­â€¢Â  Ã¬Ë†Ëœ Ã¬ÂË†Ã¬Å“Â¼Ã«Â©Â´ Ã¬Â¢â€¹ÃªÂ²Â Ã¬â€“Â´Ã¬Å¡â€.`],
    pt: ['OlÃƒÂ¡, este anÃƒÂºncio me interessou. Gostaria de participar.', `${name} aqui, ficaria feliz em participar.`],
    it: ['Ciao, questo annuncio mi interessa. Vorrei partecipare.', `${name} qui, sarei felice di partecipare.`],
    ar: ['Ã™â€¦Ã˜Â±Ã˜Â­Ã˜Â¨Ã™â€¹Ã˜Â§Ã˜Å’ Ã™â€¡Ã˜Â°Ã˜Â§ Ã˜Â§Ã™â€Ã˜Â¥Ã˜Â¹Ã™â€Ã˜Â§Ã™â€  Ã™Å Ã™â€¡Ã™â€¦Ã™â€ Ã™Å . Ã˜Â£Ã™Ë†Ã˜Â¯ Ã˜Â§Ã™â€Ã™â€¦Ã˜Â´Ã˜Â§Ã˜Â±Ã™Æ’Ã˜Â©.', `${name} Ã™â€¡Ã™â€ Ã˜Â§Ã˜Å’ Ã˜Â³Ã˜Â£Ã™Æ’Ã™Ë†Ã™â€  Ã˜Â³Ã˜Â¹Ã™Å Ã˜Â¯Ã™â€¹Ã˜Â§ Ã˜Â¨Ã˜Â§Ã™â€Ã˜Â§Ã™â€ Ã˜Â¶Ã™â€¦Ã˜Â§Ã™â€¦.`],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Shadow match post text Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateShadowMatchText({ locale, listingBotName, responderBotName, sportName, cityName }) {
  const s = sportName || 'sport';
  const templates = {
    tr: `${listingBotName} ve ${responderBotName} bugÃƒÂ¼n ${s} maÃƒÂ§Ã„Â±nÃ„Â± tamamladÃ„Â±!${cityName ? ' (' + cityName + ')' : ''}`,
    en: `${listingBotName} and ${responderBotName} completed a ${s} match today!${cityName ? ' (' + cityName + ')' : ''}`,
    ru: `${listingBotName} ÄÂ¸ ${responderBotName} Ã‘ÂÄÂµÄÂ³ÄÂ¾ÄÂ´ÄÂ½Ã‘Â ÄÂ·ÄÂ°ÄÂ²ÄÂµÃ‘â‚¬Ã‘Ë†ÄÂ¸ÄÂ»ÄÂ¸ ÄÂ¼ÄÂ°Ã‘â€šÃ‘â€¡ ÄÂ¿ÄÂ¾ ${s}!${cityName ? ' (' + cityName + ')' : ''}`,
    de: `${listingBotName} und ${responderBotName} haben heute ein ${s}-Match abgeschlossen!${cityName ? ' (' + cityName + ')' : ''}`,
    fr: `${listingBotName} et ${responderBotName} ont terminÃƒÂ© un match de ${s} aujourd'hui !${cityName ? ' (' + cityName + ')' : ''}`,
    es: `${listingBotName} y ${responderBotName} completaron hoy un partido de ${s}!${cityName ? ' (' + cityName + ')' : ''}`,
    ja: `${listingBotName}Ã£Ââ€¢Ã£â€šâ€œÃ£ÂÂ¨${responderBotName}Ã£Ââ€¢Ã£â€šâ€œÃ£ÂÅ’Ã¤Â»Å Ã¦â€”Â¥Ã£â‚¬Â${s}Ã£ÂÂ®Ã£Æ’ÂÃ£Æ’Æ’Ã£Æ’ÂÃ£â€šâ€™Ã¥Â®Å’Ã¤Âºâ€ Ã£Ââ€”Ã£ÂÂ¾Ã£Ââ€”Ã£ÂÅ¸Ã¯Â¼Â${cityName ? ' (' + cityName + ')' : ''}`,
    ko: `${listingBotName}Ã«â€¹ËœÃªÂ³Â¼ ${responderBotName}Ã«â€¹ËœÃ¬ÂÂ´ Ã¬ËœÂ¤Ã«Å Ëœ ${s} Ã«Â§Â¤Ã¬Â¹ËœÃ«Â¥Â¼ Ã¬â„¢â€Ã«Â£Å’Ã­â€“Ë†Ã¬â€“Â´Ã¬Å¡â€!${cityName ? ' (' + cityName + ')' : ''}`,
    pt: `${listingBotName} e ${responderBotName} completaram uma partida de ${s} hoje!${cityName ? ' (' + cityName + ')' : ''}`,
    it: `${listingBotName} e ${responderBotName} hanno completato un match di ${s} oggi!${cityName ? ' (' + cityName + ')' : ''}`,
    ar: `${listingBotName} Ã™Ë†${responderBotName} Ã˜Â£Ã™Æ’Ã™â€¦Ã™â€Ã˜Â§ Ã™â€¦Ã˜Â¨Ã˜Â§Ã˜Â±Ã˜Â§Ã˜Â© ${s} Ã˜Â§Ã™â€Ã™Å Ã™Ë†Ã™â€¦!${cityName ? ' (' + cityName + ')' : ''}`,
  };
  return templates[locale] || templates.en;
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Deterministic GPS coordinates Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Future date helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function getFutureDate(daysAhead) {
  const d = new Date();
  d.setDate(d.getDate() + daysAhead);
  d.setHours(10 + Math.floor(Math.random() * 8), 0, 0, 0);
  return d;
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Bot social post content Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateBotSocialPost({ locale, sportName, cityName, botName }) {
  const s = sportName || 'sport';
  const c = cityName || '';
  const n = botName || '';
  const templates = {
    tr: [
      `${c ? c + ' parkÃ„Â±nda ' : 'BugÃƒÂ¼n '}${s} antrenmanÃ„Â± yaptÃ„Â±m, harika hissediyorum! ÄŸÅ¸â€™Âª`,
      `${s} iÃƒÂ§in yeni bir partner arÃ„Â±yorum, ilgilenen yazabilir.`,
      `${s} sevenler burada mÃ„Â±? ${c ? c + "'de " : ''}birlikte pratik yapalÃ„Â±m!`,
      `Bu hafta ${s} maÃƒÂ§Ã„Â±m vardÃ„Â±, ÃƒÂ§ok keyifliydi. Siz de deneyin!`,
      `${n ? n + " olarak " : ""}${s} tutkunuyum, yeni arkadaÃ…Å¸lar arÃ„Â±yorum ÄŸÅ¸ÂÂ¯`,
      `${c ? c + " Ã…Å¸ehrinde " : ""}${s} etkinliÃ„Å¸i dÃƒÂ¼zenlemek istiyorum, kim var?`,
      `${s} antrenmanÃ„Â±ndan yeni dÃƒÂ¶ndÃƒÂ¼m, harika bir gÃƒÂ¼ndÃƒÂ¼ Ã¢Ëœâ‚¬Ã¯Â¸Â`,
      `${s} iÃƒÂ§in dÃƒÂ¼zenli grup arÃ„Â±yorum. Seviye ÃƒÂ¶nemli deÃ„Å¸il!`,
    ],
    en: [
      `Just had an amazing ${s} session${c ? ' in ' + c : ''}! Feeling great ÄŸÅ¸â€™Âª`,
      `Looking for a ${s} partner${c ? ' around ' + c : ''}. Anyone interested?`,
      `${s} fans, where are you? Let's train together!`,
      `Had a great ${s} match this week. You should try it!`,
      `Passionate about ${s}, looking for new friends ÄŸÅ¸ÂÂ¯`,
      `Want to organize a ${s} event${c ? ' in ' + c : ''}. Who's in?`,
      `Just came back from ${s} training, what a great day Ã¢Ëœâ‚¬Ã¯Â¸Â`,
      `Looking for a regular ${s} group. All levels welcome!`,
    ],
    ru: [
      `ÄÂ¢ÄÂ¾ÄÂ»Ã‘Å’ÄÂºÄÂ¾ Ã‘â€¡Ã‘â€šÄÂ¾ ÄÂ·ÄÂ°ÄÂºÄÂ¾ÄÂ½Ã‘â€¡ÄÂ¸ÄÂ» Ã‘â€šÃ‘â‚¬ÄÂµÄÂ½ÄÂ¸Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂºÃ‘Æ’ ÄÂ¿ÄÂ¾ ${s}${c ? ' ÄÂ² ' + c : ''}, ÄÂ¾Ã‘â€šÄÂ»ÄÂ¸Ã‘â€¡ÄÂ½ÄÂ¾ÄÂµ ÄÂ½ÄÂ°Ã‘ÂÃ‘â€šÃ‘â‚¬ÄÂ¾ÄÂµÄÂ½ÄÂ¸ÄÂµ! ÄŸÅ¸â€™Âª`,
      `ÄËœÃ‘â€°Ã‘Æ’ ÄÂ¿ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½ÄÂµÃ‘â‚¬ÄÂ° ÄÂ¿ÄÂ¾ ${s}${c ? ' ÄÂ² ' + c : ''}. Äâ€¢Ã‘ÂÃ‘â€šÃ‘Å’ ÄÂ¶ÄÂµÄÂ»ÄÂ°Ã‘ÂÃ‘â€°ÄÂ¸ÄÂµ?`,
      `ÄÅ¡Ã‘â€šÄÂ¾ ÄÂ»Ã‘ÂÄÂ±ÄÂ¸Ã‘â€š ${s}? Äâ€ÄÂ°ÄÂ²ÄÂ°ÄÂ¹Ã‘â€šÄÂµ Ã‘â€šÃ‘â‚¬ÄÂµÄÂ½ÄÂ¸Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂ°Ã‘â€šÃ‘Å’Ã‘ÂÃ‘Â ÄÂ²ÄÂ¼ÄÂµÃ‘ÂÃ‘â€šÄÂµ!`,
      `ÄÂÄÂ° Ã‘ÂÃ‘â€šÄÂ¾ÄÂ¹ ÄÂ½ÄÂµÄÂ´ÄÂµÄÂ»ÄÂµ ÄÂ±Ã‘â€¹ÄÂ» ÄÂ¼ÄÂ°Ã‘â€šÃ‘â€¡ ÄÂ¿ÄÂ¾ ${s}, ÄÂ¾Ã‘â€¡ÄÂµÄÂ½Ã‘Å’ ÄÂ¿ÄÂ¾ÄÂ½Ã‘â‚¬ÄÂ°ÄÂ²ÄÂ¸ÄÂ»ÄÂ¾Ã‘ÂÃ‘Å’. ÄÂ¡ÄÂ¾ÄÂ²ÄÂµÃ‘â€šÃ‘Æ’Ã‘Â!`,
      `ÄËœÃ‘â€°Ã‘Æ’ ÄÂ½ÄÂ¾ÄÂ²Ã‘â€¹Ã‘â€¦ ÄÂ´Ã‘â‚¬Ã‘Æ’ÄÂ·ÄÂµÄÂ¹ ÄÂ¸ ÄÂ¿ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½Ã‘â€˜Ã‘â‚¬ÄÂ¾ÄÂ² ÄÂ¿ÄÂ¾ ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    de: [
      `Gerade ein tolles ${s}-Training beendet${c ? ' in ' + c : ''}! FÃƒÂ¼hle mich super ÄŸÅ¸â€™Âª`,
      `Suche einen ${s}-Partner${c ? ' in ' + c : ''}. Interesse?`,
      `${s}-Fans, wo seid ihr? Lasst uns zusammen trainieren!`,
      `Diese Woche ein tolles ${s}-Match gehabt. Empfehle es!`,
      `Suche neue Freunde und Partner fÃƒÂ¼r ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    fr: [
      `Viens de finir un super entraÃƒÂ®nement de ${s}${c ? ' ÃƒÂ  ' + c : ''}! Je me sens bien ÄŸÅ¸â€™Âª`,
      `Je cherche un partenaire de ${s}${c ? ' ÃƒÂ  ' + c : ''}. IntÃƒÂ©ressÃƒÂ©(e)?`,
      `Fans de ${s}, oÃƒÂ¹ ÃƒÂªtes-vous? EntraÃƒÂ®nons-nous ensemble!`,
      `J'ai eu un super match de ${s} cette semaine. Essayez!`,
      `Je cherche de nouveaux amis pour ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    es: [
      `Ã‚Â¡Acabo de terminar un entrenamiento de ${s}${c ? ' en ' + c : ''}! Me siento genial ÄŸÅ¸â€™Âª`,
      `Busco compaÃƒÂ±ero de ${s}${c ? ' en ' + c : ''}. Ã‚Â¿Alguien interesado?`,
      `Ã‚Â¡Fans de ${s}, estÃƒÂ¡is ahÃƒÂ­? Ã‚Â¡Entrenemos juntos!`,
      `Tuve un gran partido de ${s} esta semana. Ã‚Â¡PruÃƒÂ©benlo!`,
      `Buscando nuevos amigos para ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    ja: [
      `${c ? c + 'Ã£ÂÂ§' : ''}${s}Ã£ÂÂ®Ã§Â·Â´Ã§Â¿â€™Ã£ÂÅ’Ã§Âµâ€šÃ£â€šÂÃ£â€šÅ Ã£ÂÂ¾Ã£Ââ€”Ã£ÂÅ¸Ã¯Â¼ÂÃ¦Å“â‚¬Ã©Â«ËœÃ£ÂÂ®Ã¦Â°â€”Ã¥Ë†â€ Ã£ÂÂ§Ã£Ââ„¢ ÄŸÅ¸â€™Âª`,
      `${s}Ã£ÂÂ®Ã£Æ’â€˜Ã£Æ’Â¼Ã£Æ’Ë†Ã£Æ’Å Ã£Æ’Â¼Ã£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢${c ? 'Ã¯Â¼Ë†' + c + 'Ã¥â€˜Â¨Ã¨Â¾ÂºÃ¯Â¼â€°' : ''}Ã£â‚¬â€šÃ¨Ë†Ë†Ã¥â€˜Â³Ã£Ââ€šÃ£â€šâ€¹Ã¦â€“Â¹Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£Ââ€¹Ã¯Â¼Å¸`,
      `${s}Ã¥Â¥Â½Ã£ÂÂÃ£ÂÂ®Ã¦â€“Â¹Ã£â‚¬ÂÃ¤Â¸â‚¬Ã§Â·â€™Ã£ÂÂ«Ã§Â·Â´Ã§Â¿â€™Ã£Ââ€”Ã£ÂÂ¾Ã£Ââ€ºÃ£â€šâ€œÃ£Ââ€¹Ã¯Â¼Â`,
      `Ã¤Â»Å Ã©â‚¬Â±${s}Ã£ÂÂ®Ã¨Â©Â¦Ã¥ÂË†Ã£ÂÅ’Ã£Ââ€šÃ£ÂÂ£Ã£ÂÂ¦Ã¦Â¥Â½Ã£Ââ€”Ã£Ââ€¹Ã£ÂÂ£Ã£ÂÅ¸Ã¯Â¼ÂÃ£ÂÅ Ã£Ââ„¢Ã£Ââ„¢Ã£â€šÂÃ£ÂÂ§Ã£Ââ„¢Ã£â‚¬â€š`,
      `${s}Ã¤Â»Â²Ã©â€“â€œÃ£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢ ÄŸÅ¸ÂÂ¯`,
    ],
    ko: [
      `${c ? c + 'Ã¬â€”ÂÃ¬â€Å“ ' : ''}${s} Ã­â€ºË†Ã«Â Â¨ Ã«Â§Ë†Ã¬Â³Â¤Ã¬â€“Â´Ã¬Å¡â€! Ã¬ÂµÅ“ÃªÂ³Â Ã¬ÂËœ ÃªÂ¸Â°Ã«Â¶â€ ÄŸÅ¸â€™Âª`,
      `${s} Ã­Å’Å’Ã­Å Â¸Ã«â€Ë† ÃªÂµÂ¬Ã­â€¢Â´Ã¬Å¡â€${c ? ' (' + c + ' ÃªÂ·Â¼Ã¬Â²Ëœ)' : ''}. ÃªÂ´â‚¬Ã¬â€¹Â¬Ã¬ÂË†Ã¬Å“Â¼Ã¬â€¹Â  Ã«Â¶â€?`,
      `${s} Ã¬Â¢â€¹Ã¬â€¢â€Ã­â€¢ËœÃ¬â€¹Å“Ã«Å â€ Ã«Â¶â€Ã«â€œÂ¤, ÃªÂ°â„¢Ã¬ÂÂ´ Ã¬Å¡Â´Ã«Ââ„¢Ã­â€¢Â´Ã¬Å¡â€!`,
      `Ã¬ÂÂ´Ã«Â²Ë† Ã¬Â£Â¼ ${s} Ã¬â€¹Å“Ã­â€¢Â© Ã­â€“Ë†Ã«Å â€Ã«ÂÂ° Ã¬Â â€¢Ã«Â§Â Ã¬ÂÂ¬Ã«Â°Å’Ã¬â€”Ë†Ã¬â€“Â´Ã¬Å¡â€. Ã¬Â¶â€Ã¬Â²Å“Ã­â€¢Â´Ã¬Å¡â€!`,
      `${s} ÃªÂ°â„¢Ã¬ÂÂ´ Ã­â€¢Â  Ã¬Â¹Å“ÃªÂµÂ¬ Ã¬Â°Â¾Ã¬â€¢â€Ã¬Å¡â€ ÄŸÅ¸ÂÂ¯`,
    ],
    pt: [
      `Acabei de terminar um treino incrÃƒÂ­vel de ${s}${c ? ' em ' + c : ''}! SensaÃƒÂ§ÃƒÂ£o ÃƒÂ³tima ÄŸÅ¸â€™Âª`,
      `Procuro parceiro de ${s}${c ? ' em ' + c : ''}. AlguÃƒÂ©m interessado?`,
      `FÃƒÂ£s de ${s}, onde estÃƒÂ£o? Vamos treinar juntos!`,
      `Tive um ÃƒÂ³timo jogo de ${s} esta semana. Experimentem!`,
      `Procuro novos amigos para ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    it: [
      `Ho appena finito un allenamento di ${s}${c ? ' a ' + c : ''}! Mi sento benissimo ÄŸÅ¸â€™Âª`,
      `Cerco un partner di ${s}${c ? ' a ' + c : ''}. Qualcuno interessato?`,
      `Fan di ${s}, dove siete? Alleniamoci insieme!`,
      `Ho avuto un ottimo match di ${s} questa settimana. Provatelo!`,
      `Cerco nuovi amici per ${s} ÄŸÅ¸ÂÂ¯`,
    ],
    ar: [
      `Ã˜Â§Ã™â€ Ã˜ÂªÃ™â€¡Ã™Å Ã˜Âª Ã™â€Ã™â€Ã˜ÂªÃ™Ë† Ã™â€¦Ã™â€  Ã˜ÂªÃ˜Â¯Ã˜Â±Ã™Å Ã˜Â¨ Ã˜Â±Ã˜Â§Ã˜Â¦Ã˜Â¹ Ã˜Â¹Ã™â€Ã™â€° ${s}${c ? ' Ã™ÂÃ™Å  ' + c : ''}! Ã˜Â£Ã˜Â´Ã˜Â¹Ã˜Â± Ã˜Â¨Ã˜Â±Ã™Ë†Ã˜Â­ Ã˜Â¹Ã˜Â§Ã™â€Ã™Å Ã˜Â© ÄŸÅ¸â€™Âª`,
      `Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã™â€Ã™â‚¬ ${s}${c ? ' Ã™ÂÃ™Å  ' + c : ''}. Ã™â€¡Ã™â€ Ã™â€¦Ã™â€  Ã™â€¦Ã™â€¡Ã˜ÂªÃ™â€¦Ã˜Å¸`,
      `Ã™â€¦Ã˜Â­Ã˜Â¨Ã™Ë† ${s}Ã˜Å’ Ã˜Â£Ã™Å Ã™â€  Ã˜Â£Ã™â€ Ã˜ÂªÃ™â€¦Ã˜Å¸ Ã™â€Ã™â€ Ã˜ÂªÃ˜Â¯Ã˜Â±Ã˜Â¨ Ã™â€¦Ã˜Â¹Ã˜Â§Ã™â€¹!`,
      `Ã™Æ’Ã˜Â§Ã™â€  Ã™â€Ã˜Â¯Ã™Å  Ã™â€¦Ã˜Â¨Ã˜Â§Ã˜Â±Ã˜Â§Ã˜Â© ${s} Ã˜Â±Ã˜Â§Ã˜Â¦Ã˜Â¹Ã˜Â© Ã™â€¡Ã˜Â°Ã˜Â§ Ã˜Â§Ã™â€Ã˜Â£Ã˜Â³Ã˜Â¨Ã™Ë†Ã˜Â¹. Ã˜Â¬Ã˜Â±Ã˜Â¨Ã™Ë†Ã™â€¡Ã˜Â§!`,
      `Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â£Ã˜ÂµÃ˜Â¯Ã™â€šÃ˜Â§Ã˜Â¡ Ã˜Â¬Ã˜Â¯Ã˜Â¯ Ã™â€Ã™â‚¬ ${s} ÄŸÅ¸ÂÂ¯`,
    ],
  };
  const pool = templates[locale] || templates.en;
  return pool[hashSeed(`${n}-${s}-${c}-post`) % pool.length];
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Bot social topic listing (ready-made social templates) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function generateBotSocialTopicListing({ locale, cityName, botName }) {
  const c = cityName || '';
  const n = botName || '';
  const templates = {
    tr: [
      { title: 'Hayal Kurma OrtaÃ„Å¸Ã„Â±', desc: 'Birlikte uÃƒÂ§uk fikirler ÃƒÂ¼retip kahve eÃ…Å¸liÃ„Å¸inde gelecek hayalleri kuracak birini arÃ„Â±yorum.' },
      { title: 'Ego Tatmin Partneri', desc: 'BugÃƒÂ¼n karÃ…Å¸Ã„Â±lÃ„Â±klÃ„Â± motive olup birbirimizin ÃƒÂ¶zgÃƒÂ¼venini yÃƒÂ¼kselteceÃ„Å¸imiz bir partner arÃ„Â±yorum ÄŸÅ¸Ëœâ€' },
      { title: 'Motivasyon KankasÃ„Â±', desc: 'ErtelediÃ„Å¸imiz iÃ…Å¸leri birlikte baÃ…Å¸latÃ„Â±p birbirimizi gazlayacaÃ„Å¸Ã„Â±mÃ„Â±z bir ekip arkadaÃ…Å¸Ã„Â± arÃ„Â±yorum.' },
      { title: 'Dil PratiÃ„Å¸i ArkadaÃ…Å¸Ã„Â±', desc: 'GÃƒÂ¼nlÃƒÂ¼k sohbetle dil pratiÃ„Å¸i yapÃ„Â±p keyifli vakit geÃƒÂ§irmek isteyen var mÃ„Â±?' },
      { title: 'Hobi PaylaÃ…Å¸Ã„Â±m OrtaÃ„Å¸Ã„Â±', desc: 'Yeni hobiler deneyip deneyimlerimizi paylaÃ…Å¸acaÃ„Å¸Ã„Â±mÃ„Â±z pozitif bir arkadaÃ…Å¸ arÃ„Â±yorum.' },
      { title: 'MÃƒÂ¼lakat Prova KoÃƒÂ§u', desc: 'KÃ„Â±sa bir mock interview yapÃ„Â±p birbirimize yapÃ„Â±cÃ„Â± geri bildirim verecek birini arÃ„Â±yorum.' },
    ],
    en: [
      { title: 'Daydream Partner', desc: 'Looking for someone to brainstorm wild ideas and daydream over coffee.' },
      { title: 'Ego Boost Partner', desc: 'Looking for a fun partner to hype each other up and boost confidence today ÄŸÅ¸Ëœâ€' },
      { title: 'Motivation Buddy', desc: 'Need someone to start delayed tasks together and keep each other accountable.' },
      { title: 'Language Practice Buddy', desc: 'Anyone up for casual language practice chats and fun conversation?' },
      { title: 'Hobby Share Buddy', desc: 'Looking for a positive friend to explore new hobbies and share experiences.' },
      { title: 'Interview Practice Coach', desc: 'Looking for someone to do a short mock interview and exchange feedback.' },
    ],
    ru: [
      { title: 'ÄÅ¸ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½Ã‘â€˜Ã‘â‚¬ ÄÂ´ÄÂ»Ã‘Â ÄÂ¼ÄÂµÃ‘â€¡Ã‘â€šÄÂ°ÄÂ½ÄÂ¸ÄÂ¹', desc: 'ÄËœÃ‘â€°Ã‘Æ’ Ã‘â€¡ÄÂµÄÂ»ÄÂ¾ÄÂ²ÄÂµÄÂºÄÂ°, Ã‘Â ÄÂºÄÂµÄÂ¼ ÄÂ¼ÄÂ¾ÄÂ¶ÄÂ½ÄÂ¾ ÄÂ·ÄÂ° ÄÂºÄÂ¾Ã‘â€ÄÂµ ÄÂ¾ÄÂ±Ã‘ÂÃ‘Æ’ÄÂ¶ÄÂ´ÄÂ°Ã‘â€šÃ‘Å’ Ã‘ÂÄÂ¼ÄÂµÄÂ»Ã‘â€¹ÄÂµ ÄÂ¸ÄÂ´ÄÂµÄÂ¸ ÄÂ¸ ÄÂ¼ÄÂµÃ‘â€¡Ã‘â€šÃ‘â€¹.' },
      { title: 'ÄÅ¸ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½Ã‘â€˜Ã‘â‚¬ ÄÂ´ÄÂ»Ã‘Â ÄÂ±Ã‘Æ’Ã‘ÂÃ‘â€šÄÂ° Ã‘ÂÄÂ³ÄÂ¾', desc: 'ÄËœÃ‘â€°Ã‘Æ’ ÄÂ½ÄÂ°ÄÂ¿ÄÂ°Ã‘â‚¬ÄÂ½ÄÂ¸ÄÂºÄÂ°, Ã‘â€¡Ã‘â€šÄÂ¾ÄÂ±Ã‘â€¹ ÄÂ²ÄÂ·ÄÂ°ÄÂ¸ÄÂ¼ÄÂ½ÄÂ¾ ÄÂ¼ÄÂ¾Ã‘â€šÄÂ¸ÄÂ²ÄÂ¸Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂ°Ã‘â€šÃ‘Å’ ÄÂ´Ã‘â‚¬Ã‘Æ’ÄÂ³ ÄÂ´Ã‘â‚¬Ã‘Æ’ÄÂ³ÄÂ° ÄÂ¸ ÄÂ¿ÄÂ¾ÄÂ´ÄÂ½Ã‘ÂÃ‘â€šÃ‘Å’ Ã‘Æ’ÄÂ²ÄÂµÃ‘â‚¬ÄÂµÄÂ½ÄÂ½ÄÂ¾Ã‘ÂÃ‘â€šÃ‘Å’ ÄŸÅ¸Ëœâ€' },
      { title: 'ÄÅ“ÄÂ¾Ã‘â€šÄÂ¸ÄÂ²ÄÂ°Ã‘â€ ÄÂ¸ÄÂ¾ÄÂ½ÄÂ½Ã‘â€¹ÄÂ¹ ÄÂ½ÄÂ°ÄÂ¿ÄÂ°Ã‘â‚¬ÄÂ½ÄÂ¸ÄÂº', desc: 'ÄÂÃ‘Æ’ÄÂ¶ÄÂµÄÂ½ ÄÂ½ÄÂ°ÄÂ¿ÄÂ°Ã‘â‚¬ÄÂ½ÄÂ¸ÄÂº, Ã‘â€¡Ã‘â€šÄÂ¾ÄÂ±Ã‘â€¹ ÄÂ²ÄÂ¼ÄÂµÃ‘ÂÃ‘â€šÄÂµ ÄÂ½ÄÂ°Ã‘â€¡ÄÂ°Ã‘â€šÃ‘Å’ ÄÂ¾Ã‘â€šÄÂ»ÄÂ¾ÄÂ¶ÄÂµÄÂ½ÄÂ½Ã‘â€¹ÄÂµ ÄÂ´ÄÂµÄÂ»ÄÂ° ÄÂ¸ ÄÂ½ÄÂµ Ã‘ÂÄÂ´ÄÂ°ÄÂ²ÄÂ°Ã‘â€šÃ‘Å’Ã‘ÂÃ‘Â.' },
      { title: 'ÄÅ¸ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½Ã‘â€˜Ã‘â‚¬ ÄÂ´ÄÂ»Ã‘Â Ã‘ÂÄÂ·Ã‘â€¹ÄÂºÄÂ¾ÄÂ²ÄÂ¾ÄÂ¹ ÄÂ¿Ã‘â‚¬ÄÂ°ÄÂºÃ‘â€šÄÂ¸ÄÂºÄÂ¸', desc: 'ÄÅ¡Ã‘â€šÄÂ¾ Ã‘â€¦ÄÂ¾Ã‘â€¡ÄÂµÃ‘â€š ÄÂ¿Ã‘â‚¬ÄÂ°ÄÂºÃ‘â€šÄÂ¸ÄÂºÄÂ¾ÄÂ²ÄÂ°Ã‘â€šÃ‘Å’ Ã‘ÂÄÂ·Ã‘â€¹ÄÂº ÄÂ² ÄÂ»Ã‘â€˜ÄÂ³ÄÂºÄÂ¸Ã‘â€¦ ÄÂ¸ ÄÂ¸ÄÂ½Ã‘â€šÄÂµÃ‘â‚¬ÄÂµÃ‘ÂÄÂ½Ã‘â€¹Ã‘â€¦ ÄÂ±ÄÂµÃ‘ÂÄÂµÄÂ´ÄÂ°Ã‘â€¦?' },
      { title: 'ÄÅ¸ÄÂ°Ã‘â‚¬Ã‘â€šÄÂ½Ã‘â€˜Ã‘â‚¬ ÄÂ¿ÄÂ¾ Ã‘â€¦ÄÂ¾ÄÂ±ÄÂ±ÄÂ¸', desc: 'ÄËœÃ‘â€°Ã‘Æ’ ÄÂ¿ÄÂ¾ÄÂ·ÄÂ¸Ã‘â€šÄÂ¸ÄÂ²ÄÂ½ÄÂ¾ÄÂ³ÄÂ¾ Ã‘â€¡ÄÂµÄÂ»ÄÂ¾ÄÂ²ÄÂµÄÂºÄÂ° ÄÂ´ÄÂ»Ã‘Â ÄÂ½ÄÂ¾ÄÂ²Ã‘â€¹Ã‘â€¦ Ã‘â€¦ÄÂ¾ÄÂ±ÄÂ±ÄÂ¸ ÄÂ¸ ÄÂ¾ÄÂ±ÄÂ¼ÄÂµÄÂ½ÄÂ° ÄÂ¾ÄÂ¿Ã‘â€¹Ã‘â€šÄÂ¾ÄÂ¼.' },
      { title: 'ÄÅ¡ÄÂ¾Ã‘Æ’Ã‘â€¡ ÄÂ´ÄÂ»Ã‘Â Ã‘ÂÄÂ¾ÄÂ±ÄÂµÃ‘ÂÄÂµÄÂ´ÄÂ¾ÄÂ²ÄÂ°ÄÂ½ÄÂ¸ÄÂ¹', desc: 'ÄËœÃ‘â€°Ã‘Æ’ Ã‘â€¡ÄÂµÄÂ»ÄÂ¾ÄÂ²ÄÂµÄÂºÄÂ° ÄÂ´ÄÂ»Ã‘Â ÄÂºÄÂ¾Ã‘â‚¬ÄÂ¾Ã‘â€šÄÂºÄÂ¾ÄÂ³ÄÂ¾ mock-ÄÂ¸ÄÂ½Ã‘â€šÄÂµÃ‘â‚¬ÄÂ²Ã‘Å’Ã‘Â ÄÂ¸ ÄÂ²ÄÂ·ÄÂ°ÄÂ¸ÄÂ¼ÄÂ½ÄÂ¾ÄÂ¹ ÄÂ¾ÄÂ±Ã‘â‚¬ÄÂ°Ã‘â€šÄÂ½ÄÂ¾ÄÂ¹ Ã‘ÂÄÂ²Ã‘ÂÄÂ·ÄÂ¸.' },
    ],
    de: [
      { title: 'Tagtraum-Partner', desc: 'Suche jemanden, mit dem man bei Kaffee verrueckte Ideen spinnen kann.' },
      { title: 'Ego-Boost-Partner', desc: 'Suche einen lockeren Partner, um uns gegenseitig zu pushen und Selbstvertrauen aufzubauen ÄŸÅ¸Ëœâ€' },
      { title: 'Motivations-Buddy', desc: 'Brauche jemanden, um aufgeschobene Aufgaben gemeinsam zu starten.' },
      { title: 'Sprachpraxis-Buddy', desc: 'Hat jemand Lust auf entspannte Gespraeche zum Sprache ueben?' },
      { title: 'Hobby-Partner', desc: 'Suche eine positive Person, um neue Hobbys auszuprobieren.' },
      { title: 'Interview-Trainingspartner', desc: 'Suche jemanden fuer ein kurzes Mock-Interview mit gegenseitigem Feedback.' },
    ],
    fr: [
      { title: 'Partenaire de reves', desc: 'Je cherche quelquun pour imaginer des idees folles autour dun cafe.' },
      { title: 'Partenaire boost ego', desc: 'Je cherche un partenaire fun pour se motiver mutuellement et gagner en confiance ÄŸÅ¸Ëœâ€' },
      { title: 'Buddy motivation', desc: 'Besoin de quelquun pour lancer les taches repoussees ensemble.' },
      { title: 'Buddy pratique de langue', desc: 'Qui veut pratiquer les langues dans des conversations detendues ?' },
      { title: 'Partenaire hobby', desc: 'Je cherche une personne positive pour explorer de nouveaux hobbies.' },
      { title: 'Coach entretien blanc', desc: 'Je cherche quelquun pour un mini entretien blanc avec feedback mutuel.' },
    ],
    es: [
      { title: 'Compa de suenos', desc: 'Busco a alguien para imaginar ideas locas con cafe de por medio.' },
      { title: 'Partner de ego boost', desc: 'Busco un partner divertido para motivarnos y subir la confianza ÄŸÅ¸Ëœâ€' },
      { title: 'Compa motivacion', desc: 'Necesito a alguien para empezar tareas pendientes juntos.' },
      { title: 'Compa de idiomas', desc: 'Alguien para practicar idiomas con conversaciones relajadas?' },
      { title: 'Compa de hobbies', desc: 'Busco una persona positiva para explorar hobbies nuevos.' },
      { title: 'Coach de entrevista', desc: 'Busco a alguien para hacer una mini entrevista de practica con feedback.' },
    ],
    ja: [
      { title: 'Ã¥Â¦â€Ã¦Æ’Â³Ã£Æ’â€˜Ã£Æ’Â¼Ã£Æ’Ë†Ã£Æ’Å Ã£Æ’Â¼', desc: 'Ã£â€šÂ³Ã£Æ’Â¼Ã£Æ’â€™Ã£Æ’Â¼Ã£â€šâ€™Ã©Â£Â²Ã£ÂÂ¿Ã£ÂÂªÃ£ÂÅ’Ã£â€šâ€°Ã¨â€¡ÂªÃ§â€Â±Ã£ÂÂªÃ£â€šÂ¢Ã£â€šÂ¤Ã£Æ’â€¡Ã£â€šÂ¢Ã£â€šâ€™Ã¨ÂªÂÃ£â€šÅ’Ã£â€šâ€¹Ã§â€ºÂ¸Ã¦â€°â€¹Ã£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š' },
      { title: 'Ã¨â€¡ÂªÃ¤Â¿Â¡Ã£Æ’â€“Ã£Æ’Â¼Ã£â€šÂ¹Ã£Æ’Ë†Ã§â€ºÂ¸Ã¦Â£â€™', desc: 'Ã£ÂÅ Ã¤Âºâ€™Ã£Ââ€Ã£â€šâ€™Ã¨Â¤â€™Ã£â€šÂÃ£ÂÂ¦Ã£Æ’Â¢Ã£Æ’ÂÃ£Æ’â„¢Ã£â€šâ€™Ã¤Â¸Å Ã£Ââ€™Ã£â€šâ€¹Ã¦Â¥Â½Ã£Ââ€”Ã£Ââ€Ã§â€ºÂ¸Ã¦Â£â€™Ã£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢ ÄŸÅ¸Ëœâ€' },
      { title: 'Ã£Æ’Â¢Ã£Æ’ÂÃ£Æ’â„¢Ã¤Â»Â²Ã©â€“â€œ', desc: 'Ã¥â€¦Ë†Ã¥Â»Â¶Ã£ÂÂ°Ã£Ââ€”Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£â€šâ€¹Ã£Ââ€œÃ£ÂÂ¨Ã£â€šâ€™Ã¤Â¸â‚¬Ã§Â·â€™Ã£ÂÂ«Ã¥Â§â€¹Ã£â€šÂÃ£â€šâ€°Ã£â€šÅ’Ã£â€šâ€¹Ã¤Â»Â²Ã©â€“â€œÃ¥â€¹Å¸Ã©â€ºâ€ Ã£â‚¬â€š' },
      { title: 'Ã¨Â¨â‚¬Ã¨ÂªÂÃ§Â·Â´Ã§Â¿â€™Ã£Æ’ÂÃ£Æ’â€¡Ã£â€šÂ£', desc: 'Ã¦Â°â€”Ã¨Â»Â½Ã£ÂÂªÃ£ÂÅ Ã£Ââ€”Ã£â€šÆ’Ã£ÂÂ¹Ã£â€šÅ Ã£ÂÂ§Ã¨Â¨â‚¬Ã¨ÂªÂÃ§Â·Â´Ã§Â¿â€™Ã£Ââ€”Ã£ÂÅ¸Ã£Ââ€Ã¤ÂºÂºÃ£Ââ€Ã£ÂÂ¾Ã£Ââ€ºÃ£â€šâ€œÃ£Ââ€¹Ã¯Â¼Å¸' },
      { title: 'Ã¨Â¶Â£Ã¥â€˜Â³Ã£â€šÂ·Ã£â€šÂ§Ã£â€šÂ¢Ã¤Â»Â²Ã©â€“â€œ', desc: 'Ã¦â€“Â°Ã£Ââ€”Ã£Ââ€Ã¨Â¶Â£Ã¥â€˜Â³Ã£â€šâ€™Ã¨Â©Â¦Ã£Ââ€”Ã£ÂÂ¦Ã¥â€¦Â±Ã¦Å“â€°Ã£ÂÂ§Ã£ÂÂÃ£â€šâ€¹Ã¥â€°ÂÃ¥Ââ€˜Ã£ÂÂÃ£ÂÂªÃ¤Â»Â²Ã©â€“â€œÃ£â€šâ€™Ã¦ÂÂ¢Ã£Ââ€”Ã£ÂÂ¦Ã£Ââ€Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬â€š' },
      { title: 'Ã©ÂÂ¢Ã¦ÂÂ¥Ã§Â·Â´Ã§Â¿â€™Ã£â€šÂ³Ã£Æ’Â¼Ã£Æ’Â', desc: 'Ã§Å¸Â­Ã£Ââ€Ã¦Â¨Â¡Ã¦â€œÂ¬Ã©ÂÂ¢Ã¦ÂÂ¥Ã£â€šâ€™Ã£Ââ€”Ã£ÂÂ¦Ã§â€ºÂ¸Ã¤Âºâ€™Ã£Æ’â€¢Ã£â€šÂ£Ã£Æ’Â¼Ã£Æ’â€°Ã£Æ’ÂÃ£Æ’Æ’Ã£â€šÂ¯Ã£ÂÂ§Ã£ÂÂÃ£â€šâ€¹Ã¤ÂºÂºÃ¥â€¹Å¸Ã©â€ºâ€ Ã£â‚¬â€š' },
    ],
    ko: [
      { title: 'Ã¬Æ’ÂÃ¬Æ’Â Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†', desc: 'Ã¬Â»Â¤Ã­â€Â¼ Ã«Â§Ë†Ã¬â€¹Å“Ã«Â©Â´Ã¬â€Å“ Ã¬â€”â€°Ã«Å¡Â±Ã­â€¢Å“ Ã¬â€¢â€Ã¬ÂÂ´Ã«â€â€Ã¬â€“Â´Ã«Â¥Â¼ Ã­â€¢Â¨ÃªÂ»Ëœ Ã«â€šËœÃ«Ë†Å’ Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†Ã«Â¥Â¼ Ã¬Â°Â¾ÃªÂ³Â  Ã¬ÂË†Ã¬â€“Â´Ã¬Å¡â€.' },
      { title: 'Ã¬ÂÂÃ¬Â¡Â´ÃªÂ°Â Ã«Â¶â‚¬Ã¬Å Â¤Ã­â€Â° Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†', desc: 'Ã¬â€Å“Ã«Â¡Å“ Ã¬Ââ€˜Ã¬â€ºÂÃ­â€¢ËœÃªÂ³Â  Ã¬ÂÂÃ¬â€¹Â ÃªÂ°ÂÃ¬Ââ€ Ã¬ËœÂ¬Ã«Â Â¤Ã¬Â¤â€ Ã¬ÂÂ¬Ã«Â¯Â¸Ã¬ÂË†Ã«Å â€ Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†Ã«Â¥Â¼ Ã¬Â°Â¾Ã¬Å ÂµÃ«â€¹Ë†Ã«â€¹Â¤ ÄŸÅ¸Ëœâ€' },
      { title: 'Ã«Ââ„¢ÃªÂ¸Â°Ã«Â¶â‚¬Ã¬â€”Â¬ Ã«Â²â€Ã«â€â€', desc: 'Ã«Â¯Â¸Ã«Â¤â€Ã«â€˜â€ Ã¬ÂÂ¼Ã¬Ââ€ Ã­â€¢Â¨ÃªÂ»Ëœ Ã¬â€¹Å“Ã¬Ââ€˜Ã­â€¢ËœÃªÂ³Â  Ã¬â€Å“Ã«Â¡Å“ Ã«Â°â‚¬Ã¬â€“Â´Ã¬Â¤â€ Ã¬Â¹Å“ÃªÂµÂ¬Ã«Â¥Â¼ Ã¬Â°Â¾ÃªÂ³Â  Ã¬ÂË†Ã¬â€“Â´Ã¬Å¡â€.' },
      { title: 'Ã¬â€“Â¸Ã¬â€“Â´ Ã¬â€”Â°Ã¬Å Âµ Ã«Â²â€Ã«â€â€', desc: 'ÃªÂ°â‚¬Ã«Â²Â¼Ã¬Å¡Â´ Ã«Å’â‚¬Ã­â„¢â€Ã«Â¡Å“ Ã¬â€“Â¸Ã¬â€“Â´ Ã¬â€”Â°Ã¬Å Âµ ÃªÂ°â„¢Ã¬ÂÂ´ Ã­â€¢ËœÃ¬â€¹Â¤ Ã«Â¶â€ Ã¬ÂË†Ã«â€šËœÃ¬Å¡â€?' },
      { title: 'Ã¬Â·Â¨Ã«Â¯Â¸ ÃªÂ³ÂµÃ¬Å“Â  Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†', desc: 'Ã¬Æ’Ë†Ã«Â¡Å“Ã¬Å¡Â´ Ã¬Â·Â¨Ã«Â¯Â¸Ã«Â¥Â¼ Ã­â€¢Â¨ÃªÂ»Ëœ Ã­Æ’ÂÃ­â€”ËœÃ­â€¢Â  ÃªÂ¸ÂÃ¬Â â€¢Ã¬Â ÂÃ¬ÂÂ¸ Ã¬Â¹Å“ÃªÂµÂ¬Ã«Â¥Â¼ Ã¬Â°Â¾Ã¬Å ÂµÃ«â€¹Ë†Ã«â€¹Â¤.' },
      { title: 'Ã«Â©Â´Ã¬Â â€˜ Ã¬â€”Â°Ã¬Å Âµ Ã¬Â½â€Ã¬Â¹Ëœ', desc: 'Ã¬Â§Â§Ã¬Ââ‚¬ Ã«ÂªÂ¨Ã¬ÂËœ Ã«Â©Â´Ã¬Â â€˜ Ã­â€ºâ€ Ã¬â€Å“Ã«Â¡Å“ Ã­â€Â¼Ã«â€œÅ“Ã«Â°Â±Ã­â€¢Â  Ã­Å’Å’Ã­Å Â¸Ã«â€Ë†Ã«Â¥Â¼ Ã¬Â°Â¾Ã¬Å ÂµÃ«â€¹Ë†Ã«â€¹Â¤.' },
    ],
    pt: [
      { title: 'Parceiro de devaneios', desc: 'Procuro alguem para imaginar ideias malucas tomando um cafe.' },
      { title: 'Parceiro de ego boost', desc: 'Procuro um parceiro divertido para nos motivarmos e aumentar a confianca ÄŸÅ¸Ëœâ€' },
      { title: 'Buddy de motivacao', desc: 'Preciso de alguem para comecar tarefas adiadas junto comigo.' },
      { title: 'Buddy de idiomas', desc: 'Alguem para praticar idiomas em conversas leves?' },
      { title: 'Parceiro de hobbies', desc: 'Procuro uma pessoa positiva para explorar novos hobbies.' },
      { title: 'Coach de entrevista', desc: 'Procuro alguem para um mini mock interview com feedback mutuo.' },
    ],
    it: [
      { title: 'Compagno di sogni', desc: 'Cerco qualcuno con cui immaginare idee folli davanti a un caffe.' },
      { title: 'Partner ego boost', desc: 'Cerco un partner divertente per motivarci e aumentare la fiducia ÄŸÅ¸Ëœâ€' },
      { title: 'Buddy motivazione', desc: 'Mi serve qualcuno per iniziare insieme i compiti rimandati.' },
      { title: 'Buddy pratica lingua', desc: 'Qualcuno per fare pratica di lingua con conversazioni leggere?' },
      { title: 'Compagno di hobby', desc: 'Cerco una persona positiva per esplorare nuovi hobby.' },
      { title: 'Coach colloquio', desc: 'Cerco qualcuno per un mini colloquio di prova con feedback reciproco.' },
    ],
    ar: [
      { title: 'Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã˜Â£Ã˜Â­Ã™â€Ã˜Â§Ã™â€¦', desc: 'Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â®Ã˜Âµ Ã™â€ Ã˜ÂªÃ˜Â¨Ã˜Â§Ã˜Â¯Ã™â€ Ã™â€¦Ã˜Â¹Ã™â€¡ Ã˜Â£Ã™ÂÃ™Æ’Ã˜Â§Ã˜Â±Ã˜Â§ Ã˜Â¬Ã˜Â±Ã™Å Ã˜Â¦Ã˜Â© Ã˜Â¹Ã™â€Ã™â€° Ã™ÂÃ™â€ Ã˜Â¬Ã˜Â§Ã™â€  Ã™â€šÃ™â€¡Ã™Ë†Ã˜Â©.' },
      { title: 'Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã˜ÂªÃ˜Â¹Ã˜Â²Ã™Å Ã˜Â² Ã˜Â§Ã™â€Ã˜Â«Ã™â€šÃ˜Â©', desc: 'Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã™â€¦Ã™â€¦Ã˜ÂªÃ˜Â¹ Ã™â€Ã™â€ Ã˜Â­Ã™ÂÃ˜Â² Ã˜Â¨Ã˜Â¹Ã˜Â¶Ã™â€ Ã˜Â§ Ã™Ë†Ã™â€ Ã˜Â±Ã™ÂÃ˜Â¹ Ã˜Â§Ã™â€Ã˜Â«Ã™â€šÃ˜Â© Ã˜Â¨Ã˜Â§Ã™â€Ã™â€ Ã™ÂÃ˜Â³ ÄŸÅ¸Ëœâ€' },
      { title: 'Ã˜Â±Ã™ÂÃ™Å Ã™â€š Ã˜ÂªÃ˜Â­Ã™ÂÃ™Å Ã˜Â²', desc: 'Ã˜Â£Ã˜Â­Ã˜ÂªÃ˜Â§Ã˜Â¬ Ã˜Â´Ã˜Â®Ã˜ÂµÃ˜Â§ Ã™â€ Ã˜Â¨Ã˜Â¯Ã˜Â£ Ã™â€¦Ã˜Â¹Ã™â€¡ Ã˜Â§Ã™â€Ã™â€¦Ã™â€¡Ã˜Â§Ã™â€¦ Ã˜Â§Ã™â€Ã™â€¦Ã˜Â¤Ã˜Â¬Ã™â€Ã˜Â© Ã™Ë†Ã™â€ Ã˜Â¯Ã˜Â¹Ã™â€¦ Ã˜Â¨Ã˜Â¹Ã˜Â¶Ã™â€ Ã˜Â§.' },
      { title: 'Ã˜Â±Ã™ÂÃ™Å Ã™â€š Ã™â€¦Ã™â€¦Ã˜Â§Ã˜Â±Ã˜Â³Ã˜Â© Ã™â€Ã˜ÂºÃ˜Â©', desc: 'Ã™â€¡Ã™â€ Ã™Å Ã™Ë†Ã˜Â¬Ã˜Â¯ Ã™â€¦Ã™â€  Ã™Å Ã˜Â±Ã™Å Ã˜Â¯ Ã™â€¦Ã™â€¦Ã˜Â§Ã˜Â±Ã˜Â³Ã˜Â© Ã˜Â§Ã™â€Ã™â€Ã˜ÂºÃ˜Â© Ã™ÂÃ™Å  Ã˜Â¯Ã˜Â±Ã˜Â¯Ã˜Â´Ã˜Â© Ã˜Â®Ã™ÂÃ™Å Ã™ÂÃ˜Â©Ã˜Å¸' },
      { title: 'Ã˜Â´Ã˜Â±Ã™Å Ã™Æ’ Ã™â€¡Ã™Ë†Ã˜Â§Ã™Å Ã˜Â§Ã˜Âª', desc: 'Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â®Ã˜Âµ Ã˜Â¥Ã™Å Ã˜Â¬Ã˜Â§Ã˜Â¨Ã™Å  Ã™â€Ã˜ÂªÃ˜Â¬Ã˜Â±Ã˜Â¨Ã˜Â© Ã™â€¡Ã™Ë†Ã˜Â§Ã™Å Ã˜Â§Ã˜Âª Ã˜Â¬Ã˜Â¯Ã™Å Ã˜Â¯Ã˜Â©.' },
      { title: 'Ã™â€¦Ã˜Â¯Ã˜Â±Ã˜Â¨ Ã™â€¦Ã™â€šÃ˜Â§Ã˜Â¨Ã™â€Ã˜Â©', desc: 'Ã˜Â£Ã˜Â¨Ã˜Â­Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â´Ã˜Â®Ã˜Âµ Ã™â€Ã˜Â¹Ã™â€¦Ã™â€ Ã™â€¦Ã™â€šÃ˜Â§Ã˜Â¨Ã™â€Ã˜Â© Ã˜ÂªÃ˜Â¬Ã˜Â±Ã™Å Ã˜Â¨Ã™Å Ã˜Â© Ã™â€šÃ˜ÂµÃ™Å Ã˜Â±Ã˜Â© Ã™â€¦Ã˜Â¹ Ã˜ÂªÃ˜Â¨Ã˜Â§Ã˜Â¯Ã™â€ Ã˜Â§Ã™â€Ã™â€¦Ã™â€Ã˜Â§Ã˜Â­Ã˜Â¸Ã˜Â§Ã˜Âª.' },
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Bot comment on social post Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function appendCommentEmojiFlavor(baseText, seed) {
  const clean = String(baseText || '').trim();
  if (!clean) return clean;

  const withEmoji = (hashSeed(`${seed}-emoji`) % 100) < 74;
  if (!withEmoji) return clean;

  const emojiPool = ['Ã¢ÂÂ¤Ã¯Â¸Â', 'ÄŸÅ¸â€Â¥', 'ÄŸÅ¸â€˜Â', 'ÄŸÅ¸â„¢Å’', 'Ã¢Å“Â¨', 'ÄŸÅ¸â€™Âª', 'ÄŸÅ¸Â¤Â', 'ÄŸÅ¸ËœÅ '];
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
        'Harika konu secimi, cok eglenceli gorunuyor! ÄŸÅ¸Ëœâ€',
        'Bu ilan dikkatimi cekti, detaylari konusalim mi?',
        `${pn ? pn + ', bu ' : 'Bu '}fikir gercekten hosuma gitti!`,
        'Ben de katilmak isterim, cok keyifli duruyor ÄŸÅ¸â„¢Å’',
      ],
      en: [
        'Great topic choice, this looks fun! ÄŸÅ¸Ëœâ€',
        'This listing caught my attention, shall we discuss details?',
        `${pn ? pn + ', this ' : 'This '}idea is really interesting!`,
        'I would love to join, sounds awesome ÄŸÅ¸â„¢Å’',
      ],
      ru: [
        'ÄÂÃ‘â€šÄÂ»ÄÂ¸Ã‘â€¡ÄÂ½ÄÂ°Ã‘Â Ã‘â€šÄÂµÄÂ¼ÄÂ°, ÄÂ²Ã‘â€¹ÄÂ³ÄÂ»Ã‘ÂÄÂ´ÄÂ¸Ã‘â€š ÄÂ¾Ã‘â€¡ÄÂµÄÂ½Ã‘Å’ ÄÂ¸ÄÂ½Ã‘â€šÄÂµÃ‘â‚¬ÄÂµÃ‘ÂÄÂ½ÄÂ¾! ÄŸÅ¸Ëœâ€',
        'ÄÂ­Ã‘â€šÄÂ¾ ÄÂ¾ÄÂ±Ã‘Å Ã‘ÂÄÂ²ÄÂ»ÄÂµÄÂ½ÄÂ¸ÄÂµ ÄÂ¿Ã‘â‚¬ÄÂ¸ÄÂ²ÄÂ»ÄÂµÄÂºÄÂ»ÄÂ¾ ÄÂ¼ÄÂ¾ÄÂµ ÄÂ²ÄÂ½ÄÂ¸ÄÂ¼ÄÂ°ÄÂ½ÄÂ¸ÄÂµ, ÄÂ¾ÄÂ±Ã‘ÂÃ‘Æ’ÄÂ´ÄÂ¸ÄÂ¼ ÄÂ´ÄÂµÃ‘â€šÄÂ°ÄÂ»ÄÂ¸?',
        `${pn ? pn + ', Ã‘ÂÃ‘â€šÄÂ° ' : 'ÄÂ­Ã‘â€šÄÂ° '}ÄÂ¸ÄÂ´ÄÂµÃ‘Â ÄÂ¼ÄÂ½ÄÂµ ÄÂ¾Ã‘â€¡ÄÂµÄÂ½Ã‘Å’ ÄÂ¿ÄÂ¾ÄÂ½Ã‘â‚¬ÄÂ°ÄÂ²ÄÂ¸ÄÂ»ÄÂ°Ã‘ÂÃ‘Å’!`,
        'ÄÂ¯ ÄÂ±Ã‘â€¹ Ã‘Â Ã‘Æ’ÄÂ´ÄÂ¾ÄÂ²ÄÂ¾ÄÂ»Ã‘Å’Ã‘ÂÃ‘â€šÄÂ²ÄÂ¸ÄÂµÄÂ¼ ÄÂ¿Ã‘â‚¬ÄÂ¸Ã‘ÂÄÂ¾ÄÂµÄÂ´ÄÂ¸ÄÂ½ÄÂ¸ÄÂ»Ã‘ÂÃ‘Â ÄŸÅ¸â„¢Å’',
      ],
      de: [
        'Tolles Thema, sieht richtig spannend aus! ÄŸÅ¸Ëœâ€',
        'Diese Anzeige hat meine Aufmerksamkeit geweckt, Details?',
        `${pn ? pn + ', diese ' : 'Diese '}Idee finde ich super!`,
        'Ich waere gern dabei ÄŸÅ¸â„¢Å’',
      ],
      fr: [
        'Tres bon theme, ca a l air sympa ! ÄŸÅ¸Ëœâ€',
        'Cette annonce a attire mon attention, on en parle ?',
        `${pn ? pn + ', cette ' : 'Cette '}idee me plait beaucoup !`,
        'Je veux bien participer ÄŸÅ¸â„¢Å’',
      ],
      es: [
        'Gran tema, se ve muy divertido! ÄŸÅ¸Ëœâ€',
        'Este anuncio me llamo la atencion, vemos detalles?',
        `${pn ? pn + ', esta ' : 'Esta '}idea me encanto!`,
        'Me gustaria unirme ÄŸÅ¸â„¢Å’',
      ],
      ja: [
        'Ã£Ââ€Ã£Ââ€Ã£Æ’â€ Ã£Æ’Â¼Ã£Æ’ÂÃ£ÂÂ§Ã£Ââ„¢Ã£ÂÂ­Ã£â‚¬ÂÃ£ÂÂ¨Ã£ÂÂ¦Ã£â€šâ€šÃ©ÂÂ¢Ã§â„¢Â½Ã£ÂÂÃ£Ââ€ Ã£ÂÂ§Ã£Ââ„¢Ã¯Â¼Â ÄŸÅ¸Ëœâ€',
        'Ã£Ââ€œÃ£ÂÂ®Ã¥â€¹Å¸Ã©â€ºâ€ Ã£ÂÅ’Ã¦Â°â€”Ã£ÂÂ«Ã£ÂÂªÃ£â€šÅ Ã£ÂÂ¾Ã£Ââ€”Ã£ÂÅ¸Ã£â‚¬â€šÃ¨Â©Â³Ã§Â´Â°Ã£â€šâ€™Ã¨Â©Â±Ã£Ââ€”Ã£ÂÂ¾Ã£Ââ€ºÃ£â€šâ€œÃ£Ââ€¹Ã¯Â¼Å¸',
        `${pn ? pn + 'Ã£Ââ€¢Ã£â€šâ€œÃ£â‚¬ÂÃ£Ââ€œÃ£ÂÂ®' : 'Ã£Ââ€œÃ£ÂÂ®'}Ã£â€šÂ¢Ã£â€šÂ¤Ã£Æ’â€¡Ã£â€šÂ¢Ã£Ââ„¢Ã£Ââ€Ã£ÂÂÃ£Ââ€Ã£Ââ€Ã£ÂÂ§Ã£Ââ„¢Ã¯Â¼Â`,
        'Ã£ÂÅ“Ã£ÂÂ²Ã¥Ââ€šÃ¥Å Â Ã£Ââ€”Ã£ÂÅ¸Ã£Ââ€Ã£ÂÂ§Ã£Ââ„¢ ÄŸÅ¸â„¢Å’',
      ],
      ko: [
        'Ã¬Â£Â¼Ã¬Â Å“ Ã¬Â â€¢Ã«Â§Â Ã¬Â¢â€¹Ã¬â€¢â€Ã¬Å¡â€, Ã¬ÂÂ¬Ã«Â¯Â¸Ã¬ÂË†Ã¬â€“Â´ Ã«Â³Â´Ã¬â€”Â¬Ã¬Å¡â€! ÄŸÅ¸Ëœâ€',
        'Ã¬ÂÂ´ Ã«ÂªÂ¨Ã¬Â§â€˜ Ã«Ë†Ë†Ã¬â€”Â Ã«Ââ€Ã«â€Â¤Ã¬Å¡â€, Ã¬ÂÂÃ¬â€Â¸Ã­ÂË† Ã¬ÂÂ´Ã¬â€¢Â¼ÃªÂ¸Â°Ã­â€¢Â´Ã¬Å¡â€?',
        `${pn ? pn + 'Ã«â€¹Ëœ, Ã¬ÂÂ´ ' : 'Ã¬ÂÂ´ '}Ã¬â€¢â€Ã¬ÂÂ´Ã«â€â€Ã¬â€“Â´ Ã¬Â â€¢Ã«Â§Â Ã¬Â¢â€¹Ã¬â€¢â€Ã¬Å¡â€!`,
        'Ã¬Â â‚¬Ã«Ââ€ Ã¬Â°Â¸Ã¬â€”Â¬Ã­â€¢ËœÃªÂ³Â  Ã¬â€¹Â¶Ã¬â€“Â´Ã¬Å¡â€ ÄŸÅ¸â„¢Å’',
      ],
      pt: [
        'Otimo tema, parece super divertido! ÄŸÅ¸Ëœâ€',
        'Este anuncio chamou minha atencao, vamos falar dos detalhes?',
        `${pn ? pn + ', essa ' : 'Essa '}ideia me agradou muito!`,
        'Quero participar tambem ÄŸÅ¸â„¢Å’',
      ],
      it: [
        'Ottimo tema, sembra davvero divertente! ÄŸÅ¸Ëœâ€',
        'Questo annuncio ha attirato la mia attenzione, dettagli?',
        `${pn ? pn + ', questa ' : 'Questa '}idea mi piace molto!`,
        'Mi piacerebbe partecipare ÄŸÅ¸â„¢Å’',
      ],
      ar: [
        'Ã™ÂÃ™Æ’Ã˜Â±Ã˜Â© Ã˜Â¬Ã™â€¦Ã™Å Ã™â€Ã˜Â© Ã˜Â¬Ã˜Â¯Ã˜Â§ Ã™Ë†Ã˜ÂªÃ˜Â¨Ã˜Â¯Ã™Ë† Ã™â€¦Ã™â€¦Ã˜ÂªÃ˜Â¹Ã˜Â©! ÄŸÅ¸Ëœâ€',
        'Ã™â€¡Ã˜Â°Ã˜Â§ Ã˜Â§Ã™â€Ã˜Â¥Ã˜Â¹Ã™â€Ã˜Â§Ã™â€  Ã™â€Ã™ÂÃ˜Âª Ã˜Â§Ã™â€ Ã˜ÂªÃ˜Â¨Ã˜Â§Ã™â€¡Ã™Å Ã˜Å’ Ã™â€¡Ã™â€ Ã™â€ Ã˜ÂªÃ˜Â­Ã˜Â¯Ã˜Â« Ã˜Â¹Ã™â€  Ã˜Â§Ã™â€Ã˜ÂªÃ™ÂÃ˜Â§Ã˜ÂµÃ™Å Ã™â€Ã˜Å¸',
        `${pn ? pn + 'Ã˜Å’ Ã™â€¡Ã˜Â°Ã™â€¡ ' : 'Ã™â€¡Ã˜Â°Ã™â€¡ '}Ã˜Â§Ã™â€Ã™ÂÃ™Æ’Ã˜Â±Ã˜Â© Ã˜Â£Ã˜Â¹Ã˜Â¬Ã˜Â¨Ã˜ÂªÃ™â€ Ã™Å  Ã˜Â¬Ã˜Â¯Ã˜Â§!`,
        'Ã˜Â£Ã˜Â±Ã˜ÂºÃ˜Â¨ Ã˜Â¨Ã˜Â§Ã™â€Ã™â€¦Ã˜Â´Ã˜Â§Ã˜Â±Ã™Æ’Ã˜Â© Ã˜Â£Ã™Å Ã˜Â¶Ã˜Â§ ÄŸÅ¸â„¢Å’',
      ],
    };
    const pool = genericTemplates[language] || genericTemplates.en;
    const base = pool[hashSeed(`${seedBase}-generic-body`) % pool.length];
    return appendCommentEmojiFlavor(base, `${seedBase}-generic-flavor`);
  }

  const templates = {
    tr: [
      `Harika paylaÃ…Å¸Ã„Â±m! ${s} tutkunlarÃ„Â±na selamlar ÄŸÅ¸â„¢Å’`,
      `Ben de ${s} yapÃ„Â±yorum, seninle antrenman yapmayÃ„Â± isterim!`,
      `${pn ? pn + ', bu ' : 'Bu '}paylaÃ…Å¸Ã„Â±m ilgimi ÃƒÂ§ekti, devam et!`,
      `${s} iÃƒÂ§in ÃƒÂ§ok gÃƒÂ¼zel bir motivasyon, teÃ…Å¸ekkÃƒÂ¼rler!`,
      `SÃƒÂ¼per! Ben de aynÃ„Â± his iÃƒÂ§indeyim, ${s} harika ÄŸÅ¸â€™Âª`,
      `${pn ? pn + ' ' : ''}ne zaman ve nerede? KatÃ„Â±lmak isterim!`,
      `Bence de ${s} en iyi spor ÄŸÅ¸Ââ€ `,
      `Devam et, bÃƒÂ¶yle paylaÃ…Å¸Ã„Â±mlar ÃƒÂ§ok motive edici!`,
    ],
    en: [
      `Great post! Shoutout to all ${s} fans ÄŸÅ¸â„¢Å’`,
      `I do ${s} too! Would love to train with you.`,
      `${pn ? pn + ', this ' : 'This '}post caught my eye. Keep it up!`,
      `Such great motivation for ${s}, thanks!`,
      `Awesome! Feeling the same way, ${s} is amazing ÄŸÅ¸â€™Âª`,
      `${pn ? pn + ' ' : ''}when and where? I'd love to join!`,
      `I agree, ${s} is the best sport ÄŸÅ¸Ââ€ `,
      `Keep going, posts like this are so motivating!`,
    ],
    ru: [
      `ÄÂÃ‘â€šÄÂ»ÄÂ¸Ã‘â€¡ÄÂ½Ã‘â€¹ÄÂ¹ ÄÂ¿ÄÂ¾Ã‘ÂÃ‘â€š! ÄÅ¸Ã‘â‚¬ÄÂ¸ÄÂ²ÄÂµÃ‘â€š ÄÂ²Ã‘ÂÄÂµÄÂ¼ ÄÂ»Ã‘ÂÄÂ±ÄÂ¸Ã‘â€šÄÂµÄÂ»Ã‘ÂÄÂ¼ ${s} ÄŸÅ¸â„¢Å’`,
      `ÄÂ¯ Ã‘â€šÄÂ¾ÄÂ¶ÄÂµ ÄÂ·ÄÂ°ÄÂ½ÄÂ¸ÄÂ¼ÄÂ°Ã‘ÂÃ‘ÂÃ‘Å’ ${s}! ÄÂ¥ÄÂ¾Ã‘â€šÄÂµÄÂ» ÄÂ±Ã‘â€¹ ÄÂ¿ÄÂ¾Ã‘â€šÃ‘â‚¬ÄÂµÄÂ½ÄÂ¸Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂ°Ã‘â€šÃ‘Å’Ã‘ÂÃ‘Â ÄÂ²ÄÂ¼ÄÂµÃ‘ÂÃ‘â€šÄÂµ.`,
      `${pn ? pn + ', Ã‘ÂÃ‘â€šÄÂ¾Ã‘â€š ' : 'ÄÂ­Ã‘â€šÄÂ¾Ã‘â€š '}ÄÂ¿ÄÂ¾Ã‘ÂÃ‘â€š ÄÂ¼ÄÂµÄÂ½Ã‘Â ÄÂ·ÄÂ°Ã‘â€ ÄÂµÄÂ¿ÄÂ¸ÄÂ». ÄÅ¸Ã‘â‚¬ÄÂ¾ÄÂ´ÄÂ¾ÄÂ»ÄÂ¶ÄÂ°ÄÂ¹!`,
      `ÄÂ¢ÄÂ°ÄÂºÄÂ°Ã‘Â Ã‘â€¦ÄÂ¾Ã‘â‚¬ÄÂ¾Ã‘Ë†ÄÂ°Ã‘Â ÄÂ¼ÄÂ¾Ã‘â€šÄÂ¸ÄÂ²ÄÂ°Ã‘â€ ÄÂ¸Ã‘Â ÄÂ´ÄÂ»Ã‘Â ${s}, Ã‘ÂÄÂ¿ÄÂ°Ã‘ÂÄÂ¸ÄÂ±ÄÂ¾!`,
      `ÄÂ¡Ã‘Æ’ÄÂ¿ÄÂµÃ‘â‚¬! ÄÅ¸ÄÂ¾ÄÂ»ÄÂ½ÄÂ¾Ã‘ÂÃ‘â€šÃ‘Å’Ã‘Â Ã‘ÂÄÂ¾ÄÂ³ÄÂ»ÄÂ°Ã‘ÂÄÂµÄÂ½, ${s} Ã¢â‚¬â€ Ã‘ÂÃ‘â€šÄÂ¾ ÄÂ·ÄÂ´ÄÂ¾Ã‘â‚¬ÄÂ¾ÄÂ²ÄÂ¾ ÄŸÅ¸â€™Âª`,
    ],
    de: [
      `Toller Beitrag! GrÃƒÂ¼ÃƒÅ¸e an alle ${s}-Fans ÄŸÅ¸â„¢Å’`,
      `Ich mache auch ${s}! WÃƒÂ¼rde gerne mit dir trainieren.`,
      `${pn ? pn + ', dieser ' : 'Dieser '}Beitrag hat mich angesprochen. Weiter so!`,
      `So eine tolle Motivation fÃƒÂ¼r ${s}, danke!`,
      `Super! FÃƒÂ¼hle genau dasselbe, ${s} ist groÃƒÅ¸artig ÄŸÅ¸â€™Âª`,
    ],
    fr: [
      `Super post ! Salut ÃƒÂ  tous les fans de ${s} ÄŸÅ¸â„¢Å’`,
      `Je fais aussi du ${s} ! J'aimerais m'entraÃƒÂ®ner avec toi.`,
      `${pn ? pn + ', ce ' : 'Ce '}post m'a accrochÃƒÂ©. Continue!`,
      `Quelle bonne motivation pour ${s}, merci!`,
      `Super ! Je ressens la mÃƒÂªme chose, ${s} c'est gÃƒÂ©nial ÄŸÅ¸â€™Âª`,
    ],
    es: [
      `Ã‚Â¡Gran publicaciÃƒÂ³n! Saludos a todos los fans de ${s} ÄŸÅ¸â„¢Å’`,
      `Ã‚Â¡Yo tambiÃƒÂ©n hago ${s}! Me encantarÃƒÂ­a entrenar contigo.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicaciÃƒÂ³n me llamÃƒÂ³ la atenciÃƒÂ³n. Ã‚Â¡Sigue asÃƒÂ­!`,
      `Ã‚Â¡QuÃƒÂ© buena motivaciÃƒÂ³n para ${s}, gracias!`,
      `Ã‚Â¡Genial! Siento lo mismo, ${s} es increÃƒÂ­ble ÄŸÅ¸â€™Âª`,
    ],
    ja: [
      `Ã§Â´Â Ã¦â„¢Â´Ã£â€šâ€°Ã£Ââ€”Ã£Ââ€Ã¦Å â€¢Ã§Â¨Â¿Ã¯Â¼Â${s}Ã£Æ’â€¢Ã£â€šÂ¡Ã£Æ’Â³Ã£ÂÂ®Ã£ÂÂ¿Ã£â€šâ€œÃ£ÂÂªÃ£ÂÂ«Ã£â€šË†Ã£â€šÂÃ£Ââ€”Ã£ÂÂ ÄŸÅ¸â„¢Å’`,
      `Ã§Â§ÂÃ£â€šâ€š${s}Ã£â€šâ€Ã£ÂÂ£Ã£ÂÂ¦Ã£ÂÂ¾Ã£Ââ„¢Ã¯Â¼ÂÃ¤Â¸â‚¬Ã§Â·â€™Ã£ÂÂ«Ã§Â·Â´Ã§Â¿â€™Ã£Ââ€”Ã£ÂÅ¸Ã£Ââ€Ã£ÂÂ§Ã£Ââ„¢Ã£â‚¬â€š`,
      `${pn ? pn + 'Ã£Ââ€¢Ã£â€šâ€œÃ£â‚¬ÂÃ£Ââ€œÃ£ÂÂ®' : 'Ã£Ââ€œÃ£ÂÂ®'}Ã¦Å â€¢Ã§Â¨Â¿Ã£ÂÅ’Ã¦Â°â€”Ã£ÂÂ«Ã£ÂÂªÃ£â€šÅ Ã£ÂÂ¾Ã£Ââ€”Ã£ÂÅ¸Ã£â‚¬â€šÃ§Â¶Å¡Ã£Ââ€˜Ã£ÂÂ¦Ã£ÂÂÃ£ÂÂ Ã£Ââ€¢Ã£Ââ€Ã¯Â¼Â`,
      `${s}Ã£ÂÂ®Ã£Æ’Â¢Ã£Æ’ÂÃ£Æ’â„¢Ã£Æ’Â¼Ã£â€šÂ·Ã£Æ’Â§Ã£Æ’Â³Ã£ÂÂ«Ã£ÂÂªÃ£â€šÅ Ã£ÂÂ¾Ã£Ââ„¢Ã£â‚¬ÂÃ£Ââ€šÃ£â€šÅ Ã£ÂÅ’Ã£ÂÂ¨Ã£Ââ€ Ã¯Â¼Â`,
      `Ã¦Å“â‚¬Ã©Â«ËœÃ¯Â¼ÂÃ¥ÂÅ’Ã£ÂËœÃ¦Â°â€”Ã¦Å’ÂÃ£ÂÂ¡Ã£ÂÂ§Ã£Ââ„¢Ã£â‚¬Â${s}Ã£ÂÂ¯Ã§Â´Â Ã¦â„¢Â´Ã£â€šâ€°Ã£Ââ€”Ã£Ââ€ ÄŸÅ¸â€™Âª`,
    ],
    ko: [
      `Ã¬Â¢â€¹Ã¬Ââ‚¬ ÃªÂ²Å’Ã¬â€¹Å“Ã«Â¬Â¼Ã¬ÂÂ´Ã¬â€”ÂÃ¬Å¡â€! ${s} Ã­Å’Â¬ Ã«ÂªÂ¨Ã«â€˜Â Ã­â„¢â€Ã¬ÂÂ´Ã­Å’â€¦ ÄŸÅ¸â„¢Å’`,
      `Ã¬Â â‚¬Ã«Ââ€ ${s} Ã­â€¢Â´Ã¬Å¡â€! ÃªÂ°â„¢Ã¬ÂÂ´ Ã­â€ºË†Ã«Â Â¨Ã­â€¢ËœÃªÂ³Â  Ã¬â€¹Â¶Ã¬â€“Â´Ã¬Å¡â€.`,
      `${pn ? pn + 'Ã«â€¹Ëœ, Ã¬ÂÂ´ ' : 'Ã¬ÂÂ´ '}ÃªÂ²Å’Ã¬â€¹Å“Ã«Â¬Â¼ Ã«Ë†Ë†Ã¬â€”Â Ã«Ââ€Ã¬â€”Ë†Ã¬â€“Â´Ã¬Å¡â€. ÃªÂ³â€Ã¬â€ Â Ã­â€¢Â´Ã¬Â£Â¼Ã¬â€Â¸Ã¬Å¡â€!`,
      `${s} Ã«Ââ„¢ÃªÂ¸Â°Ã«Â¶â‚¬Ã¬â€”Â¬ Ã«ÂËœÃ«â€Â¤Ã¬Å¡â€, ÃªÂ°ÂÃ¬â€šÂ¬Ã­â€¢Â´Ã¬Å¡â€!`,
      `Ã¬ÂµÅ“ÃªÂ³Â ! ÃªÂ°â„¢Ã¬Ââ‚¬ ÃªÂ¸Â°Ã«Â¶â€Ã¬ÂÂ´Ã¬â€”ÂÃ¬Å¡â€, ${s} Ã¬ÂµÅ“ÃªÂ³Â  ÄŸÅ¸â€™Âª`,
    ],
    pt: [
      `Ãƒâ€œtima postagem! SaudaÃƒÂ§ÃƒÂµes a todos os fÃƒÂ£s de ${s} ÄŸÅ¸â„¢Å’`,
      `Eu tambÃƒÂ©m faÃƒÂ§o ${s}! Adoraria treinar com vocÃƒÂª.`,
      `${pn ? pn + ', esta ' : 'Esta '}publicaÃƒÂ§ÃƒÂ£o me chamou atenÃƒÂ§ÃƒÂ£o. Continue assim!`,
      `Que boa motivaÃƒÂ§ÃƒÂ£o para ${s}, obrigado!`,
      `IncrÃƒÂ­vel! Sinto o mesmo, ${s} ÃƒÂ© fantÃƒÂ¡stico ÄŸÅ¸â€™Âª`,
    ],
    it: [
      `Ottimo post! Saluti a tutti i fan di ${s} ÄŸÅ¸â„¢Å’`,
      `Faccio anch'io ${s}! Mi piacerebbe allenarmi con te.`,
      `${pn ? pn + ', questo ' : 'Questo '}post mi ha colpito. Continua cosÃƒÂ¬!`,
      `Che bella motivazione per ${s}, grazie!`,
      `Super! Provo la stessa cosa, ${s} ÃƒÂ¨ fantastico ÄŸÅ¸â€™Âª`,
    ],
    ar: [
      `Ã™â€¦Ã™â€ Ã˜Â´Ã™Ë†Ã˜Â± Ã˜Â±Ã˜Â§Ã˜Â¦Ã˜Â¹! Ã˜ÂªÃ˜Â­Ã™Å Ã˜Â© Ã™â€Ã˜Â¬Ã™â€¦Ã™Å Ã˜Â¹ Ã™â€¦Ã˜Â­Ã˜Â¨Ã™Å  ${s} ÄŸÅ¸â„¢Å’`,
      `Ã˜Â£Ã™â€ Ã˜Â§ Ã˜Â£Ã™Å Ã˜Â¶Ã˜Â§Ã™â€¹ Ã˜Â£Ã™â€¦Ã˜Â§Ã˜Â±Ã˜Â³ ${s}! Ã˜Â£Ã™Ë†Ã˜Â¯ Ã˜Â§Ã™â€Ã˜ÂªÃ˜Â¯Ã˜Â±Ã˜Â¨ Ã™â€¦Ã˜Â¹Ã™Æ’.`,
      `${pn ? pn + 'Ã˜Å’ Ã™â€¡Ã˜Â°Ã˜Â§ ' : 'Ã™â€¡Ã˜Â°Ã˜Â§ '}Ã˜Â§Ã™â€Ã™â€¦Ã™â€ Ã˜Â´Ã™Ë†Ã˜Â± Ã™â€Ã™ÂÃ˜Âª Ã˜Â§Ã™â€ Ã˜ÂªÃ˜Â¨Ã˜Â§Ã™â€¡Ã™Å . Ã˜Â§Ã˜Â³Ã˜ÂªÃ™â€¦Ã˜Â±!`,
      `Ã™â€¡Ã˜Â°Ã˜Â§ Ã˜ÂªÃ˜Â­Ã™ÂÃ™Å Ã˜Â² Ã˜Â±Ã˜Â§Ã˜Â¦Ã˜Â¹ Ã™â€Ã™â‚¬ ${s}Ã˜Å’ Ã˜Â´Ã™Æ’Ã˜Â±Ã˜Â§Ã™â€¹!`,
      `Ã˜Â±Ã˜Â§Ã˜Â¦Ã˜Â¹! Ã˜Â£Ã˜Â´Ã˜Â¹Ã˜Â± Ã˜Â¨Ã™â€ Ã™ÂÃ˜Â³ Ã˜Â§Ã™â€Ã˜Â´Ã™Å Ã˜Â¡Ã˜Å’ ${s} Ã™â€¦Ã˜Â°Ã™â€¡Ã™â€ ÄŸÅ¸â€™Âª`,
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
