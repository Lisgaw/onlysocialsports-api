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

// ─── Deterministic avatar URL ──────────────────────────────────────────────────
function buildBotAvatarUrl({ gender, seed }) {
  const isFemale = (gender || '').toUpperCase() === 'FEMALE';
  const group = isFemale ? 'women' : 'men';
  const avatarIndex = hashSeed(seed) % 100;
  return `https://randomuser.me/api/portraits/${group}/${avatarIndex}.jpg`;
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

// ─── Localized bio generation ──────────────────────────────────────────────────
function generateBotBio({ locale, sportName, sportId, cityName, persona }) {
  const s = translateSportName(sportId, locale, sportName || 'spor');
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

// ─── Sport name translations by sport ID ──────────────────────────────────────
const SPORT_NAME_TRANSLATIONS = {
  yoga:              { tr: 'Yoga',            en: 'Yoga',            de: 'Yoga',          fr: 'Yoga',          es: 'Yoga',          ru: 'Йога',           ja: 'ヨガ',           ko: '요가',     pt: 'Yoga',          it: 'Yoga',          ar: 'اليوغا' },
  pilates:           { tr: 'Pilates',         en: 'Pilates',         de: 'Pilates',       fr: 'Pilates',       es: 'Pilates',       ru: 'Пилатес',        ja: 'ピラティス',      ko: '필라테스', pt: 'Pilates',       it: 'Pilates',       ar: 'البيلاتس' },
  running:           { tr: 'Koşu',            en: 'Running',         de: 'Laufen',        fr: 'Course',        es: 'Carrera',       ru: 'Бег',            ja: 'ランニング',      ko: '달리기',   pt: 'Corrida',       it: 'Corsa',         ar: 'الجري' },
  hiking:            { tr: 'Yürüyüş',         en: 'Hiking',          de: 'Wandern',       fr: 'Randonnée',     es: 'Senderismo',    ru: 'Пешие прогулки', ja: 'ハイキング',      ko: '하이킹',   pt: 'Caminhada',     it: 'Escursionismo', ar: 'المشي' },
  swimming:          { tr: 'Yüzme',           en: 'Swimming',        de: 'Schwimmen',     fr: 'Natation',      es: 'Natación',      ru: 'Плавание',       ja: '水泳',           ko: '수영',     pt: 'Natação',       it: 'Nuoto',         ar: 'السباحة' },
  cycling:           { tr: 'Bisiklet',        en: 'Cycling',         de: 'Radfahren',     fr: 'Cyclisme',      es: 'Ciclismo',      ru: 'Велоспорт',      ja: 'サイクリング',    ko: '사이클링',  pt: 'Ciclismo',      it: 'Ciclismo',      ar: 'ركوب الدراجات' },
  fitness:           { tr: 'Fitness',         en: 'Fitness',         de: 'Fitness',       fr: 'Fitness',       es: 'Fitness',       ru: 'Фитнес',         ja: 'フィットネス',    ko: '피트니스', pt: 'Fitness',       it: 'Fitness',       ar: 'اللياقة' },
  table_tennis:      { tr: 'Masa Tenisi',     en: 'Table Tennis',    de: 'Tischtennis',   fr: 'Tennis de Table', es: 'Tenis de Mesa', ru: 'Настольный теннис', ja: '卓球',      ko: '탁구',     pt: 'Tênis de Mesa', it: 'Ping-Pong',     ar: 'تنس الطاولة' },
  tennis:            { tr: 'Tenis',           en: 'Tennis',          de: 'Tennis',        fr: 'Tennis',        es: 'Tenis',         ru: 'Теннис',         ja: 'テニス',         ko: '테니스',   pt: 'Tênis',         it: 'Tennis',        ar: 'التنس' },
  badminton:         { tr: 'Badminton',       en: 'Badminton',       de: 'Badminton',     fr: 'Badminton',     es: 'Bádminton',     ru: 'Бадминтон',      ja: 'バドミントン',    ko: '배드민턴',  pt: 'Badminton',     it: 'Badminton',     ar: 'الريشة' },
  basketball:        { tr: 'Basketbol',       en: 'Basketball',      de: 'Basketball',    fr: 'Basketball',    es: 'Baloncesto',    ru: 'Баскетбол',      ja: 'バスケ',         ko: '농구',     pt: 'Basquete',      it: 'Basket',        ar: 'كرة السلة' },
  football:          { tr: 'Futbol',          en: 'Football',        de: 'Fußball',       fr: 'Football',      es: 'Fútbol',        ru: 'Футбол',         ja: 'サッカー',        ko: '축구',     pt: 'Futebol',       it: 'Calcio',        ar: 'كرة القدم' },
  volleyball:        { tr: 'Voleybol',        en: 'Volleyball',      de: 'Volleyball',    fr: 'Volleyball',    es: 'Voleibol',      ru: 'Волейбол',       ja: 'バレーボール',    ko: '배구',     pt: 'Vôlei',         it: 'Pallavolo',     ar: 'الكرة الطائرة' },
  padel:             { tr: 'Padel',           en: 'Padel',           de: 'Padel',         fr: 'Padel',         es: 'Pádel',         ru: 'Падел',          ja: 'パデル',         ko: '파델',     pt: 'Padel',         it: 'Padel',         ar: 'البادل' },
  martial_arts:      { tr: 'Dövüş Sanatları', en: 'Martial Arts',   de: 'Kampfsport',    fr: 'Arts martiaux', es: 'Artes marciales', ru: 'Боевые искусства', ja: '武道',      ko: '무술',     pt: 'Artes marciais', it: 'Arti marziali', ar: 'فنون القتال' },
  crossfit:          { tr: 'Crossfit',        en: 'CrossFit',        de: 'CrossFit',      fr: 'CrossFit',      es: 'CrossFit',      ru: 'Кроссфит',       ja: 'クロスフィット',  ko: '크로스핏',  pt: 'CrossFit',      it: 'CrossFit',      ar: 'كروس فيت' },
  dance:             { tr: 'Dans',            en: 'Dance',           de: 'Tanzen',        fr: 'Danse',         es: 'Baile',         ru: 'Танцы',          ja: 'ダンス',         ko: '댄스',     pt: 'Dança',         it: 'Danza',         ar: 'الرقص' },
  skating:           { tr: 'Paten',           en: 'Skating',         de: 'Schlittschuhlaufen', fr: 'Patinage', es: 'Patinaje',      ru: 'Катание на коньках', ja: 'スケート',   ko: '스케이팅',  pt: 'Patinação',     it: 'Pattinaggio',   ar: 'التزلج' },
  golf:              { tr: 'Golf',            en: 'Golf',            de: 'Golf',          fr: 'Golf',          es: 'Golf',          ru: 'Гольф',          ja: 'ゴルフ',         ko: '골프',     pt: 'Golfe',         it: 'Golf',          ar: 'الغولف' },
  surfing:           { tr: 'Sörf',            en: 'Surfing',         de: 'Surfen',        fr: 'Surf',          es: 'Surf',          ru: 'Серфинг',        ja: 'サーフィン',      ko: '서핑',     pt: 'Surf',          it: 'Surf',          ar: 'ركوب الأمواج' },
  archery:           { tr: 'Okçuluk',         en: 'Archery',         de: 'Bogenschießen', fr: 'Tir à l\'arc',  es: 'Tiro con arco', ru: 'Стрельба из лука', ja: 'アーチェリー',  ko: '양궁',     pt: 'Arco e flecha', it: 'Tiro con l\'arco', ar: 'الرماية' },
  pickleball:        { tr: 'Pickleball',      en: 'Pickleball',      de: 'Pickleball',    fr: 'Pickleball',    es: 'Pickleball',    ru: 'Пиклбол',        ja: 'ピックルボール',   ko: '피클볼',   pt: 'Pickleball',    it: 'Pickleball',    ar: 'بيكلبول' },
  sand_surfing:      { tr: 'Kum Sörfü',       en: 'Sand Surfing',    de: 'Sandsurfen',    fr: 'Surf sur sable', es: 'Surf en arena', ru: 'Сёрфинг по песку', ja: 'サンドサーフィン', ko: '모래 서핑', pt: 'Surfe na areia', it: 'Surf sulla sabbia', ar: 'التزلج على الرمال' },
  rugby:             { tr: 'Rugby',           en: 'Rugby',           de: 'Rugby',         fr: 'Rugby',         es: 'Rugby',         ru: 'Регби',          ja: 'ラグビー',        ko: '럭비',     pt: 'Rugby',         it: 'Rugby',         ar: 'الرغبي' },
  cricket:           { tr: 'Kriket',          en: 'Cricket',         de: 'Cricket',       fr: 'Cricket',       es: 'Críquet',       ru: 'Крикет',         ja: 'クリケット',      ko: '크리켓',   pt: 'Críquete',      it: 'Cricket',       ar: 'الكريكت' },
  handball:          { tr: 'Hentbol',         en: 'Handball',        de: 'Handball',      fr: 'Handball',      es: 'Balonmano',     ru: 'Гандбол',        ja: 'ハンドボール',    ko: '핸드볼',   pt: 'Handebol',      it: 'Pallamano',     ar: 'كرة اليد' },
  bowling:           { tr: 'Bowling',         en: 'Bowling',         de: 'Bowling',       fr: 'Bowling',       es: 'Boliche',       ru: 'Боулинг',        ja: 'ボーリング',      ko: '볼링',     pt: 'Boliche',       it: 'Bowling',       ar: 'البولينغ' },
  billiards:         { tr: 'Bilardo',         en: 'Billiards',       de: 'Billard',       fr: 'Billard',       es: 'Billar',        ru: 'Бильярд',        ja: 'ビリヤード',      ko: '당구',     pt: 'Bilhar',        it: 'Biliardo',      ar: 'البلياردو' },
  darts:             { tr: 'Dart',            en: 'Darts',           de: 'Darts',         fr: 'Fléchettes',    es: 'Dardos',        ru: 'Дартс',          ja: 'ダーツ',         ko: '다트',     pt: 'Dardos',        it: 'Freccette',     ar: 'الدارتس' },
  baseball:          { tr: 'Beyzbol',         en: 'Baseball',        de: 'Baseball',      fr: 'Baseball',      es: 'Béisbol',       ru: 'Бейсбол',        ja: '野球',           ko: '야구',     pt: 'Beisebol',      it: 'Baseball',      ar: 'البيسبول' },
  american_football: { tr: 'Amerikan Futbolu', en: 'American Football', de: 'American Football', fr: 'Football américain', es: 'Fútbol americano', ru: 'Американский футбол', ja: 'アメフト', ko: '미식축구', pt: 'Futebol americano', it: 'Football americano', ar: 'كرة القدم الأمريكية' },
  ice_hockey:        { tr: 'Buz Hokeyi',      en: 'Ice Hockey',      de: 'Eishockey',     fr: 'Hockey sur glace', es: 'Hockey sobre hielo', ru: 'Хоккей', ja: 'アイスホッケー', ko: '아이스 하키', pt: 'Hóquei no gelo', it: 'Hockey su ghiaccio', ar: 'هوكي الجليد' },
  skateboarding:     { tr: 'Kaykay',          en: 'Skateboarding',   de: 'Skateboarden',  fr: 'Skateboard',    es: 'Skateboard',    ru: 'Скейтбординг',   ja: 'スケートボード',  ko: '스케이트보드', pt: 'Skate',        it: 'Skateboard',    ar: 'التزلج على الألواح' },
  equestrian:        { tr: 'Binicilik',       en: 'Horse Riding',    de: 'Reiten',        fr: 'Équitation',    es: 'Equitación',    ru: 'Верховая езда',  ja: '乗馬',           ko: '승마',     pt: 'Hipismo',       it: 'Equitazione',   ar: 'ركوب الخيل' },
  fishing:           { tr: 'Balık Tutma',     en: 'Fishing',         de: 'Angeln',        fr: 'Pêche',         es: 'Pesca',         ru: 'Рыбалка',        ja: '釣り',           ko: '낚시',     pt: 'Pesca',         it: 'Pesca',         ar: 'الصيد' },
  paintball:         { tr: 'Paintball',       en: 'Paintball',       de: 'Paintball',     fr: 'Paintball',     es: 'Paintball',     ru: 'Пейнтбол',       ja: 'ペイントボール',  ko: '페인트볼',  pt: 'Paintball',     it: 'Paintball',     ar: 'البينتبول' },
  kabaddi:           { tr: 'Kabaddi',         en: 'Kabaddi',         de: 'Kabaddi',       fr: 'Kabaddi',       es: 'Kabaddi',       ru: 'Кабадди',        ja: 'カバディ',        ko: '카바디',   pt: 'Kabaddi',       it: 'Kabaddi',       ar: 'الكابادي' },
};

/**
 * Translate a sport name to a given locale.
 * Falls back to the provided rawName if no translation exists.
 */
function translateSportName(sportId, locale, rawName) {
  const map = SPORT_NAME_TRANSLATIONS[sportId];
  if (!map) return rawName || sportId;
  return map[locale] || map.en || rawName || sportId;
}

// ─── Listing description ───────────────────────────────────────────────────────
function generateListingDesc({ name, sport, sportId, locale, city, listingType }) {
  const s = translateSportName(sportId, locale, sport);
  const isRival = (listingType || '').toUpperCase() === 'RIVAL';
  const templates = {
    tr: isRival ? [
      `Bu hafta ${s} için rakip arıyorum. Kaybeden ısmarlıyor! 😄`,
      `${city ? city + "'da " : ''}${s} için ciddi bir rakip arıyorum.`,
      `${s} alanında kendimi geliştirmek istiyorum — beni yenebilir misin?`,
      `1v1 ${s} maçı için meydan okuyorum. Kabul ediyor musun?`,
    ] : [
      `${city ? city + " tarafında " : 'Bu hafta '}${s} için eşleşmek isteyen var mı?`,
      `${s} antrenmanlarına devam etmek istiyorum, düzenli bir partner ararım.`,
      `Seviyem ne olursa olsun, beraber ${s} yaparız. Yazın!`,
      `${s} için pozitif enerjili biri arıyorum. Detayları konuşalım.`,
      `Haftalık ${s} seansı için partner arıyorum. Ciddi teklifler bekliyorum.`,
    ],
    en: isRival ? [
      `Looking for a strong opponent for ${s}. May the best win! 🏆`,
      `Ready for a competitive ${s} match${city ? ' in ' + city : ''}. Who dares?`,
      `Challenge accepted? I'm looking for a worthy ${s} rival.`,
      `1v1 ${s} — let's see what you've got. Message me!`,
    ] : [
      `Searching for a reliable ${s} partner${city ? ' near ' + city : ' this week'}.`,
      `I enjoy structured ${s} sessions — looking for someone consistent.`,
      `All skill levels welcome. Let's enjoy a good ${s} session together.`,
      `${s} is better with the right partner. Are you in?`,
      `Looking to stay active with regular ${s} meetups. Drop me a message!`,
    ],
    ru: isRival ? [
      `Ищу сильного соперника по ${s}. Кто победит — узнаем на матче!`,
      `Готов к серьёзному матчу по ${s}${city ? ' в ' + city : ''}. Принимаете вызов?`,
      `1v1 по ${s} — проверим, кто сильнее. Пишите!`,
    ] : [
      `Ищу постоянного партнёра по ${s}${city ? ' в районе ' + city : ''}.`,
      `Занимаюсь ${s} регулярно, ищу надёжного партнёра для совместных тренировок.`,
      `Открыт к любому уровню — главное желание заниматься ${s}!`,
    ],
    de: isRival ? [
      `Suche einen starken Gegner für ${s}. Der Bessere gewinnt! 🏆`,
      `Bereit für ein ernstes ${s}-Match${city ? ' in ' + city : ''}. Wer traut sich?`,
      `1v1 ${s} — schauen wir mal, wer stärker ist. Schreib mir!`,
    ] : [
      `Suche einen zuverlässigen Partner für ${s}${city ? ' in ' + city : ''}.`,
      `Ich trainiere regelmäßig ${s} und suche jemanden zum gemeinsamen Üben.`,
      `Alle Level willkommen. Lasst uns ${s} zusammen genießen!`,
    ],
    fr: isRival ? [
      `Je cherche un adversaire de taille pour ${s}. Que le meilleur gagne ! 🏆`,
      `Prêt pour un match sérieux de ${s}${city ? ' à ' + city : ''}. Qui ose ?`,
      `1v1 ${s} — voyons qui est le plus fort. Écrivez-moi !`,
    ] : [
      `Je cherche un partenaire régulier pour ${s}${city ? ' vers ' + city : ''}.`,
      `J'aime les sessions ${s} bien organisées — quelqu'un de fiable SVP.`,
      `Tous niveaux bienvenus. Pratiquons ${s} ensemble avec plaisir !`,
    ],
    es: isRival ? [
      `Busco un rival serio para ${s}. ¡Que gane el mejor! 🏆`,
      `Listo para un partido de ${s}${city ? ' en ' + city : ''}. ¿Quién se atreve?`,
      `1v1 ${s} — ¿estás a la altura? ¡Escríbeme!`,
    ] : [
      `Busco un compañero constante para ${s}${city ? ' por ' + city : ''}.`,
      `Me gustan las sesiones de ${s} bien planificadas. ¡Apúntate!`,
      `Todos los niveles son bienvenidos. ¡Practiquemos ${s} juntos!`,
    ],
    ja: isRival ? [
      `${s}の真剣な対戦相手を探しています。実力で勝負しましょう！`,
      `${city ? city + 'で' : ''}1v1の${s}マッチ相手募集。勝負してみませんか？`,
    ] : [
      `${city ? city + '近辺で' : ''}${s}の定期パートナーを探しています。`,
      `一緒に${s}を楽しめる方、レベル問わず歓迎です！`,
    ],
    ko: isRival ? [
      `${s} 진지한 대결 상대를 찾고 있어요. 실력으로 승부해요! 🏆`,
      `1v1 ${s} 매치 도전자 구합니다. 자신 있으면 연락해요!`,
    ] : [
      `${city ? city + ' 근처에서 ' : ''}${s} 고정 파트너 구해요.`,
      `${s} 꾸준히 함께할 분 찾아요. 실력 무관 환영!`,
    ],
    pt: isRival ? [
      `Procuro um rival forte para ${s}. Que vença o melhor! 🏆`,
      `1v1 ${s}${city ? ' em ' + city : ''} — quem aceita o desafio?`,
    ] : [
      `Procuro parceiro regular para ${s}${city ? ' em ' + city : ''}.`,
      `Todos os níveis são bem-vindos. Vamos praticar ${s} juntos!`,
    ],
    it: isRival ? [
      `Cerco un avversario all'altezza per ${s}. Vinca il migliore! 🏆`,
      `1v1 ${s}${city ? ' a ' + city : ''} — chi accetta la sfida?`,
    ] : [
      `Cerco un partner regolare per ${s}${city ? ' a ' + city : ''}.`,
      `Tutti i livelli benvenuti. Pratichiamo ${s} insieme!`,
    ],
    ar: isRival ? [
      `أبحث عن منافس قوي في ${s}. ليفز الأفضل! 🏆`,
      `تحدٍّ 1v1 في ${s}${city ? ' في ' + city : ''} — من يقبل؟`,
    ] : [
      `أبحث عن شريك منتظم لـ ${s}${city ? ' في ' + city : ''}.`,
      `جميع المستويات مرحب بها. هيا نمارس ${s} معاً!`,
    ],
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
function generateShadowMatchText({ locale, listingBotName, responderBotName, sportName, sportId, cityName }) {
  const s = translateSportName(sportId, locale, sportName || 'sport');
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

// ─── Fake social links generator ──────────────────────────────────────────────
// Returns { platform: 'username' } for 3 platforms — visible but not clickable on bot profiles
function generateBotSocialLinks({ countryCode, name, seed }) {
  const h = hashSeed(seed || name || 'default');
  const cleanName = (name || 'user').replace(/[^a-zA-Z]/g, '').toLowerCase().slice(0, 12) || 'user';
  const suffix = 100 + (h % 900); // 3-digit suffix looks natural

  const platformPriority = {
    RU: ['instagram', 'vk', 'telegram'],
    KR: ['instagram', 'youtube', 'tiktok'],
    JP: ['instagram', 'twitter', 'youtube'],
    IN: ['instagram', 'youtube', 'twitter'],
    DE: ['instagram', 'facebook', 'youtube'],
    FR: ['instagram', 'tiktok', 'youtube'],
    GB: ['instagram', 'tiktok', 'youtube'],
    ES: ['instagram', 'tiktok', 'twitter'],
    CA: ['instagram', 'tiktok', 'youtube'],
    US: ['instagram', 'tiktok', 'youtube'],
  };

  const platforms = platformPriority[(countryCode || '').toUpperCase()] || ['instagram', 'tiktok', 'youtube'];
  const result = {};
  for (const platform of platforms) {
    result[platform] = `${cleanName}_${suffix}`;
  }
  return result;
}

// ─── Country sport preferences ─────────────────────────────────────────────────
const COUNTRY_SPORT_PREFERENCES = {
  RU: ['football', 'tennis', 'running', 'swimming', 'volleyball', 'yoga', 'pilates', 'cycling'],
  US: ['basketball', 'tennis', 'running', 'yoga', 'pilates', 'cycling', 'swimming', 'hiking'],
  KR: ['badminton', 'table_tennis', 'running', 'yoga', 'pilates', 'hiking', 'cycling', 'swimming'],
  JP: ['table_tennis', 'tennis', 'running', 'yoga', 'cycling', 'swimming', 'badminton', 'hiking'],
  IN: ['badminton', 'running', 'yoga', 'pilates', 'cycling', 'tennis', 'swimming', 'hiking'],
  DE: ['football', 'tennis', 'cycling', 'running', 'swimming', 'yoga', 'pilates', 'hiking'],
  FR: ['football', 'tennis', 'cycling', 'running', 'swimming', 'yoga', 'pilates', 'hiking'],
  GB: ['football', 'tennis', 'running', 'cycling', 'yoga', 'pilates', 'swimming', 'hiking'],
  ES: ['football', 'tennis', 'running', 'cycling', 'yoga', 'pilates', 'swimming', 'hiking'],
  CA: ['basketball', 'tennis', 'running', 'cycling', 'yoga', 'skiing', 'swimming', 'hiking'],
};

// ─── Global ecosystem city data (10 countries × 3 cities) ─────────────────────
const GLOBAL_ECOSYSTEM_CITIES = [
  { countryCode: 'RU', cities: [
    { name: 'Moscow', id: 'global_ru_moscow' },
    { name: 'Saint Petersburg', id: 'global_ru_spb' },
    { name: 'Novosibirsk', id: 'global_ru_novosibirsk' },
  ]},
  { countryCode: 'US', cities: [
    { name: 'New York', id: 'global_us_newyork' },
    { name: 'Los Angeles', id: 'global_us_la' },
    { name: 'Chicago', id: 'global_us_chicago' },
  ]},
  { countryCode: 'KR', cities: [
    { name: 'Seoul', id: 'global_kr_seoul' },
    { name: 'Busan', id: 'global_kr_busan' },
    { name: 'Incheon', id: 'global_kr_incheon' },
  ]},
  { countryCode: 'JP', cities: [
    { name: 'Tokyo', id: 'global_jp_tokyo' },
    { name: 'Osaka', id: 'global_jp_osaka' },
    { name: 'Yokohama', id: 'global_jp_yokohama' },
  ]},
  { countryCode: 'IN', cities: [
    { name: 'Mumbai', id: 'global_in_mumbai' },
    { name: 'Delhi', id: 'global_in_delhi' },
    { name: 'Bangalore', id: 'global_in_bangalore' },
  ]},
  { countryCode: 'DE', cities: [
    { name: 'Berlin', id: 'global_de_berlin' },
    { name: 'Munich', id: 'global_de_munich' },
    { name: 'Hamburg', id: 'global_de_hamburg' },
  ]},
  { countryCode: 'FR', cities: [
    { name: 'Paris', id: 'global_fr_paris' },
    { name: 'Lyon', id: 'global_fr_lyon' },
    { name: 'Marseille', id: 'global_fr_marseille' },
  ]},
  { countryCode: 'GB', cities: [
    { name: 'London', id: 'global_gb_london' },
    { name: 'Manchester', id: 'global_gb_manchester' },
    { name: 'Birmingham', id: 'global_gb_birmingham' },
  ]},
  { countryCode: 'ES', cities: [
    { name: 'Madrid', id: 'global_es_madrid' },
    { name: 'Barcelona', id: 'global_es_barcelona' },
    { name: 'Seville', id: 'global_es_seville' },
  ]},
  { countryCode: 'CA', cities: [
    { name: 'Toronto', id: 'global_ca_toronto' },
    { name: 'Montreal', id: 'global_ca_montreal' },
    { name: 'Vancouver', id: 'global_ca_vancouver' },
  ]},
];

// ─── Social post templates (localized, sport-themed) ──────────────────────────
function generateBotSocialPost({ locale, sportName, sportId, cityName }) {
  const s = translateSportName(sportId, locale, sportName || 'sport');
  const c = cityName || '';
  const templates = {
    tr: [
      `${c ? c + ' parkında ' : 'Bu sabah '}${s} antrenmanı harika geçti! 💪 Düzenli egzersiz hayat kalitesini artırıyor.`,
      `${s} sezonunu açtık! 🎯 Herkese aktif ve sağlıklı bir hafta diliyorum.`,
      `${s} için yeni bir hedef belirledim. Birlikte başarabiliriz! 🏆`,
      `Hafta sonu ${s} maçı için kim hazır? Yorum bırakın! 💬`,
      `${c ? c + ' sokaklarında ' : ''}${s} antrenmanı yapmanın tadı başka. 🏃‍♀️`,
      `${s} ile güne harika başladım. Siz de deneyin! ☀️`,
    ],
    en: [
      `Had an amazing ${s} session ${c ? 'in ' + c : 'today'}! 💪 Consistency is key to a healthy lifestyle.`,
      `Just finished a great ${s} workout. Feeling energized! ⚡`,
      `${c ? c + ' has' : 'This city has'} such a vibrant ${s} community. Love it! 🎯`,
      `Setting new goals for ${s} this season. Who's with me? 🏆`,
      `${s} is more than a sport — it's a way of life! 💬`,
      `Morning ${s}${c ? ' in ' + c : ''} is unbeatable. Started the day right! ☀️`,
    ],
    ru: [
      `Отличная тренировка по ${s}${c ? ' в ' + c : ' сегодня'}! 💪 Спорт — это жизнь!`,
      `${c ? c + ' — ' : ''}Лучший город для ${s}! Присоединяйтесь! 🎯`,
      `Новый сезон ${s} начался! Кто готов тренироваться вместе? 🏆`,
      `${s} каждый день — залог здоровья и хорошего настроения! ⚡`,
      `Утренняя тренировка по ${s} — лучшее начало дня! ☀️`,
    ],
    de: [
      `Fantastisches ${s}-Training ${c ? 'in ' + c : 'heute'}! 💪 Sport ist das beste Lebensgefühl.`,
      `${c ? c + ' ist eine' : 'Eine'} tolle Stadt für ${s}-Enthusiasten! 🎯`,
      `Neue ${s}-Saison, neue Ziele! Wer macht mit? 🏆`,
      `Nichts ist besser als ein gutes ${s}-Training am Morgen! ⚡`,
    ],
    fr: [
      `Super session de ${s}${c ? ' à ' + c : ' aujourd\'hui'}! 💪 Le sport c'est la santé!`,
      `${c ? c + ' est une' : 'Une'} ville fantastique pour ${s}! 🎯`,
      `Nouvelle saison de ${s}, nouveaux objectifs! Qui est partant? 🏆`,
      `Rien de tel qu'une bonne session de ${s} pour se ressourcer! ⚡`,
    ],
    es: [
      `¡Increíble sesión de ${s}${c ? ' en ' + c : ' hoy'}! 💪 El deporte es vida.`,
      `${c ? c + ' es' : 'Esta ciudad es'} perfecta para los amantes del ${s}! 🎯`,
      `¡Nueva temporada de ${s}, nuevos retos! ¿Quién se apunta? 🏆`,
      `¡No hay nada mejor que una buena sesión de ${s}! ⚡`,
    ],
    ja: [
      `${c ? c + 'で' : '今日は'}${s}の練習が最高でした！💪 スポーツは人生を豊かにします。`,
      `${c ? c + 'の' : '地元の'}${s}コミュニティが大好きです！🎯`,
      `${s}の新シーズン、新しい目標を設定しました。一緒に頑張りましょう！🏆`,
      `${s}は単なるスポーツではなく、ライフスタイルです！⚡`,
    ],
    ko: [
      `${c ? c + '에서 ' : '오늘 '}${s} 훈련이 너무 좋았어요! 💪 운동은 삶의 질을 높여줘요.`,
      `${c ? c + '의 ' : ''}${s} 커뮤니티가 너무 활발해서 좋아요! 🎯`,
      `${s} 새 시즌, 새 목표! 함께해요! 🏆`,
      `${s}는 단순한 스포츠가 아닌 라이프스타일이에요! ⚡`,
    ],
    pt: [
      `Sessão de ${s} incrível${c ? ' em ' + c : ' hoje'}! 💪 Esporte é vida!`,
      `${c ? c + ' é' : 'Esta cidade é'} fantástica para os amantes de ${s}! 🎯`,
      `Nova temporada de ${s}, novos objetivos! Quem se junta? 🏆`,
      `Nada melhor do que uma boa sessão de ${s}! ⚡`,
    ],
    it: [
      `Sessione di ${s} fantastica${c ? ' a ' + c : ' oggi'}! 💪 Lo sport è vita!`,
      `${c ? c + ' è' : 'Questa città è'} perfetta per gli appassionati di ${s}! 🎯`,
      `Nuova stagione di ${s}, nuovi obiettivi! Chi si unisce? 🏆`,
      `Niente di meglio di una buona sessione di ${s}! ⚡`,
    ],
    ar: [
      `جلسة ${s} رائعة${c ? ' في ' + c : ' اليوم'}! 💪 الرياضة هي الحياة.`,
      `${c ? c + ' هي' : 'هذه المدينة هي'} مكان رائع لعشاق ${s}! 🎯`,
      `موسم ${s} الجديد، أهداف جديدة! من يشاركني؟ 🏆`,
      `لا شيء أفضل من جلسة ${s} ممتعة! ⚡`,
    ],
  };
  const pool = templates[locale] || templates.en;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ─── Social comment templates (localized) ─────────────────────────────────────
function generateBotComment({ locale, posterName }) {
  const n = posterName || '';
  const templates = {
    tr: [
      `Harika! ${n ? n + ', ' : ''}seni destekliyorum 💪`,
      `Çok güzel paylaşım! 🔥`,
      `Çok motive edici, devam et! 🎯`,
      `Muhteşem! Devam et! ⚡`,
      `Bu paylaşım beni motive etti 🏆`,
      `Süper! 👏`,
      `Tebrikler ${n || ''}! 🎉`,
      `Gerçekten ilham verici! ✨`,
    ],
    en: [
      `Amazing${n ? ' ' + n : ''}! Keep it up! 💪`,
      `Love this post! 🔥`,
      `So inspiring! 🎯`,
      `Goals! ⚡`,
      `This motivated me to work out too! 🏆`,
      `Great energy! 👏`,
      `Congrats ${n || ''}! 🎉`,
      `Truly inspiring! ✨`,
    ],
    ru: [
      `Отличный пост! Продолжай в том же духе! 💪`,
      `Вдохновляет! 🔥`,
      `Молодец${n ? ', ' + n : ''}! 🎯`,
      `Так держать! ⚡`,
      `Мотивируешь тренироваться! 🏆`,
      `Поздравляю! 🎉`,
    ],
    de: [
      `Fantastisch${n ? ', ' + n : ''}! Weiter so! 💪`,
      `Klasse Post! 🔥`,
      `So inspirierend! 🎯`,
      `Ziele! ⚡`,
      `Das motiviert mich auch zu trainieren! 🏆`,
      `Herzlichen Glückwunsch! 🎉`,
    ],
    fr: [
      `Fantastique${n ? ', ' + n : ''}! Continue ainsi! 💪`,
      `Super post! 🔥`,
      `Tellement inspirant! 🎯`,
      `Objectifs! ⚡`,
      `Ça me motive à m'entraîner aussi! 🏆`,
      `Félicitations! 🎉`,
    ],
    es: [
      `¡Increíble${n ? ', ' + n : ''}! ¡Sigue así! 💪`,
      `¡Gran publicación! 🔥`,
      `¡Tan inspirador! 🎯`,
      `¡Metas! ⚡`,
      `¡Esto me motiva a entrenar también! 🏆`,
      `¡Felicidades! 🎉`,
    ],
    ja: [
      `素晴らしい${n ? '、' + n + 'さん' : ''}！続けてください！💪`,
      `素敵な投稿！🔥`,
      `とても刺激になります！🎯`,
      `目標！⚡`,
      `私も頑張ります！🏆`,
      `おめでとうございます！🎉`,
    ],
    ko: [
      `대단해요${n ? ', ' + n + '님' : ''}! 계속 화이팅! 💪`,
      `멋진 포스팅이에요! 🔥`,
      `정말 동기부여가 돼요! 🎯`,
      `목표! ⚡`,
      `저도 운동하고 싶어졌어요! 🏆`,
      `축하드려요! 🎉`,
    ],
    pt: [
      `Incrível${n ? ', ' + n : ''}! Continue assim! 💪`,
      `Post incrível! 🔥`,
      `Tão inspirador! 🎯`,
      `Objetivos! ⚡`,
      `Isso me motiva a treinar também! 🏆`,
      `Parabéns! 🎉`,
    ],
    it: [
      `Fantastico${n ? ', ' + n : ''}! Continua così! 💪`,
      `Post fantastico! 🔥`,
      `Così ispirante! 🎯`,
      `Obiettivi! ⚡`,
      `Questo mi motiva ad allenarmi anche io! 🏆`,
      `Congratulazioni! 🎉`,
    ],
    ar: [
      `رائع${n ? '، ' + n : ''}! استمر هكذا! 💪`,
      `منشور رائع! 🔥`,
      `ملهم جداً! 🎯`,
      `أهداف! ⚡`,
      `هذا يحفزني على ممارسة الرياضة أيضاً! 🏆`,
      `تهانيني! 🎉`,
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

module.exports = {
  hashSeed,
  mapCountryCodeToLocale,
  buildBotAvatarUrl,
  LOCALIZED_NAMES,
  DEFAULT_NAMES,
  SPORT_NAME_TRANSLATIONS,
  translateSportName,
  generateBotBio,
  generateListingDesc,
  generateResponseMsg,
  generateShadowMatchText,
  generateBotSocialPost,
  generateBotComment,
  generateBotSocialLinks,
  COUNTRY_SPORT_PREFERENCES,
  GLOBAL_ECOSYSTEM_CITIES,
  estimateBotCoordinates,
  getFutureDate,
};
