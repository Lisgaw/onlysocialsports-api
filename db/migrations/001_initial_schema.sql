-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  Sports Partner — Supabase PostgreSQL Migration                    ║
-- ║  22 collection → 28 tablo (ilişkisel, index'li, RLS hazır)        ║
-- ║  Çalıştırma: Supabase Dashboard → SQL Editor → Run                ║
-- ╚══════════════════════════════════════════════════════════════════════╝

-- ── Extensions ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- fuzzy text search için

-- ══════════════════════════════════════════════════════════════════════════════
-- 1. REFERANS TABLOLARI (Static Data)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE sports (
  id          TEXT PRIMARY KEY,                -- 'football', 'tennis' etc.
  name        TEXT NOT NULL,
  icon        TEXT NOT NULL,
  category    TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE cities (
  id          TEXT PRIMARY KEY,                -- 'c1', 'c2' etc.
  name        TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE districts (
  id          TEXT PRIMARY KEY,                -- 'd1', 'd2' etc.
  name        TEXT NOT NULL,
  city_id     TEXT NOT NULL REFERENCES cities(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_districts_city ON districts(city_id);

CREATE TABLE countries (
  id          TEXT PRIMARY KEY,                -- 'country_tr'
  name        TEXT NOT NULL,
  code        TEXT NOT NULL UNIQUE,            -- 'TR', 'DE'
  flag        TEXT NOT NULL,
  is_active   BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
-- 2. KULLANICILAR
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE users (
  id               TEXT PRIMARY KEY DEFAULT ('user_' || uuid_generate_v4()::TEXT),
  email            TEXT NOT NULL UNIQUE,
  name             TEXT NOT NULL,
  username         TEXT NOT NULL UNIQUE,
  password         TEXT NOT NULL,                -- bcrypt hash
  avatar_url       TEXT,
  cover_url        TEXT,
  phone            TEXT,
  is_admin         BOOLEAN DEFAULT FALSE,
  is_bot           BOOLEAN DEFAULT FALSE,
  onboarding_done  BOOLEAN DEFAULT FALSE,
  user_type        TEXT DEFAULT 'USER',
  city             TEXT,
  city_id          TEXT REFERENCES cities(id),
  district         TEXT,
  district_id      TEXT REFERENCES districts(id),
  bio              TEXT,
  -- Sosyal medya platformları (13 adet)
  instagram        TEXT,
  tiktok           TEXT,
  facebook         TEXT,
  twitter          TEXT,
  youtube          TEXT,
  linkedin         TEXT,
  discord          TEXT,
  twitch           TEXT,
  snapchat         TEXT,
  telegram         TEXT,
  whatsapp         TEXT,
  vk               TEXT,
  litmatch         TEXT,
  -- Spor tercihleri
  sports           JSONB DEFAULT '[]',           -- [{id, name, icon, category}]
  level            TEXT DEFAULT 'BEGINNER',       -- BEGINNER, INTERMEDIATE, ADVANCED, PRO
  gender           TEXT,                          -- MALE, FEMALE, OTHER
  preferred_time   TEXT,                          -- MORNING, AFTERNOON, EVENING, ANY
  preferred_style  TEXT,                          -- CASUAL, COMPETITIVE, BOTH
  birth_date       TIMESTAMPTZ,
  -- İstatistikler
  total_matches    INT DEFAULT 0,
  current_streak   INT DEFAULT 0,
  longest_streak   INT DEFAULT 0,
  total_points     INT DEFAULT 0,
  follower_count   INT DEFAULT 0,
  following_count  INT DEFAULT 0,
  average_rating   NUMERIC(3,2) DEFAULT 0,
  rating_count     INT DEFAULT 0,
  -- Durum
  is_banned        BOOLEAN DEFAULT FALSE,
  is_private       BOOLEAN DEFAULT FALSE,
  no_show_count    INT DEFAULT 0,
  -- Referral
  referral_code    TEXT UNIQUE,
  referred_by      TEXT,
  -- Meta
  country_code     TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_city ON users(city_id);
CREATE INDEX idx_users_is_bot ON users(is_bot) WHERE is_bot = TRUE;
CREATE INDEX idx_users_name_trgm ON users USING gin(name gin_trgm_ops);

-- ══════════════════════════════════════════════════════════════════════════════
-- 3. REFRESH TOKENS
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE refresh_tokens (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  expires_at  TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 4. İLANLAR (Listings)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE listings (
  id               TEXT PRIMARY KEY DEFAULT ('listing_' || uuid_generate_v4()::TEXT),
  type             TEXT NOT NULL CHECK (type IN ('RIVAL', 'PARTNER')),
  title            TEXT NOT NULL,
  description      TEXT,
  sport_id         TEXT REFERENCES sports(id),
  sport_name       TEXT,
  city_id          TEXT REFERENCES cities(id),
  city_name        TEXT,
  district_id      TEXT REFERENCES districts(id),
  district_name    TEXT,
  venue_id         TEXT,
  venue_name       TEXT,
  level            TEXT DEFAULT 'BEGINNER',
  gender           TEXT DEFAULT 'ANY',
  date             TIMESTAMPTZ,
  image_urls       JSONB DEFAULT '[]',
  max_participants INT,
  accepted_count   INT DEFAULT 0,
  status           TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'MATCHED', 'EXPIRED', 'DELETED')),
  age_min          INT,
  age_max          INT,
  is_recurring     BOOLEAN DEFAULT FALSE,
  is_anonymous     BOOLEAN DEFAULT FALSE,
  is_urgent        BOOLEAN DEFAULT FALSE,
  is_quick         BOOLEAN DEFAULT FALSE,
  response_count   INT DEFAULT 0,
  user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_name        TEXT,
  user_avatar      TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  expires_at       TIMESTAMPTZ
);

CREATE INDEX idx_listings_user ON listings(user_id);
CREATE INDEX idx_listings_sport ON listings(sport_id);
CREATE INDEX idx_listings_city ON listings(city_id);
CREATE INDEX idx_listings_status ON listings(status);
CREATE INDEX idx_listings_type ON listings(type);
CREATE INDEX idx_listings_date ON listings(date);
CREATE INDEX idx_listings_created ON listings(created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
-- 5. EŞLEŞMELER (Matches)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE matches (
  id             TEXT PRIMARY KEY DEFAULT ('match_' || uuid_generate_v4()::TEXT),
  listing_id     TEXT REFERENCES listings(id) ON DELETE SET NULL,
  source         TEXT DEFAULT 'LISTING' CHECK (source IN ('LISTING', 'CHALLENGE')),
  user1_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user2_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status         TEXT DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED', 'COMPLETED', 'CANCELLED', 'NO_SHOW')),
  u1_approved    BOOLEAN DEFAULT FALSE,
  u2_approved    BOOLEAN DEFAULT FALSE,
  scheduled_at   TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  trust_score    INT DEFAULT 0,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_matches_user1 ON matches(user1_id);
CREATE INDEX idx_matches_user2 ON matches(user2_id);
CREATE INDEX idx_matches_listing ON matches(listing_id);
CREATE INDEX idx_matches_status ON matches(status);

-- ══════════════════════════════════════════════════════════════════════════════
-- 6. MESAJLAŞMA
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE conversations (
  id           TEXT PRIMARY KEY DEFAULT ('conv_' || uuid_generate_v4()::TEXT),
  user1_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user2_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type         TEXT DEFAULT 'direct',
  last_message JSONB,                           -- {content, senderId, createdAt}
  unread_for   JSONB DEFAULT '{}',              -- {userId: count}
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user1_id, user2_id)
);

CREATE INDEX idx_conversations_user1 ON conversations(user1_id);
CREATE INDEX idx_conversations_user2 ON conversations(user2_id);

CREATE TABLE messages (
  id              TEXT PRIMARY KEY DEFAULT ('msg_' || uuid_generate_v4()::TEXT),
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content         TEXT NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_messages_conversation ON messages(conversation_id);
CREATE INDEX idx_messages_created ON messages(created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
-- 7. MEYDAN OKUMALAR (Challenges)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE challenges (
  id                TEXT PRIMARY KEY DEFAULT ('challenge_' || uuid_generate_v4()::TEXT),
  sender_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sport_id          TEXT REFERENCES sports(id),
  challenge_type    TEXT DEFAULT 'RIVAL' CHECK (challenge_type IN ('RIVAL', 'PARTNER')),
  message           TEXT,
  proposed_date_time TIMESTAMPTZ,
  district_id       TEXT REFERENCES districts(id),
  status            TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED')),
  expires_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_challenges_sender ON challenges(sender_id);
CREATE INDEX idx_challenges_target ON challenges(target_id);
CREATE INDEX idx_challenges_status ON challenges(status);

-- ══════════════════════════════════════════════════════════════════════════════
-- 8. BİLDİRİMLER (Notifications)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE notifications (
  id            TEXT PRIMARY KEY DEFAULT ('notif_' || uuid_generate_v4()::TEXT),
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type          TEXT NOT NULL,                     -- 11 bildirim tipi
  title         TEXT,
  body          TEXT,
  related_id    TEXT,
  link          TEXT,
  sender_id     TEXT,
  sender_name   TEXT,
  sender_avatar TEXT,
  is_read       BOOLEAN DEFAULT FALSE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(user_id, is_read);
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
-- 9. TAKİP SİSTEMİ (Follows)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE follows (
  id           TEXT PRIMARY KEY DEFAULT ('follow_' || uuid_generate_v4()::TEXT),
  follower_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  following_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status       TEXT DEFAULT 'accepted' CHECK (status IN ('accepted', 'pending')),
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(follower_id, following_id)
);

CREATE INDEX idx_follows_follower ON follows(follower_id);
CREATE INDEX idx_follows_following ON follows(following_id);
CREATE INDEX idx_follows_status ON follows(status);

-- ══════════════════════════════════════════════════════════════════════════════
-- 10. ENGELLEME (Blocked Users)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE blocked_users (
  id          TEXT PRIMARY KEY DEFAULT ('block_' || uuid_generate_v4()::TEXT),
  blocker_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(blocker_id, blocked_id)
);

CREATE INDEX idx_blocked_blocker ON blocked_users(blocker_id);
CREATE INDEX idx_blocked_blocked ON blocked_users(blocked_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 11. RAPORLAR (Reports)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE reports (
  id               TEXT PRIMARY KEY DEFAULT ('report_' || uuid_generate_v4()::TEXT),
  reporter_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reported_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  target_id        TEXT,                          -- generic target (post, listing, etc.)
  type             TEXT NOT NULL,                  -- USER, POST, LISTING, COMMENT
  reason           TEXT,
  description      TEXT,
  status           TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RESOLVED', 'DISMISSED')),
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_reporter ON reports(reporter_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 12. İLAN BAŞVURULARI (Interests)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE interests (
  id           TEXT PRIMARY KEY DEFAULT ('interest_' || uuid_generate_v4()::TEXT),
  listing_id   TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_name    TEXT,
  user_avatar  TEXT,
  message      TEXT,
  status       TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED')),
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(listing_id, user_id)
);

CREATE INDEX idx_interests_listing ON interests(listing_id);
CREATE INDEX idx_interests_user ON interests(user_id);
CREATE INDEX idx_interests_status ON interests(status);

-- ══════════════════════════════════════════════════════════════════════════════
-- 13. DEĞERLENDİRMELER (Ratings)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE ratings (
  id          TEXT PRIMARY KEY DEFAULT ('rating_' || uuid_generate_v4()::TEXT),
  match_id    TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  rater_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ratee_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  score       INT NOT NULL CHECK (score BETWEEN 1 AND 5),
  comment     TEXT,
  sport_id    TEXT REFERENCES sports(id),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(match_id, rater_id)
);

CREATE INDEX idx_ratings_ratee ON ratings(ratee_id);
CREATE INDEX idx_ratings_match ON ratings(match_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 14. TOPLULUKLAR (Communities)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE communities (
  id           TEXT PRIMARY KEY DEFAULT ('community_' || uuid_generate_v4()::TEXT),
  type         TEXT DEFAULT 'GROUP' CHECK (type IN ('GROUP', 'CLUB', 'TEAM')),
  name         TEXT NOT NULL,
  description  TEXT,
  avatar_url   TEXT,
  website      TEXT,
  is_private   BOOLEAN DEFAULT FALSE,
  sport        JSONB,                           -- {id, name, icon}
  city         JSONB,                           -- {id, name}
  owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  members      JSONB DEFAULT '[]',
  posts        JSONB DEFAULT '[]',
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_communities_owner ON communities(owner_id);
CREATE INDEX idx_communities_type ON communities(type);

-- ══════════════════════════════════════════════════════════════════════════════
-- 15. GRUPLAR (Groups — basitleştirilmiş topluluk)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE groups (
  id           TEXT PRIMARY KEY DEFAULT ('group_' || uuid_generate_v4()::TEXT),
  name         TEXT NOT NULL,
  description  TEXT,
  is_public    BOOLEAN DEFAULT TRUE,
  avatar_url   TEXT,
  sport        JSONB,
  city         JSONB,
  _count       JSONB DEFAULT '{"members": 0}',
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE group_members (
  id        SERIAL PRIMARY KEY,
  group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role      TEXT DEFAULT 'MEMBER',
  UNIQUE(group_id, user_id)
);

CREATE INDEX idx_group_members_group ON group_members(group_id);
CREATE INDEX idx_group_members_user ON group_members(user_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 16. PAYLAŞIMLAR (Posts)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE posts (
  id           TEXT PRIMARY KEY DEFAULT ('post_' || uuid_generate_v4()::TEXT),
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_type    TEXT DEFAULT 'POST' CHECK (post_type IN ('POST', 'SOCIAL_LISTING')),
  content      TEXT,
  title        TEXT,
  image_url    TEXT,
  sport_id     TEXT REFERENCES sports(id),
  city_id      TEXT REFERENCES cities(id),
  city_name    TEXT,
  district_id  TEXT REFERENCES districts(id),
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_posts_user ON posts(user_id);
CREATE INDEX idx_posts_type ON posts(post_type);
CREATE INDEX idx_posts_created ON posts(created_at DESC);
CREATE INDEX idx_posts_city ON posts(city_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 17. TEPKİLER (Post Reactions)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE post_reactions (
  id          TEXT PRIMARY KEY DEFAULT ('react_' || uuid_generate_v4()::TEXT),
  post_id     TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        TEXT NOT NULL CHECK (type IN ('LIKE', 'LOVE', 'FIRE', 'STRONG', 'WOW', 'CLAP')),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(post_id, user_id)
);

CREATE INDEX idx_post_reactions_post ON post_reactions(post_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 18. YORUMLAR (Comments)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE comments (
  id          TEXT PRIMARY KEY DEFAULT ('comment_' || uuid_generate_v4()::TEXT),
  post_id     TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id   TEXT REFERENCES comments(id) ON DELETE CASCADE,   -- nested comments
  content     TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_comments_post ON comments(post_id);
CREATE INDEX idx_comments_parent ON comments(parent_id);

CREATE TABLE comment_likes (
  id          TEXT PRIMARY KEY DEFAULT ('cl_' || uuid_generate_v4()::TEXT),
  comment_id  TEXT NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(comment_id, user_id)
);

CREATE INDEX idx_comment_likes_comment ON comment_likes(comment_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 19. BOT GÖREVLERI (Bot Tasks)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE bot_tasks (
  id               TEXT PRIMARY KEY DEFAULT ('task_' || uuid_generate_v4()::TEXT),
  listing_bot_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
  responder_bot_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  city_id          TEXT,
  city_name        TEXT,
  country_code     TEXT,
  sport_id         TEXT,
  status           TEXT DEFAULT 'PENDING',
  listing_date_time TIMESTAMPTZ,
  match_id         TEXT,
  delay_seconds    INT DEFAULT 0,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_bot_tasks_status ON bot_tasks(status);

-- ══════════════════════════════════════════════════════════════════════════════
-- 20. OTP VE NO-SHOW
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE otps (
  id            TEXT PRIMARY KEY DEFAULT ('otp_' || uuid_generate_v4()::TEXT),
  match_id      TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  requester_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code          TEXT NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_otps_match ON otps(match_id);

CREATE TABLE noshows (
  id           TEXT PRIMARY KEY DEFAULT ('noshow_' || uuid_generate_v4()::TEXT),
  match_id     TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  reporter_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reported_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
-- 21. KULLANICI GİZLİLİK AYARLARI
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE user_privacy (
  user_id              TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  profile_visibility   TEXT DEFAULT 'PUBLIC',       -- PUBLIC, FOLLOWERS_ONLY, PRIVATE
  show_online_status   BOOLEAN DEFAULT TRUE,
  show_last_seen       BOOLEAN DEFAULT TRUE,
  show_sports          BOOLEAN DEFAULT TRUE,
  show_statistics      BOOLEAN DEFAULT TRUE,
  show_social_links    BOOLEAN DEFAULT TRUE,
  allow_messages_from  TEXT DEFAULT 'EVERYONE',     -- EVERYONE, FOLLOWERS, NOBODY
  show_age             BOOLEAN DEFAULT TRUE,
  show_location        BOOLEAN DEFAULT TRUE,
  updated_at           TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
-- 22. SEED DATA — Referans Tabloları
-- ══════════════════════════════════════════════════════════════════════════════

-- Sporlar (36 adet)
INSERT INTO sports (id, name, icon, category) VALUES
  ('football', 'Futbol', '⚽', 'Top Sporları'),
  ('basketball', 'Basketbol', '🏀', 'Top Sporları'),
  ('volleyball', 'Voleybol', '🏐', 'Top Sporları'),
  ('tennis', 'Tenis', '🎾', 'Raket Sporları'),
  ('padel', 'Padel', '🏓', 'Raket Sporları'),
  ('fitness', 'Fitness', '💪', 'Fitness ve Güç'),
  ('swimming', 'Yüzme', '🏊', 'Su Sporları'),
  ('running', 'Koşu', '🏃', 'Kardiyo'),
  ('hiking', 'Yürüyüş', '🥾', 'Doğa ve Outdoor'),
  ('yoga', 'Yoga', '🧘', 'Esneklik ve Zihin'),
  ('pilates', 'Pilates', '🤸', 'Esneklik ve Zihin'),
  ('cricket', 'Kriket', '🏏', 'Top Sporları'),
  ('badminton', 'Badminton', '🏸', 'Raket Sporları'),
  ('table_tennis', 'Masa Tenisi', '🏓', 'Raket Sporları'),
  ('baseball', 'Beyzbol', '⚾', 'Top Sporları'),
  ('kabaddi', 'Kabaddi', '🤼', 'Dövüş Sporları'),
  ('martial_arts', 'Dövüş Sanatları', '🥋', 'Dövüş Sporları'),
  ('archery', 'Okçuluk', '🏹', 'Doğa ve Outdoor'),
  ('equestrian', 'Binicilik', '🏇', 'Doğa ve Outdoor'),
  ('sand_surfing', 'Kum Sörfü', '🏄', 'Su Sporları'),
  ('cycling', 'Bisiklet', '🚴', 'Doğa ve Outdoor'),
  ('american_football', 'Amerikan Futbolu', '🏈', 'Top Sporları'),
  ('rugby', 'Rugby', '🏉', 'Top Sporları'),
  ('ice_hockey', 'Buz Hokeyi', '🏒', 'Kış Sporları'),
  ('handball', 'Hentbol', '🤾', 'Top Sporları'),
  ('skateboarding', 'Kaykay', '🛹', 'Urban Sporlar'),
  ('skating', 'Paten', '⛸️', 'Urban Sporlar'),
  ('surfing', 'Sörf', '🏄', 'Su Sporları'),
  ('crossfit', 'Crossfit', '🏋️', 'Fitness ve Güç'),
  ('pickleball', 'Pickleball', '🏓', 'Raket Sporları'),
  ('billiards', 'Bilardo', '🎱', 'Masa Sporları'),
  ('darts', 'Dart', '🎯', 'Masa Sporları'),
  ('bowling', 'Bowling', '🎳', 'Masa Sporları'),
  ('fishing', 'Balık Tutma', '🎣', 'Su Sporları'),
  ('paintball', 'Paintball', '🔫', 'Aksiyon Sporları'),
  ('dance', 'Dans', '💃', 'Müzik ve Dans');

-- Şehirler
INSERT INTO cities (id, name) VALUES
  ('c1', 'İstanbul'),
  ('c2', 'Ankara'),
  ('c3', 'İzmir'),
  ('c4', 'Bursa'),
  ('c5', 'Antalya');

-- İlçeler
INSERT INTO districts (id, name, city_id) VALUES
  ('d1', 'Kadıköy', 'c1'),
  ('d2', 'Beşiktaş', 'c1'),
  ('d3', 'Şişli', 'c1'),
  ('d4', 'Üsküdar', 'c1'),
  ('d5', 'Çankaya', 'c2'),
  ('d6', 'Keçiören', 'c2'),
  ('d7', 'Konak', 'c3'),
  ('d8', 'Bornova', 'c3'),
  ('d9', 'Osmangazi', 'c4'),
  ('d10', 'Muratpaşa', 'c5');

-- Ülkeler (24 adet)
INSERT INTO countries (id, name, code, flag) VALUES
  ('country_tr', 'Türkiye', 'TR', '🇹🇷'),
  ('country_de', 'Almanya', 'DE', '🇩🇪'),
  ('country_gb', 'İngiltere', 'GB', '🇬🇧'),
  ('country_fr', 'Fransa', 'FR', '🇫🇷'),
  ('country_nl', 'Hollanda', 'NL', '🇳🇱'),
  ('country_us', 'ABD', 'US', '🇺🇸'),
  ('country_es', 'İspanya', 'ES', '🇪🇸'),
  ('country_it', 'İtalya', 'IT', '🇮🇹'),
  ('country_ru', 'Rusya', 'RU', '🇷🇺'),
  ('country_jp', 'Japonya', 'JP', '🇯🇵'),
  ('country_kr', 'Güney Kore', 'KR', '🇰🇷'),
  ('country_br', 'Brezilya', 'BR', '🇧🇷'),
  ('country_pt', 'Portekiz', 'PT', '🇵🇹'),
  ('country_in', 'Hindistan', 'IN', '🇮🇳'),
  ('country_au', 'Avustralya', 'AU', '🇦🇺'),
  ('country_ca', 'Kanada', 'CA', '🇨🇦'),
  ('country_sa', 'Suudi Arabistan', 'SA', '🇸🇦'),
  ('country_eg', 'Mısır', 'EG', '🇪🇬'),
  ('country_az', 'Azerbaycan', 'AZ', '🇦🇿'),
  ('country_pk', 'Pakistan', 'PK', '🇵🇰'),
  ('country_gr', 'Yunanistan', 'GR', '🇬🇷'),
  ('country_bg', 'Bulgaristan', 'BG', '🇧🇬'),
  ('country_ge', 'Gürcistan', 'GE', '🇬🇪'),
  ('country_ar', 'Arjantin', 'AR', '🇦🇷');

-- ══════════════════════════════════════════════════════════════════════════════
-- 23. ROW LEVEL SECURITY (RLS) — Temel Kurallar
-- ══════════════════════════════════════════════════════════════════════════════

-- NOT: Supabase RLS'i, auth.uid() ile çalışır. Custom JWT auth
-- kullanıyorsan RLS yerine server-side middleware tercih et.
-- Aşağıdaki politikalar Supabase Auth entegrasyonu sonrası aktif edilebilir.

-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE listings ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- ══════════════════════════════════════════════════════════════════════════════
-- 24. FONKSİYONLAR — Yardımcı
-- ══════════════════════════════════════════════════════════════════════════════

-- Kullanıcı rating ortalamasını güncelle
CREATE OR REPLACE FUNCTION update_user_rating()
RETURNS TRIGGER AS $$
DECLARE
  avg_score NUMERIC;
  count_score INT;
BEGIN
  SELECT AVG(score), COUNT(*) INTO avg_score, count_score
  FROM ratings WHERE ratee_id = NEW.ratee_id;

  UPDATE users
  SET average_rating = ROUND(avg_score, 2),
      rating_count = count_score
  WHERE id = NEW.ratee_id;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_rating
  AFTER INSERT ON ratings
  FOR EACH ROW EXECUTE FUNCTION update_user_rating();

-- Follow count'ları güncelle
CREATE OR REPLACE FUNCTION update_follow_counts()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.status = 'accepted' THEN
    UPDATE users SET follower_count = follower_count + 1 WHERE id = NEW.following_id;
    UPDATE users SET following_count = following_count + 1 WHERE id = NEW.follower_id;
  ELSIF TG_OP = 'DELETE' AND OLD.status = 'accepted' THEN
    UPDATE users SET follower_count = GREATEST(follower_count - 1, 0) WHERE id = OLD.following_id;
    UPDATE users SET following_count = GREATEST(following_count - 1, 0) WHERE id = OLD.follower_id;
  ELSIF TG_OP = 'UPDATE' AND OLD.status = 'pending' AND NEW.status = 'accepted' THEN
    UPDATE users SET follower_count = follower_count + 1 WHERE id = NEW.following_id;
    UPDATE users SET following_count = following_count + 1 WHERE id = NEW.follower_id;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_follow_counts
  AFTER INSERT OR UPDATE OR DELETE ON follows
  FOR EACH ROW EXECUTE FUNCTION update_follow_counts();

-- ══════════════════════════════════════════════════════════════════════════════
-- TAMAMLANDI! 28 tablo, 40+ index, 2 trigger, referans verileri yüklü.
-- ══════════════════════════════════════════════════════════════════════════════
