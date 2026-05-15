-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  Bot Ecosystems — Şehir/Ülke Canlandırma Motoru                   ║
-- ║  Çalıştırma: Supabase Dashboard → SQL Editor → Run                ║
-- ╚══════════════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS bot_ecosystems (
  id                    TEXT PRIMARY KEY,
  scope                 TEXT NOT NULL DEFAULT 'CITY',          -- 'CITY' | 'COUNTRY' | 'WORLD'
  country_code          TEXT,                                  -- 'TR', 'DE', etc.
  city_id               TEXT,
  city_name             TEXT,
  sport_ids             JSONB DEFAULT '[]'::jsonb,             -- Array of sport IDs
  listing_type          TEXT NOT NULL DEFAULT 'PARTNER',       -- 'PARTNER' | 'RIVAL' | 'BOTH'
  bots_per_city         INTEGER NOT NULL DEFAULT 6,
  max_participants      INTEGER NOT NULL DEFAULT 4,
  hourly_applications   INTEGER NOT NULL DEFAULT 2,
  status                TEXT NOT NULL DEFAULT 'ACTIVE',        -- 'ACTIVE' | 'PAUSED'
  total_bots            INTEGER DEFAULT 0,
  total_listings        INTEGER DEFAULT 0,
  total_matches         INTEGER DEFAULT 0,
  last_tick_at          TIMESTAMPTZ,
  created_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ecosystems_status ON bot_ecosystems(status);
CREATE INDEX IF NOT EXISTS idx_ecosystems_city ON bot_ecosystems(city_id);
CREATE INDEX IF NOT EXISTS idx_ecosystems_country ON bot_ecosystems(country_code);

-- Add is_bot and bot_persona to users if not exists
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_bot') THEN
    ALTER TABLE users ADD COLUMN is_bot BOOLEAN DEFAULT FALSE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='bot_persona') THEN
    ALTER TABLE users ADD COLUMN bot_persona TEXT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='latitude') THEN
    ALTER TABLE users ADD COLUMN latitude DOUBLE PRECISION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='longitude') THEN
    ALTER TABLE users ADD COLUMN longitude DOUBLE PRECISION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='listings' AND column_name='latitude') THEN
    ALTER TABLE listings ADD COLUMN latitude DOUBLE PRECISION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='listings' AND column_name='longitude') THEN
    ALTER TABLE listings ADD COLUMN longitude DOUBLE PRECISION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='listings' AND column_name='accepted_count') THEN
    ALTER TABLE listings ADD COLUMN accepted_count INTEGER DEFAULT 0;
  END IF;
END $$;
