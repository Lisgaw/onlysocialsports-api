-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  006 — OSM venue cache (city + sport, 30 days TTL)                  ║
-- ╚══════════════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS venues_cache (
  cache_key   TEXT PRIMARY KEY,
  city_name   TEXT NOT NULL,
  sport_id    TEXT NOT NULL,
  source      TEXT NOT NULL DEFAULT 'overpass',
  venues_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_venues_cache_city_sport
  ON venues_cache(city_name, sport_id);

CREATE INDEX IF NOT EXISTS idx_venues_cache_expires_at
  ON venues_cache(expires_at);
