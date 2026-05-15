-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  004 — Match Location Verifications (OTP + GPS doğrulama desteği)   ║
-- ╚══════════════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS match_location_verifications (
  id                    TEXT PRIMARY KEY DEFAULT ('mlv_' || uuid_generate_v4()::TEXT),
  match_id              TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  latitude              DOUBLE PRECISION NOT NULL CHECK (latitude >= -90 AND latitude <= 90),
  longitude             DOUBLE PRECISION NOT NULL CHECK (longitude >= -180 AND longitude <= 180),
  verified_at           TIMESTAMPTZ DEFAULT NOW(),
  rewarded_at           TIMESTAMPTZ,
  distance_to_listing_m INT,
  UNIQUE(match_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_match_location_verifications_match
  ON match_location_verifications(match_id);

CREATE INDEX IF NOT EXISTS idx_match_location_verifications_user
  ON match_location_verifications(user_id);
