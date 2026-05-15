-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  005 — Ratings unique key fix for group match multi-partner rating   ║
-- ╚══════════════════════════════════════════════════════════════════════╝
--
-- Problem:
--   Old schema used UNIQUE(match_id, rater_id). In group matches,
--   one user must be able to rate multiple different partners.
--
-- Fix:
--   Move uniqueness to UNIQUE(match_id, rater_id, ratee_id).

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ratings_match_id_rater_id_key'
      AND conrelid = 'ratings'::regclass
  ) THEN
    ALTER TABLE ratings
      DROP CONSTRAINT ratings_match_id_rater_id_key;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ratings_match_id_rater_id_ratee_id_key'
      AND conrelid = 'ratings'::regclass
  ) THEN
    ALTER TABLE ratings
      ADD CONSTRAINT ratings_match_id_rater_id_ratee_id_key
      UNIQUE (match_id, rater_id, ratee_id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ratings_match_rater
  ON ratings(match_id, rater_id);
