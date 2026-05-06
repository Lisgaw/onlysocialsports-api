-- ╔══════════════════════════════════════════════════════════════════════╗
-- ║  003 — Match Participants (Kalıcı Grup Katılımcı Modeli)            ║
-- ╚══════════════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS match_participants (
  id          TEXT PRIMARY KEY DEFAULT ('mp_' || uuid_generate_v4()::TEXT),
  match_id    TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        TEXT NOT NULL DEFAULT 'PARTICIPANT' CHECK (role IN ('OWNER', 'PARTICIPANT')),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(match_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_match_participants_match ON match_participants(match_id);
CREATE INDEX IF NOT EXISTS idx_match_participants_user ON match_participants(user_id);
