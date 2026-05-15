-- Push token persistence for FCM/APNS delivery
-- Run in Supabase SQL Editor (or via migration pipeline)

CREATE TABLE IF NOT EXISTS push_tokens (
  id           TEXT PRIMARY KEY DEFAULT ('pt_' || uuid_generate_v4()::TEXT),
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token        TEXT NOT NULL,
  platform     TEXT NOT NULL DEFAULT 'android',
  is_active    BOOLEAN DEFAULT TRUE,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, token)
);

CREATE INDEX IF NOT EXISTS idx_push_tokens_user_id ON push_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_push_tokens_active ON push_tokens(user_id, is_active);
