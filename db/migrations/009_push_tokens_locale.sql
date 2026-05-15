-- Add per-device locale to push token records so backend can localize push text.

ALTER TABLE IF EXISTS push_tokens
  ADD COLUMN IF NOT EXISTS locale TEXT;

CREATE INDEX IF NOT EXISTS idx_push_tokens_locale
  ON push_tokens(locale);
