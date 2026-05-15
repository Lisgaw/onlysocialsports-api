-- Auth reset audit logs
-- Run in Supabase SQL Editor (or via migration pipeline)

CREATE TABLE IF NOT EXISTS auth_audit_logs (
  id         TEXT PRIMARY KEY DEFAULT ('audit_' || uuid_generate_v4()::TEXT),
  event_type TEXT NOT NULL,
  user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
  email      TEXT,
  ip_address TEXT,
  user_agent TEXT,
  success    BOOLEAN DEFAULT TRUE,
  reason     TEXT,
  metadata   JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_created_at
  ON auth_audit_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_event_type
  ON auth_audit_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_email
  ON auth_audit_logs(email);

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_id
  ON auth_audit_logs(user_id);
