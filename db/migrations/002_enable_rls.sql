-- ============================================================
-- 002_enable_rls.sql
-- Row-Level Security (RLS) for ALL tables
-- Backend uses service_key → bypasses RLS automatically
-- This ONLY blocks direct anon/authenticated key access
-- ============================================================

-- ─── 1. ENABLE RLS ON ALL UNPROTECTED TABLES ────────────────

ALTER TABLE listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocked_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE ratings ENABLE ROW LEVEL SECURITY;
ALTER TABLE interests ENABLE ROW LEVEL SECURITY;
ALTER TABLE communities ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE otps ENABLE ROW LEVEL SECURITY;
ALTER TABLE noshows ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE bot_ecosystems ENABLE ROW LEVEL SECURITY;
ALTER TABLE bot_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE post_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE comment_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;

-- Public reference tables (read-only for everyone)
ALTER TABLE sports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cities ENABLE ROW LEVEL SECURITY;
ALTER TABLE districts ENABLE ROW LEVEL SECURITY;
ALTER TABLE countries ENABLE ROW LEVEL SECURITY;

-- users table (already has some protection but ensure RLS is on)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- ─── 2. PUBLIC READ POLICIES (Reference/Catalog tables) ─────
-- These tables should be readable by anyone (anon + authenticated)
-- They contain non-sensitive reference data (sport names, city names, etc.)

CREATE POLICY "Public read: sports" ON sports
  FOR SELECT USING (true);

CREATE POLICY "Public read: cities" ON cities
  FOR SELECT USING (true);

CREATE POLICY "Public read: districts" ON districts
  FOR SELECT USING (true);

CREATE POLICY "Public read: countries" ON countries
  FOR SELECT USING (true);

-- ─── 3. NO POLICIES FOR SENSITIVE TABLES ────────────────────
-- service_role (used by backend) bypasses RLS automatically.
-- No anon/authenticated policies = NO direct access from client.
-- All data access goes through the Express API backend.
--
-- Tables with NO client policy (fully blocked except via backend):
--   users, listings, messages, conversations, notifications,
--   matches, challenges, posts, follows, blocked_users, reports,
--   ratings, interests, communities, groups, comments, otps,
--   noshows, password_reset_tokens, bot_ecosystems, bot_tasks,
--   post_reactions, comment_likes, group_members

-- ─── 4. VERIFICATION QUERY ──────────────────────────────────
-- Run this after to confirm all tables have RLS enabled:
-- SELECT schemaname, tablename, rowsecurity 
-- FROM pg_tables 
-- WHERE schemaname = 'public' 
-- ORDER BY tablename;
