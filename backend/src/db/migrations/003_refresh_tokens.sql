-- Migration 003: refresh tokens + short-lived access tokens
-- Access token: 15 minutes (JWT)
-- Refresh token: 30 days (opaque, stored hashed in DB)
-- On each use, refresh token is rotated (old one invalidated, new one issued)

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) NOT NULL UNIQUE,   -- SHA-256 of the raw token
  family      UUID        NOT NULL,          -- token family for reuse detection
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,                   -- set when rotated (single-use)
  revoked_at  TIMESTAMPTZ,                   -- set on logout or family compromise
  ip          INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- Fast lookup by token hash (used on every /auth/refresh call)
CREATE INDEX IF NOT EXISTS rt_hash_idx    ON refresh_tokens(token_hash)
  WHERE used_at IS NULL AND revoked_at IS NULL;

-- Fast family lookup (used for reuse detection)
CREATE INDEX IF NOT EXISTS rt_family_idx  ON refresh_tokens(family);
CREATE INDEX IF NOT EXISTS rt_user_idx    ON refresh_tokens(user_id);

-- RLS: app_api can read/write all (service-level, controlled by token hash check)
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY rt_all ON refresh_tokens FOR ALL USING (true);
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO app_api;
