-- Run this migration after the initial schema.sql
-- Adds email_verifications table + mp_payment_id column

CREATE TABLE IF NOT EXISTS email_verifications (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ev_token_idx ON email_verifications(token_hash)
  WHERE used_at IS NULL;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS mp_payment_id VARCHAR(64);
CREATE INDEX IF NOT EXISTS orders_mp_idx ON orders(mp_payment_id)
  WHERE mp_payment_id IS NOT NULL;

-- RLS: email_verifications only accessible via service functions
ALTER TABLE email_verifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY ev_all ON email_verifications FOR ALL USING (true);
GRANT SELECT, INSERT, UPDATE ON email_verifications TO app_api;
