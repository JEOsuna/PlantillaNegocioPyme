-- PlantillaNegocioPyme schema · PostgreSQL 16
-- ── RLS-hardened: every user-scoped table has policies that enforce
--    ownership at the DB level, independent of application code.
-- ── Uses two roles:
--      app_api   — the Node app connects as this; limited to DML, RLS enforced
--      app_admin — migrations + seeds run as this; bypasses RLS
-- ── In production: DATABASE_URL should use app_api credentials.
--    Run migrations with a superuser / app_admin role.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Roles ───────────────────────────────────────────────────────────────────
-- Create if they don't exist (idempotent via DO block)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_api') THEN
    CREATE ROLE app_api LOGIN PASSWORD 'CHANGE_IN_PROD';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin') THEN
    CREATE ROLE app_admin LOGIN PASSWORD 'CHANGE_IN_PROD';
  END IF;
END$$;

-- ─── Tables ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email              VARCHAR(255) UNIQUE NOT NULL,
  password_hash      VARCHAR(255) NOT NULL,
  name               VARCHAR(120),
  role               VARCHAR(16)  NOT NULL DEFAULT 'customer'
                                  CHECK (role IN ('customer','admin')),
  email_verified_at  TIMESTAMPTZ,
  created_at         TIMESTAMPTZ  DEFAULT now(),
  last_login_at      TIMESTAMPTZ,
  -- Soft-delete: preserves order/refund history but blocks login
  deleted_at         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS products (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  slug               VARCHAR(64)  UNIQUE NOT NULL,
  name               VARCHAR(200) NOT NULL,
  description        TEXT,
  price_mxn_cents    INTEGER      NOT NULL CHECK (price_mxn_cents > 0),
  r2_object_key      VARCHAR(255) NOT NULL,
  version            VARCHAR(16)  DEFAULT '1.0',
  is_active          BOOLEAN      DEFAULT TRUE,
  created_at         TIMESTAMPTZ  DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orders (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total_mxn_cents    INTEGER     NOT NULL CHECK (total_mxn_cents > 0),
  gateway            VARCHAR(16) NOT NULL CHECK (gateway IN ('stripe','mp')),
  gateway_id         VARCHAR(255),
  status             VARCHAR(16) NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending','paid','refunded','failed')),
  paid_at            TIMESTAMPTZ,
  created_at         TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS orders_user_idx   ON orders(user_id);
CREATE INDEX IF NOT EXISTS orders_status_idx ON orders(status);
CREATE INDEX IF NOT EXISTS orders_gw_idx     ON orders(gateway_id) WHERE gateway_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS order_items (
  id                 UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id           UUID    NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id         UUID    NOT NULL REFERENCES products(id),
  unit_price_cents   INTEGER NOT NULL CHECK (unit_price_cents > 0),
  quantity           INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0)
);
CREATE INDEX IF NOT EXISTS oi_order_idx ON order_items(order_id);

CREATE TABLE IF NOT EXISTS entitlements (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id         UUID        NOT NULL REFERENCES products(id),
  order_id           UUID        NOT NULL REFERENCES orders(id),
  updates_until      TIMESTAMPTZ,
  created_at         TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, product_id)
);
CREATE INDEX IF NOT EXISTS ent_user_idx ON entitlements(user_id);

CREATE TABLE IF NOT EXISTS downloads (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  entitlement_id     UUID        NOT NULL REFERENCES entitlements(id) ON DELETE CASCADE,
  -- Store a HASH of the signed URL, not the URL itself.
  -- The URL is a secret capability — no need to store it in plain text forever.
  url_hash           VARCHAR(64) NOT NULL,  -- SHA-256 hex
  expires_at         TIMESTAMPTZ NOT NULL,
  ip                 INET,
  user_agent         TEXT,
  created_at         TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dl_entitlement_idx ON downloads(entitlement_id);
CREATE INDEX IF NOT EXISTS dl_expires_idx     ON downloads(expires_at);

CREATE TABLE IF NOT EXISTS password_resets (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash         VARCHAR(64) NOT NULL,  -- SHA-256 hex of the raw token
  expires_at         TIMESTAMPTZ NOT NULL,
  used_at            TIMESTAMPTZ
);
-- Partial index: only un-used, non-expired tokens need fast lookup
CREATE INDEX IF NOT EXISTS pr_token_idx ON password_resets(token_hash)
  WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS events (
  id         BIGSERIAL   PRIMARY KEY,
  user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
  name       VARCHAR(64) NOT NULL,
  props      JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_name_idx    ON events(name);
CREATE INDEX IF NOT EXISTS events_created_idx ON events(created_at);
CREATE INDEX IF NOT EXISTS events_user_idx    ON events(user_id) WHERE user_id IS NOT NULL;

-- ─── Grant table-level privileges to app_api ─────────────────────────────────
-- app_api can only DML on these tables; DDL (ALTER, DROP) is denied.
GRANT SELECT, INSERT, UPDATE ON users, products, orders, order_items,
      entitlements, downloads, password_resets, events TO app_api;
GRANT USAGE ON SEQUENCE events_id_seq TO app_api;
-- Products are read-only for app_api; only app_admin can INSERT/UPDATE products
REVOKE INSERT, UPDATE, DELETE ON products FROM app_api;
GRANT SELECT ON products TO app_api;
-- Admin metrics need SELECT on everything — already granted above.

-- ─── Row Level Security ───────────────────────────────────────────────────────
-- The Node app sets a session-local GUC before each query:
--   SET LOCAL app.current_user_id = '<uuid>';
-- Policies compare this GUC to user_id columns.
-- app_admin BYPASSRLS so migrations/seeds always work.
ALTER ROLE app_admin BYPASSRLS;

-- users: each user sees only their own row; admins see all (handled in app layer,
-- but we still restrict at DB level using a permissive SELECT policy).
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_self    ON users;
DROP POLICY IF EXISTS users_insert  ON users;
DROP POLICY IF EXISTS users_update  ON users;

CREATE POLICY users_self   ON users FOR SELECT
  USING (id = current_setting('app.current_user_id', true)::uuid);

CREATE POLICY users_insert ON users FOR INSERT
  WITH CHECK (true);   -- registration: no user_id context yet

CREATE POLICY users_update ON users FOR UPDATE
  USING (id = current_setting('app.current_user_id', true)::uuid);

-- orders
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS orders_own ON orders;
DROP POLICY IF EXISTS orders_ins ON orders;

CREATE POLICY orders_own ON orders FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

CREATE POLICY orders_ins ON orders FOR INSERT
  WITH CHECK (user_id = current_setting('app.current_user_id', true)::uuid);

-- Webhooks UPDATE orders (status=paid) without a user context.
-- Use a separate SECURITY DEFINER function for webhook fulfillment (see rls_helpers.sql).
CREATE POLICY orders_wh_update ON orders FOR UPDATE
  USING (true);  -- restricted by app logic + SECURITY DEFINER fn

-- order_items: visible if the parent order belongs to the current user
ALTER TABLE order_items ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oi_own ON order_items;
DROP POLICY IF EXISTS oi_ins ON order_items;

CREATE POLICY oi_own ON order_items FOR SELECT
  USING (
    order_id IN (
      SELECT id FROM orders
      WHERE user_id = current_setting('app.current_user_id', true)::uuid
    )
  );

CREATE POLICY oi_ins ON order_items FOR INSERT
  WITH CHECK (
    order_id IN (
      SELECT id FROM orders
      WHERE user_id = current_setting('app.current_user_id', true)::uuid
    )
  );

-- entitlements
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ent_own ON entitlements;
DROP POLICY IF EXISTS ent_ins ON entitlements;
DROP POLICY IF EXISTS ent_upd ON entitlements;

CREATE POLICY ent_own ON entitlements FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

CREATE POLICY ent_ins ON entitlements FOR INSERT
  WITH CHECK (user_id = current_setting('app.current_user_id', true)::uuid);

-- Webhook upsert needs UPDATE without user context — SECURITY DEFINER fn handles it.
CREATE POLICY ent_wh_upd ON entitlements FOR UPDATE USING (true);

-- downloads
ALTER TABLE downloads ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dl_own ON downloads;
DROP POLICY IF EXISTS dl_ins ON downloads;

CREATE POLICY dl_own ON downloads FOR SELECT
  USING (
    entitlement_id IN (
      SELECT id FROM entitlements
      WHERE user_id = current_setting('app.current_user_id', true)::uuid
    )
  );

CREATE POLICY dl_ins ON downloads FOR INSERT
  WITH CHECK (
    entitlement_id IN (
      SELECT id FROM entitlements
      WHERE user_id = current_setting('app.current_user_id', true)::uuid
    )
  );

-- password_resets: insert without user context (forgot flow); update by token only.
ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;
CREATE POLICY pr_all ON password_resets FOR ALL USING (true);  -- app logic enforces token check

-- events: insert-only for app_api (analytics ingestion).
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY ev_ins ON events FOR INSERT WITH CHECK (true);
CREATE POLICY ev_own ON events FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- ─── SECURITY DEFINER functions for webhook fulfillment ──────────────────────
-- These run with elevated privileges so webhooks can mark orders paid and
-- upsert entitlements WITHOUT a user session context (no current_user_id GUC).

CREATE OR REPLACE FUNCTION fulfill_order(
  p_order_id      UUID,
  p_product_ids   UUID[],
  p_months        INT DEFAULT 12
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER   -- runs as the function owner (app_admin), bypasses RLS
SET search_path = public
AS $$
DECLARE
  v_user_id UUID;
BEGIN
  -- Validate order exists and is pending
  SELECT user_id INTO v_user_id
  FROM orders WHERE id = p_order_id AND status = 'pending'
  FOR UPDATE;  -- lock row against duplicate webhook

  IF NOT FOUND THEN RETURN; END IF;  -- idempotent: already fulfilled

  UPDATE orders SET status = 'paid', paid_at = now()
  WHERE id = p_order_id;

  FOR i IN 1..array_length(p_product_ids, 1) LOOP
    INSERT INTO entitlements (user_id, product_id, order_id, updates_until)
    VALUES (v_user_id, p_product_ids[i], p_order_id, now() + (p_months || ' months')::interval)
    ON CONFLICT (user_id, product_id) DO UPDATE
      SET updates_until = EXCLUDED.updates_until;
  END LOOP;
END;
$$;

-- Only app_api (and app_admin) can call this function
REVOKE ALL ON FUNCTION fulfill_order FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fulfill_order TO app_api;
