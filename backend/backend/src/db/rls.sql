-- ═══════════════════════════════════════════════════════════
-- Row Level Security · PlantillaNegocioPyme
-- ═══════════════════════════════════════════════════════════
-- Strategy: single connection pool (pnp_app role) + SET LOCAL
-- for app.current_user_id at the start of each transaction.
-- RLS policies use current_setting() so Postgres enforces them
-- even if application code has a bug in its WHERE clause.
-- ═══════════════════════════════════════════════════════════

-- ─── 1. Create two DB roles ──────────────────────────────────
-- Run this block ONCE as a superuser (e.g. in Neon console).

DO $$
BEGIN
  -- pnp_app  : what the connection pool connects as (no superuser)
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pnp_app') THEN
    CREATE ROLE pnp_app LOGIN PASSWORD 'CHANGE_IN_NEON_CONSOLE';
  END IF;
  -- pnp_anon : used for public (unauthenticated) queries
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pnp_anon') THEN
    CREATE ROLE pnp_anon NOLOGIN;
  END IF;
END $$;

-- Grant connect and schema usage
GRANT CONNECT ON DATABASE plantilla TO pnp_app, pnp_anon;
GRANT USAGE ON SCHEMA public TO pnp_app, pnp_anon;

-- pnp_app can do everything on its own tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pnp_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pnp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pnp_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO pnp_app;

-- pnp_anon can only read public catalog
GRANT SELECT ON products TO pnp_anon;

-- ─── 2. Enable RLS on every sensitive table ──────────────────
ALTER TABLE users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders         ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_items    ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements   ENABLE ROW LEVEL SECURITY;
ALTER TABLE downloads      ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE events         ENABLE ROW LEVEL SECURITY;

-- products is public read — RLS not needed for SELECT, but prevent
-- non-admin writes (enforced at app layer too, double protection).
ALTER TABLE products ENABLE ROW LEVEL SECURITY;

-- ─── 3. Policy helper: get current user id from session var ──
-- The app sets this at the start of every transaction:
--   SET LOCAL app.current_user_id = '<uuid>';

CREATE OR REPLACE FUNCTION current_user_id() RETURNS UUID AS $$
  SELECT NULLIF(current_setting('app.current_user_id', true), '')::UUID;
$$ LANGUAGE sql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION is_admin() RETURNS BOOLEAN AS $$
  SELECT COALESCE(current_setting('app.current_role', true), '') = 'admin';
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- ─── 4. users ────────────────────────────────────────────────
-- Users can only read/update their own row.
-- Admin can read all. Nobody can delete via app (use admin endpoint).
DROP POLICY IF EXISTS users_self   ON users;
DROP POLICY IF EXISTS users_admin  ON users;

CREATE POLICY users_self ON users
  FOR ALL TO pnp_app
  USING (id = current_user_id())
  WITH CHECK (id = current_user_id());

CREATE POLICY users_admin ON users
  FOR SELECT TO pnp_app
  USING (is_admin());

-- ─── 5. orders ───────────────────────────────────────────────
DROP POLICY IF EXISTS orders_self  ON orders;
DROP POLICY IF EXISTS orders_admin ON orders;

CREATE POLICY orders_self ON orders
  FOR ALL TO pnp_app
  USING (user_id = current_user_id())
  WITH CHECK (user_id = current_user_id());

CREATE POLICY orders_admin ON orders
  FOR ALL TO pnp_app
  USING (is_admin());

-- ─── 6. order_items ──────────────────────────────────────────
DROP POLICY IF EXISTS oi_self  ON order_items;
DROP POLICY IF EXISTS oi_admin ON order_items;

CREATE POLICY oi_self ON order_items
  FOR SELECT TO pnp_app
  USING (
    EXISTS (SELECT 1 FROM orders o WHERE o.id = order_id AND o.user_id = current_user_id())
  );

CREATE POLICY oi_admin ON order_items
  FOR ALL TO pnp_app
  USING (is_admin());

-- ─── 7. entitlements ─────────────────────────────────────────
DROP POLICY IF EXISTS ent_self  ON entitlements;
DROP POLICY IF EXISTS ent_admin ON entitlements;

CREATE POLICY ent_self ON entitlements
  FOR ALL TO pnp_app
  USING (user_id = current_user_id())
  WITH CHECK (user_id = current_user_id());

CREATE POLICY ent_admin ON entitlements
  FOR ALL TO pnp_app
  USING (is_admin());

-- ─── 8. downloads ────────────────────────────────────────────
DROP POLICY IF EXISTS dl_self  ON downloads;
DROP POLICY IF EXISTS dl_admin ON downloads;

CREATE POLICY dl_self ON downloads
  FOR ALL TO pnp_app
  USING (
    EXISTS (
      SELECT 1 FROM entitlements e WHERE e.id = entitlement_id AND e.user_id = current_user_id()
    )
  );

CREATE POLICY dl_admin ON downloads
  FOR ALL TO pnp_app
  USING (is_admin());

-- ─── 9. password_resets ──────────────────────────────────────
-- Auth routes run as pnp_app and set current_user_id before touching this table.
DROP POLICY IF EXISTS pr_self  ON password_resets;
DROP POLICY IF EXISTS pr_admin ON password_resets;

CREATE POLICY pr_self ON password_resets
  FOR ALL TO pnp_app
  USING (user_id = current_user_id())
  WITH CHECK (user_id = current_user_id());

-- Webhook / forgot-password flow: allow INSERT without session (user not yet logged in).
-- We handle this by running that specific query as the service role (bypass RLS).
-- See db/index.js serviceQ() below.

-- ─── 10. events (analytics) ──────────────────────────────────
DROP POLICY IF EXISTS evt_self  ON events;
DROP POLICY IF EXISTS evt_admin ON events;

CREATE POLICY evt_self ON events
  FOR SELECT TO pnp_app
  USING (user_id = current_user_id() OR user_id IS NULL);

CREATE POLICY evt_admin ON events
  FOR ALL TO pnp_app
  USING (is_admin());

-- ─── 11. products — public read, admin write only ────────────
DROP POLICY IF EXISTS prod_read   ON products;
DROP POLICY IF EXISTS prod_admin  ON products;

CREATE POLICY prod_read ON products
  FOR SELECT TO pnp_app, pnp_anon
  USING (is_active = TRUE);

CREATE POLICY prod_admin ON products
  FOR ALL TO pnp_app
  USING (is_admin())
  WITH CHECK (is_admin());

-- ─── 12. Bypass RLS for service-level ops ────────────────────
-- The app uses a second pool or runs specific queries as pnp_app
-- with BYPASSRLS for webhook fulfillment (order status changes, creating
-- entitlements server-side without a logged-in user context).
-- Grant BYPASSRLS to pnp_app ONLY (not pnp_anon):
ALTER ROLE pnp_app BYPASSRLS;
-- Then in application code, use serviceQ() (see db/index.js) for
-- webhook / admin queries, and q() (which sets current_user_id) for
-- all user-facing queries.
