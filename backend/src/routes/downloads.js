import { Router } from 'express';
import { q, qs, assertUUID } from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';
import { signDownload } from '../lib/r2.js';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';

const r = Router();

// ── Rate limit: max 20 download URL generations per user per hour ──────────
// Prevents hammering R2 for URL generation (each call signs a new presigned URL).
const dlLimiter = rateLimit({
  windowMs:        60 * 60_000,   // 1 hour
  max:             20,
  keyGenerator:    req => req.user?.sub || req.ip,
  handler:         (_req, res) =>
    res.status(429).json({ error: 'Demasiadas descargas. Intenta más tarde.' }),
});

/** List templates the authenticated user owns (RLS-scoped) */
r.get('/', requireAuth, async (req, res, next) => {
  try {
    // qs() sets app.current_user_id before running the query.
    // Postgres RLS policy on `entitlements` will additionally enforce
    // that only rows with user_id = current_user_id are visible,
    // even if the WHERE clause were accidentally removed.
    const { rows } = await qs(
      req.user.sub,
      `SELECT e.id, p.slug, p.name, p.version
       FROM entitlements e
       JOIN products p ON p.id = e.product_id
       WHERE e.user_id = $1
       ORDER BY e.created_at DESC`,
      [req.user.sub]
    );
    res.json({ templates: rows });
  } catch (e) { next(e); }
});

/** Generate a fresh signed URL for one entitlement the user owns */
r.post('/:entitlementId', requireAuth, dlLimiter, async (req, res, next) => {
  try {
    // ── Validate the route param before it ever touches the DB ────────────
    // assertUUID throws a 400 error for malformed inputs, preventing
    // Postgres from surfacing "invalid input syntax for type uuid" errors.
    assertUUID(req.params.entitlementId, 'entitlementId');

    // ── RLS-scoped query ─────────────────────────────────────────────────
    // The WHERE e.user_id = $2 clause is application-layer authorisation.
    // The Postgres RLS policy on entitlements is the DB-layer defence:
    // if user_id ≠ current_user_id, the row is invisible regardless of the query.
    const { rows } = await qs(
      req.user.sub,
      `SELECT e.id, p.r2_object_key, p.name, p.slug
       FROM entitlements e
       JOIN products p ON p.id = e.product_id
       WHERE e.id = $1 AND e.user_id = $2`,
      [req.params.entitlementId, req.user.sub]
    );

    if (!rows[0]) {
      // Same response for "doesn't exist" and "not yours" — no info leakage
      return res.status(404).json({ error: 'Plantilla no encontrada' });
    }

    const url = await signDownload(rows[0].r2_object_key, 24 * 3600);

    // Store only a hash of the signed URL, not the URL itself.
    // The URL is a time-limited capability token — no need to keep it in plaintext.
    const urlHash = crypto.createHash('sha256').update(url).digest('hex');

    await qs(
      req.user.sub,
      `INSERT INTO downloads (entitlement_id, url_hash, expires_at, ip, user_agent)
       VALUES ($1, $2, now() + interval '24 hours', $3, $4)`,
      [
        rows[0].id,
        urlHash,
        req.ip,
        // Truncate user-agent to prevent unbounded storage
        (req.get('user-agent') || '').slice(0, 512),
      ]
    );

    // Return the URL only once — the client must use it before expiry.
    // We do NOT store it server-side so it can't be leaked from our DB.
    res.json({
      url,
      name:      rows[0].name,
      expiresIn: 24 * 3600,
    });
  } catch (e) { next(e); }
});

export default r;
