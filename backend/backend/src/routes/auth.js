import crypto from 'node:crypto';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { q } from '../db/index.js';
import { verifyRefreshToken } from '../lib/jwt.js';
import { issueTokenPair, clearTokenCookies, REFRESH_COOKIE } from '../lib/tokens.js';
import { checkPassword } from '../lib/auth-helpers.js';
import { sendWelcome, sendReset, sendVerification } from '../lib/email.js';
import bcrypt from 'bcryptjs';

const r = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60_000, max: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: req => req.ip,
  handler: (_req, res) =>
    res.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos.' }),
});

// ── POST /auth/register ───────────────────────────────────────────────────
r.post('/register', authLimiter, async (req, res, next) => {
  try {
    const { email, password, name } = z.object({
      email:    z.string().email().max(255).toLowerCase(),
      password: z.string().min(8).max(128),
      name:     z.string().min(2).max(120).trim(),
    }).parse(req.body);

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await q(
      `INSERT INTO users (email, password_hash, name)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO NOTHING
       RETURNING id, email, name, role`,
      [email, hash, name]
    );

    if (!rows[0]) return res.status(200).json({ ok: true, requiresVerification: true });
    const u = rows[0];

    // Issue verification token
    const rawToken  = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    await q(
      `INSERT INTO email_verifications (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '24 hours')`,
      [u.id, tokenHash]
    );
    sendVerification(u.email, u.name,
      `${process.env.APP_URL}/verify-email?token=${rawToken}`
    ).catch(() => {});

    // Issue token pair — user can browse but checkout blocked until verified
    const userOut = await issueTokenPair(res, u);
    res.status(201).json({ user: userOut, requiresVerification: true });
  } catch (e) { next(e); }
});

// ── POST /auth/login ──────────────────────────────────────────────────────
r.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = z.object({
      email:    z.string().email().max(255).toLowerCase(),
      password: z.string().min(1).max(128),
    }).parse(req.body);

    const { rows } = await q(
      `SELECT id, email, name, role, password_hash, email_verified_at, deleted_at
       FROM users WHERE email = $1`,
      [email]
    );
    const u = rows[0];
    const ok = await checkPassword(password, u?.password_hash);
    if (!ok || !u || u.deleted_at)
      return res.status(401).json({ error: 'Credenciales inválidas' });

    await q(`UPDATE users SET last_login_at = now() WHERE id = $1`, [u.id]);
    const userOut = await issueTokenPair(res, u);
    res.json({ user: userOut, emailVerified: !!u.email_verified_at });
  } catch (e) { next(e); }
});

// ── POST /auth/refresh ────────────────────────────────────────────────────
// Called automatically by the client when the 15-min access token expires.
// Uses the 30-day refresh cookie (only sent to this exact path).
r.post('/refresh', async (req, res, next) => {
  try {
    const rawJwt = req.signedCookies?.[REFRESH_COOKIE];
    if (!rawJwt) return res.status(401).json({ error: 'No autenticado', code: 'NO_REFRESH' });

    let payload;
    try {
      payload = verifyRefreshToken(rawJwt);
    } catch {
      clearTokenCookies(res);
      return res.status(401).json({ error: 'Refresh token inválido', code: 'INVALID_REFRESH' });
    }

    const { raw, family } = payload;
    const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');

    // ── Reuse detection ───────────────────────────────────────────────────
    // If a token that was already used (used_at IS NOT NULL) is presented again,
    // it means the old token was stolen and replayed. Revoke the ENTIRE family.
    const { rows: [storedToken] } = await q(
      `SELECT id, user_id, used_at, revoked_at, expires_at
       FROM refresh_tokens
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (!storedToken) {
      clearTokenCookies(res);
      return res.status(401).json({ error: 'Token desconocido', code: 'UNKNOWN_REFRESH' });
    }

    if (storedToken.used_at || storedToken.revoked_at) {
      // ⚠️  TOKEN REUSE DETECTED — revoke the entire family
      await q(
        `UPDATE refresh_tokens SET revoked_at = now()
         WHERE family = $1 AND revoked_at IS NULL`,
        [family]
      );
      clearTokenCookies(res);
      // TODO: send security alert email to user
      return res.status(401).json({
        error: 'Sesión comprometida. Por seguridad, inicia sesión de nuevo.',
        code:  'TOKEN_REUSE_DETECTED',
      });
    }

    if (new Date(storedToken.expires_at) < new Date()) {
      clearTokenCookies(res);
      return res.status(401).json({ error: 'Sesión expirada', code: 'REFRESH_EXPIRED' });
    }

    // ── Rotate: mark old token used, issue new pair ───────────────────────
    const pool = (await import('../db/index.js')).default;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Mark current token as used (single-use enforcement)
      await client.query(
        `UPDATE refresh_tokens SET used_at = now() WHERE id = $1`,
        [storedToken.id]
      );
      // Get user data
      const { rows: [user] } = await client.query(
        `SELECT id, email, name, role, deleted_at FROM users WHERE id = $1`,
        [storedToken.user_id]
      );
      if (!user || user.deleted_at) {
        await client.query('ROLLBACK');
        clearTokenCookies(res);
        return res.status(401).json({ error: 'Usuario no encontrado' });
      }
      await client.query('COMMIT');

      // Issue new token pair in the same family (rotation chain)
      const userOut = await issueTokenPair(res, user, family);
      res.json({ user: userOut });
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }
  } catch (e) { next(e); }
});

// ── POST /auth/logout ─────────────────────────────────────────────────────
r.post('/logout', async (req, res, next) => {
  try {
    // Revoke the refresh token in DB if we can identify it
    const rawJwt = req.signedCookies?.[REFRESH_COOKIE];
    if (rawJwt) {
      try {
        const { raw } = verifyRefreshToken(rawJwt);
        const hash = crypto.createHash('sha256').update(raw).digest('hex');
        await q(
          `UPDATE refresh_tokens SET revoked_at = now()
           WHERE token_hash = $1 AND revoked_at IS NULL`,
          [hash]
        );
      } catch { /* token already invalid — fine */ }
    }
    clearTokenCookies(res);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ── GET /auth/verify?token= ───────────────────────────────────────────────
r.get('/verify', authLimiter, async (req, res, next) => {
  try {
    const { token } = z.object({
      token: z.string().length(64).regex(/^[0-9a-f]+$/),
    }).parse(req.query);

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await q(
      `SELECT ev.id, ev.user_id FROM email_verifications ev
       WHERE ev.token_hash = $1 AND ev.used_at IS NULL AND ev.expires_at > now()`,
      [tokenHash]
    );
    if (!rows[0])
      return res.status(400).json({ error: 'El link de verificación es inválido o ya expiró.', code: 'INVALID_VERIFY_TOKEN' });

    const pool = (await import('../db/index.js')).default;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE users SET email_verified_at = now() WHERE id = $1`, [rows[0].user_id]);
      await client.query(`UPDATE email_verifications SET used_at = now() WHERE id = $1`, [rows[0].id]);
      await client.query('COMMIT');
    } catch (txErr) { await client.query('ROLLBACK'); throw txErr; }
    finally { client.release(); }

    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ── POST /auth/resend-verification ────────────────────────────────────────
r.post('/resend-verification', authLimiter, async (req, res, next) => {
  try {
    const { email } = z.object({ email: z.string().email().toLowerCase() }).parse(req.body);
    const { rows } = await q(
      `SELECT id, name, email_verified_at FROM users WHERE email = $1 AND deleted_at IS NULL`, [email]);
    if (rows[0] && !rows[0].email_verified_at) {
      await q(`UPDATE email_verifications SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`, [rows[0].id]);
      const raw  = crypto.randomBytes(32).toString('hex');
      const hash = crypto.createHash('sha256').update(raw).digest('hex');
      await q(`INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES ($1,$2, now() + interval '24 hours')`, [rows[0].id, hash]);
      sendVerification(email, rows[0].name, `${process.env.APP_URL}/verify-email?token=${raw}`).catch(() => {});
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ── POST /auth/forgot ─────────────────────────────────────────────────────
r.post('/forgot', authLimiter, async (req, res, next) => {
  try {
    const { email } = z.object({ email: z.string().email().max(255).toLowerCase() }).parse(req.body);
    const { rows } = await q(`SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`, [email]);
    if (rows[0]) {
      await q(`UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`, [rows[0].id]);
      const raw  = crypto.randomBytes(32).toString('hex');
      const hash = crypto.createHash('sha256').update(raw).digest('hex');
      await q(`INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2, now() + interval '1 hour')`, [rows[0].id, hash]);
      sendReset(email, `${process.env.APP_URL}/reset?token=${raw}`).catch(() => {});
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ── POST /auth/reset ──────────────────────────────────────────────────────
r.post('/reset', authLimiter, async (req, res, next) => {
  try {
    const { token, password } = z.object({
      token:    z.string().length(64).regex(/^[0-9a-f]+$/),
      password: z.string().min(8).max(128),
    }).parse(req.body);
    const hash   = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await q(
      `SELECT pr.id, pr.user_id FROM password_resets pr
       WHERE pr.token_hash = $1 AND pr.used_at IS NULL AND pr.expires_at > now()`, [hash]);
    const pwHash = await bcrypt.hash(password, 12);
    if (!rows[0]) return res.status(400).json({ error: 'Token inválido o expirado' });

    const pool = (await import('../db/index.js')).default;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [pwHash, rows[0].user_id]);
      await client.query(`UPDATE password_resets SET used_at = now() WHERE id = $1`, [rows[0].id]);
      // Revoke all refresh tokens for this user (password changed = all sessions invalid)
      await client.query(`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, [rows[0].user_id]);
      await client.query('COMMIT');
    } catch (txErr) { await client.query('ROLLBACK'); throw txErr; }
    finally { client.release(); }
    res.json({ ok: true });
  } catch (e) { next(e); }
});

export default r;
