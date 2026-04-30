import crypto from 'node:crypto';
import { q } from '../db/index.js';
import { signRefreshToken } from './jwt.js';

// Cookie names — separate cookies for access and refresh tokens
export const ACCESS_COOKIE  = '__Host-session';     // 15 min, readable by requireAuth
export const REFRESH_COOKIE = '__Host-refresh';     // 30 days, httpOnly, Secure, Path=/auth/refresh

// Access token cookie: short-lived, sent on every request
export const accessCookieOpts = {
  httpOnly: true,
  secure:   true,
  sameSite: 'strict',
  signed:   true,
  path:     '/',
  maxAge:   15 * 60 * 1000,   // 15 minutes
};

// Refresh token cookie: long-lived, but scoped to /auth/refresh ONLY.
// The browser will NOT send this cookie on any other route.
// This limits the attack surface if XSS somehow reads request headers.
export const refreshCookieOpts = {
  httpOnly: true,
  secure:   true,
  sameSite: 'strict',
  signed:   true,
  path:     '/auth/refresh',   // ← key: browser only sends it to this exact path
  maxAge:   30 * 24 * 60 * 60 * 1000,  // 30 days
};

/**
 * Issue a new refresh token, store its hash in DB, set both cookies.
 * family: UUID that groups tokens in a rotation chain. Pass existing family
 *         when rotating, generate a new one for fresh logins.
 */
export async function issueTokenPair(res, user, family = crypto.randomUUID()) {
  // 1. Generate opaque refresh token (32 random bytes → hex)
  const rawRefresh  = crypto.randomBytes(32).toString('hex');
  const refreshHash = crypto.createHash('sha256').update(rawRefresh).digest('hex');

  // 2. Store hashed refresh token
  await q(
    `INSERT INTO refresh_tokens (user_id, token_hash, family, expires_at)
     VALUES ($1, $2, $3, now() + interval '30 days')`,
    [user.id, refreshHash, family]
  );

  // 3. Sign a short-lived access JWT
  const { signAccessToken, signRefreshToken } = await import('./jwt.js');
  const accessJwt  = signAccessToken({ sub: user.id, role: user.role, email: user.email });
  // Refresh JWT carries the raw token so we can look it up and family for reuse detection
  const refreshJwt = signRefreshToken({ raw: rawRefresh, family });

  // 4. Set cookies
  res.cookie(ACCESS_COOKIE,  accessJwt,  accessCookieOpts);
  res.cookie(REFRESH_COOKIE, refreshJwt, refreshCookieOpts);

  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

/**
 * Clear both cookies (logout).
 */
export function clearTokenCookies(res) {
  res.clearCookie(ACCESS_COOKIE,  { ...accessCookieOpts,  maxAge: 0 });
  res.clearCookie(REFRESH_COOKIE, { ...refreshCookieOpts, maxAge: 0 });
}
