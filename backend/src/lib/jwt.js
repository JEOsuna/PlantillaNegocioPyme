import jwt from 'jsonwebtoken';

const ACCESS_SECRET  = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Access token: short-lived (15 min). Stateless — verified via signature only.
export const signAccessToken = (payload) =>
  jwt.sign(payload, ACCESS_SECRET, { expiresIn: '15m' });

// Refresh token: long-lived (30 days). Opaque JWT used only to call /auth/refresh.
// The actual DB record (hashed) is what's authoritative — this JWT is just a carrier.
export const signRefreshToken = (payload) =>
  jwt.sign(payload, REFRESH_SECRET, { expiresIn: '30d' });

export const verifyAccessToken  = (token) => jwt.verify(token, ACCESS_SECRET);
export const verifyRefreshToken = (token) => jwt.verify(token, REFRESH_SECRET);

// Legacy alias — keep for any remaining callers during transition
export const signToken   = signAccessToken;
export const verifyToken = verifyAccessToken;
