import bcrypt from 'bcryptjs';
import { SESSION_COOKIE, sessionCookieOpts } from '../middleware/auth.js';
import { signToken } from '../lib/jwt.js';

// Shared helper: issue session cookie + return safe user object
export function issueSession(res, user) {
  const token = signToken({
    sub:   user.id,
    role:  user.role,
    email: user.email,
  });
  // Use the centralised cookie options from middleware/auth.js
  res.cookie(SESSION_COOKIE, token, sessionCookieOpts);
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

// Timing-safe password check — always runs bcrypt even if user not found
// to prevent timing-based user enumeration
export async function checkPassword(candidate, storedHash) {
  if (!storedHash) {
    // Run bcrypt anyway to take constant time
    await bcrypt.compare(candidate, '$2b$12$invalidhashfortimingprotection000000000000000');
    return false;
  }
  return bcrypt.compare(candidate, storedHash);
}
