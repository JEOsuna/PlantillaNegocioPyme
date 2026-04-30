import { verifyAccessToken } from '../lib/jwt.js';
import { ACCESS_COOKIE }     from '../lib/tokens.js';

export { ACCESS_COOKIE as SESSION_COOKIE };

export const sessionCookieOpts = {
  httpOnly: true, secure: true, sameSite: 'strict', signed: true,
  path: '/', maxAge: 15 * 60 * 1000,
};

export function requireAuth(req, res, next) {
  const token = req.signedCookies?.[ACCESS_COOKIE];
  if (!token)
    return res.status(401).json({ error: 'No autenticado', code: 'NO_SESSION' });
  try {
    const payload = verifyAccessToken(token);
    if (typeof payload.sub !== 'string' || !payload.sub)
      return res.status(401).json({ error: 'Token malformado', code: 'BAD_TOKEN' });
    if (!['customer','admin'].includes(payload.role))
      return res.status(401).json({ error: 'Rol inválido', code: 'BAD_TOKEN' });
    req.user = payload;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Sesión expirada', code: 'TOKEN_EXPIRED' });
    res.status(401).json({ error: 'Sesión inválida', code: 'INVALID_TOKEN' });
  }
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error: 'Acceso restringido', code: 'FORBIDDEN' });
  next();
}
