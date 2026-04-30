// ── errorHandler — updated to use logger ─────────────────────────────────
import { ZodError } from 'zod';
import { logger } from '../lib/logger.js';

export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  if (err instanceof ZodError) {
    const fields = err.errors.map(e => ({
      field:   e.path.join('.') || 'body',
      message: e.message,
      code:    e.code,
    }));
    return res.status(400).json({ error: 'Datos inválidos', fields });
  }

  if (err.message?.startsWith('CORS:'))
    return res.status(403).json({ error: 'Origen no permitido' });

  if (err.status && err.status < 500)
    return res.status(err.status).json({ error: err.message });

  // Postgres error — log internally, never expose
  if (err.code && /^[0-9A-Z]{5}$/.test(err.code)) {
    (req.log || logger).error({ err, reqId: req.id }, 'database error');
    return res.status(500).json({ error: 'Error de base de datos' });
  }

  // Generic 500 — structured log with reqId for Railway tracing
  (req.log || logger).error({
    err:    { message: err.message, stack: err.stack },
    reqId:  req.id,
    method: req.method,
    path:   req.path,
  }, 'unhandled error');

  res.status(500).json({ error: 'Error del servidor' });
}
