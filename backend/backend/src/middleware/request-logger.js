/**
 * requestLogger middleware — wraps pino-http.
 *
 * Adds to every request:
 *   - req.log   (child logger with reqId bound)
 *   - req.id    (X-Request-ID, used in all child logs)
 *   - Automatic request start + response end log lines
 *   - Response time in ms
 *   - User ID (if authenticated, bound after requireAuth runs)
 *
 * Log line example (production JSON):
 * {
 *   "level": 30, "time": "2026-04-24T14:22:01.234Z",
 *   "app": "plantilla-api", "reqId": "abc-123",
 *   "req": { "method": "POST", "url": "/checkout" },
 *   "res": { "statusCode": 200 },
 *   "responseTime": 142,
 *   "userId": "uuid...",
 *   "msg": "request completed"
 * }
 */

import pinoHttp from 'pino-http';
import { logger } from '../lib/logger.js';

export const requestLogger = pinoHttp({
  logger,

  // Use the same request ID set in server.js (or generate a new one)
  genReqId(req) {
    return req.headers['x-request-id'] || req.id || crypto.randomUUID();
  },

  // Bind userId to the log if the user is authenticated
  customProps(req) {
    return req.user?.sub ? { userId: req.user.sub } : {};
  },

  // Suppress health check logs — they're too noisy
  autoLogging: {
    ignore: (req) => req.url === '/health',
  },

  // Map HTTP status codes to log levels
  customLogLevel(_req, res, err) {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400)        return 'warn';
    return 'info';
  },

  // What to include from req/res — keep it minimal, no bodies
  serializers: {
    req(req) {
      return {
        method: req.method,
        url:    req.url,
        // Include referer for tracing funnel drop-offs
        referer: req.headers?.referer,
      };
    },
    res(res) {
      return { statusCode: res.statusCode };
    },
  },
});
