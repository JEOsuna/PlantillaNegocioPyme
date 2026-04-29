/**
 * logger.js — Structured logging via Pino
 *
 * In production: outputs newline-delimited JSON to stdout.
 *   Railway captures this and makes it searchable.
 *   Each log line has: time, level, reqId, method, url, statusCode, responseTime, userId.
 *
 * In development: pino-pretty formats it into readable colored output.
 *
 * Usage anywhere in the app:
 *   import logger from '../lib/logger.js';
 *   logger.info({ userId, orderId }, 'Order fulfilled');
 *   logger.error({ err }, 'Stripe webhook failed');
 */

import pino from 'pino';

const isDev = process.env.NODE_ENV !== 'production';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',

  // Rename 'pid' and 'hostname' to keep logs clean; add app name
  base: { app: 'plantilla-api' },

  // ISO timestamp instead of epoch ms
  timestamp: pino.stdTimeFunctions.isoTime,

  // In dev, use pino-pretty for human-readable output
  ...(isDev && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize:        true,
        translateTime:   'HH:MM:ss',
        ignore:          'pid,hostname,app',
        messageFormat:   '{msg} {reqId}',
      },
    },
  }),

  // Redact sensitive fields from ALL log lines, regardless of who logs them.
  // This is a safety net — callers should never log these, but if they do,
  // Pino will replace the value with '[Redacted]'.
  redact: {
    paths: [
      'password', 'password_hash', 'token', 'token_hash',
      'req.headers.authorization',
      'req.headers.cookie',
      'body.password',
      'body.token',
      'body.card_number',
      '*.secret',
      '*.api_key',
    ],
    censor: '[Redacted]',
  },
});

export default logger;
