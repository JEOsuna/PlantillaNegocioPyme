import 'dotenv/config';
import { checkEnv } from './lib/env-check.js';
checkEnv();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import { logger } from './lib/logger.js';
import { requestLogger } from './middleware/request-logger.js';

import auth       from './routes/auth.js';
import products   from './routes/products.js';
import checkout   from './routes/checkout.js';
import orders     from './routes/orders.js';
import downloads  from './routes/downloads.js';
import admin      from './routes/admin.js';
import stripeWH   from './webhooks/stripe.js';
import mpWH       from './webhooks/mercadopago.js';
import { errorHandler } from './middleware/error.js';

const app = express();

// ─── Trust proxy ─────────────────────────────────────
app.set('trust proxy', 1);

// ── Logging ─────────────────────────────────────────
app.use(requestLogger);

// ─── Helmet ─────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'none'"],
      styleSrc: ["'none'"],
      imgSrc: ["'none'"],
      connectSrc: ["'none'"],
      fontSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  strictTransportSecurity: {
    maxAge: 63_072_000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hidePoweredBy: true,
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  dnsPrefetchControl: { allow: false },
}));

app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'interest-cohort=()',
      'browsing-topics=()',
      'display-capture=()',
      'screen-wake-lock=()',
    ].join(', ')
  );
  next();
});

// ── Request ID ─────────────────────────────────────
app.use((req, res, next) => {
  const incoming = (req.headers['x-request-id'] || '').replace(/[^\w-]/g, '').slice(0, 64);
  req.id = incoming || crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// ✅ HEALTH PRIMERO (antes de CORS)
app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

// ─── CORS ───────────────────────────────────────────
const ALLOWED_ORIGINS = new Set(
  (process.env.APP_URL || '')
    .split(',')
    .map(s => s.trim().replace(/\/$/, ''))
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, cb) {
    // ✅ Permitir requests sin origin (curl, navegador directo, healthchecks)
    if (!origin) {
      return cb(null, true);
    }

    const norm = origin.trim().replace(/\/$/, '');
    if (ALLOWED_ORIGINS.has(norm)) return cb(null, true);

    cb(Object.assign(new Error('CORS: origin not allowed'), { status: 403 }));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Request-ID'],
  exposedHeaders: ['X-RateLimit-Remaining', 'X-Request-ID'],
  maxAge: 86_400,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ─── Webhooks ───────────────────────────────────────
app.use('/webhooks/stripe',
  express.raw({ type: 'application/json', limit: '64kb' }),
  stripeWH
);
app.use('/webhooks/mercadopago',
  express.json({ limit: '64kb' }),
  mpWH
);

// ─── Body ───────────────────────────────────────────
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// ─── Rate limit ─────────────────────────────────────
app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: req => req.ip,
  skip: req => req.path === '/health',
  handler: (_req, res) =>
    res.status(429).json({ error: 'Demasiadas solicitudes. Intenta en un momento.' }),
}));

// ─── Routes ─────────────────────────────────────────
app.use('/auth', auth);
app.use('/products', products);
app.use('/checkout', checkout);
app.use('/orders', orders);
app.use('/downloads', downloads);
app.use('/admin', admin);

// ─── 404 ───────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

app.use(errorHandler);

const port = Number(process.env.PORT) || 3000;
app.listen(port, () =>
  logger.info({ port, env: process.env.NODE_ENV }, 'API started')
);
