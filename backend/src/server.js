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

// ─── Trust Railway/Render proxy so req.ip = real client IP ─────────────────
// Required for rate-limiter accuracy; set to 1 (one proxy hop).
// If behind multiple proxies, increase accordingly — but NOT to 'true'.
app.set('trust proxy', 1);

// ── Structured request logging ─────────────────────────────────────────────
// Mount FIRST so every request gets logged, including ones that fail early.
app.use(requestLogger);

// ─── Helmet — full hardened header suite ────────────────────────────────────
app.use(helmet({
  // Content-Security-Policy — this is a pure API; lock it down hard.
  // A browser hitting this API should run zero scripts from it.
  contentSecurityPolicy: {
    directives: {
      defaultSrc:          ["'none'"],
      scriptSrc:           ["'none'"],
      styleSrc:            ["'none'"],
      imgSrc:              ["'none'"],
      connectSrc:          ["'none'"],
      fontSrc:             ["'none'"],
      objectSrc:           ["'none'"],
      mediaSrc:            ["'none'"],
      frameSrc:            ["'none'"],
      frameAncestors:      ["'none'"],   // prevents clickjacking
      baseUri:             ["'none'"],
      formAction:          ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // HSTS — force HTTPS for 2 years, all subdomains, submit to preload list
  strictTransportSecurity: {
    maxAge: 63_072_000,   // 2 years in seconds
    includeSubDomains: true,
    preload: true,
  },
  // X-Content-Type-Options: nosniff — prevent MIME-type sniffing attacks
  noSniff: true,
  // X-Frame-Options: DENY — belt-and-suspenders with CSP frameAncestors
  frameguard: { action: 'deny' },
  // Referrer-Policy — don't leak path info cross-origin
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Remove X-Powered-By: Express fingerprint
  hidePoweredBy: true,
  // Cross-Origin headers — isolate this API from cross-origin embedding
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy:   { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  // Prevent Adobe/Flash cross-domain policy files
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  // X-DNS-Prefetch-Control: off — no prefetch from browsers
  dnsPrefetchControl: { allow: false },
}));

// Permissions-Policy — disable every browser feature this API doesn't need.
// Helmet doesn't set this header yet; add it manually.
app.use((_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',          // even though we process payments, we don't use the Payment Request API
      'usb=()',
      'interest-cohort=()',  // opt out of FLoC
      'browsing-topics=()',  // opt out of Topics API
      'display-capture=()',
      'screen-wake-lock=()',
    ].join(', ')
  );
  next();
});

// ── Request ID for tracing ────────────────────────────────────────────────
app.use((req, res, next) => {
  const incoming = (req.headers['x-request-id'] || '').replace(/[^\w-]/g, '').slice(0, 64);
  req.id = incoming || crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// ─── CORS ─────────────────────────────────────────────────────────────────
// Allow only the explicit origins in APP_URL (comma-separated for staging + prod).
// Anything else — including requests with no Origin — is rejected in production.

const ALLOWED_ORIGINS = new Set(
  (process.env.APP_URL || '')
    .split(',')
    .map(s => s.trim().replace(/\/$/, ''))   // strip trailing slash
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, cb) {
    // No Origin header: non-browser requests (curl, Postman, server-to-server).
    // Allow in dev only. In production, require an explicit Origin.
    if (!origin) {
      return process.env.NODE_ENV !== 'production'
        ? cb(null, true)
        : cb(Object.assign(new Error('CORS: no Origin header'), { status: 403 }));
    }
    // Normalise: strip trailing slash, compare lowercase
    const norm = origin.trim().replace(/\/$/, '');
    if (ALLOWED_ORIGINS.has(norm)) return cb(null, true);
    // Never reveal the list of allowed origins in the error message
    cb(Object.assign(new Error('CORS: origin not allowed'), { status: 403 }));
  },
  credentials: true,    // required for cookie-based auth
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Request-ID'],
  exposedHeaders: ['X-RateLimit-Remaining', 'X-Request-ID'],
  maxAge: 86_400,       // cache preflight for 24h — reduces OPTIONS noise
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));   // handle preflight for all routes

// ─── Webhooks — raw body BEFORE json parser ──────────────────────────────────
// Stripe signature verification requires the raw Buffer body.
// Mount these routes before express.json() strips the raw body.
app.use('/webhooks/stripe',
  express.raw({ type: 'application/json', limit: '64kb' }),
  stripeWH
);
app.use('/webhooks/mercadopago',
  express.json({ limit: '64kb' }),
  mpWH
);

// ─── Body parsing ────────────────────────────────────────────────────────────
app.use(express.json({ limit: '32kb' }));   // tight limit — no large uploads expected
app.use(cookieParser(process.env.COOKIE_SECRET));

// ─── Rate limiting ───────────────────────────────────────────────────────────
// Global: 120 req/min per IP. Individual routes add stricter limits on top.
app.use(rateLimit({
  windowMs:        60_000,
  max:             120,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
  keyGenerator:    req => req.ip,
  skip:            req => req.path === '/health',
  handler:         (_req, res) =>
    res.status(429).json({ error: 'Demasiadas solicitudes. Intenta en un momento.' }),
}));

// ─── Routes ──────────────────────────────────────────────────────────────────
// Health — expose NOTHING about the system (no version, no uptime).
app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

app.use('/auth',      auth);
app.use('/products',  products);
app.use('/checkout',  checkout);
app.use('/orders',    orders);
app.use('/downloads', downloads);
app.use('/admin',     admin);

// ─── 404 catch-all ───────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

app.use(errorHandler);

const port = Number(process.env.PORT) || 3000;
app.listen(port, () =>
  logger.info({ port, env: process.env.NODE_ENV }, 'API started')
);
