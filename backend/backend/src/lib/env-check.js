/**
 * env-check.js — Startup validation of required environment variables.
 * Import this FIRST in server.js, before any other module.
 *
 * If any required variable is missing or obviously wrong,
 * the process exits with a clear message instead of crashing later
 * with a cryptic runtime error mid-request.
 */

// Add to REQUIRED array in env-check.js:
// { key: 'JWT_REFRESH_SECRET', hint: 'openssl rand -hex 32', minLen: 32 },

const REQUIRED = [
  // Database
  { key: 'DATABASE_URL',          hint: 'postgres://user:pass@host/db?sslmode=require' },
  // Auth
  { key: 'JWT_SECRET',            hint: 'openssl rand -hex 32', minLen: 32 },
  { key: 'COOKIE_SECRET',         hint: 'openssl rand -hex 32', minLen: 32 },
  // App URLs
  { key: 'APP_URL',               hint: 'https://plantillanegociopyme.com' },
  { key: 'API_URL',               hint: 'https://api.plantillanegociopyme.com' },
  // Stripe
  { key: 'STRIPE_SECRET_KEY',     hint: 'sk_live_... from Stripe dashboard' },
  { key: 'STRIPE_WEBHOOK_SECRET', hint: 'whsec_... from Stripe webhook settings' },
  // Mercado Pago
  { key: 'MP_ACCESS_TOKEN',       hint: 'APP_USR-... from MP credentials' },
  { key: 'MP_WEBHOOK_SECRET',     hint: 'from MP webhook configuration' },
  // Cloudflare R2
  { key: 'R2_ACCOUNT_ID',         hint: 'Cloudflare dashboard → R2 → Account ID' },
  { key: 'R2_ACCESS_KEY_ID',      hint: 'R2 API token' },
  { key: 'R2_SECRET_ACCESS_KEY',  hint: 'R2 API token secret' },
  { key: 'R2_BUCKET',             hint: 'e.g. plantillas' },
  { key: 'R2_ENDPOINT',           hint: 'https://<account_id>.r2.cloudflarestorage.com' },
  // Email
  { key: 'RESEND_API_KEY',        hint: 're_... from Resend dashboard' },
  { key: 'EMAIL_FROM',            hint: 'e.g. [email protected]' },
  { key: 'JWT_REFRESH_SECRET',    hint: 'openssl rand -hex 32 (different from JWT_SECRET)', minLen: 32 },
];

export function checkEnv() {
  const errors = [];

  for (const { key, hint, minLen } of REQUIRED) {
    const val = process.env[key];
    if (!val || val.trim() === '') {
      errors.push(`  ✗ ${key} is missing\n      → ${hint}`);
      continue;
    }
    if (minLen && val.length < minLen) {
      errors.push(`  ✗ ${key} is too short (${val.length} chars, need ≥ ${minLen})\n      → ${hint}`);
    }
  }

  // Extra sanity checks
  if (process.env.JWT_SECRET === process.env.COOKIE_SECRET) {
    errors.push('  ✗ JWT_SECRET and COOKIE_SECRET must be different values');
  }
  if (process.env.NODE_ENV === 'production') {
    if (process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_')) {
      errors.push('  ✗ STRIPE_SECRET_KEY is a TEST key but NODE_ENV=production');
    }
    if (process.env.APP_URL?.includes('localhost')) {
      errors.push('  ✗ APP_URL points to localhost but NODE_ENV=production');
    }
  }

  if (errors.length > 0) {
    console.error('\n╔══════════════════════════════════════════════════════╗');
    console.error('║  STARTUP FAILED — missing or invalid environment vars ║');
    console.error('╚══════════════════════════════════════════════════════╝\n');
    errors.forEach(e => console.error(e));
    console.error('\nCopy .env.example to .env and fill in all values.\n');
    process.exit(1);   // non-zero exit → Railway will mark deployment as failed
  }

  console.log(`[env] ✓ all ${REQUIRED.length} required variables present`);
}
