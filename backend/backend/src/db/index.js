import pg from 'pg';
import crypto from 'node:crypto';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

/**
 * Simple query — no RLS context (use for public data: products, webhook fulfillment via SECURITY DEFINER fn).
 */
export const q = (text, params) => pool.query(text, params);

/**
 * RLS-scoped query: wraps the query in a transaction and sets
 * app.current_user_id so Postgres RLS policies can enforce row ownership.
 *
 * Usage: await qs(userId, 'SELECT * FROM orders WHERE user_id=$1', [userId])
 *
 * IMPORTANT: every query that touches user-owned rows MUST use qs(), not q().
 */
export async function qs(userId, text, params) {
  const client = await pool.connect();
  try {
    // SET LOCAL only lasts for the duration of the transaction — safe with connection pooling.
    await client.query('BEGIN');
    await client.query(
      `SELECT set_config('app.current_user_id', $1, true)`,  // true = transaction-local
      [userId]
    );
    const result = await client.query(text, params);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * UUID v4 guard — call before passing route params to DB queries.
 * Prevents Postgres errors from malformed UUIDs leaking stack traces.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function assertUUID(value, label = 'id') {
  if (!UUID_RE.test(value)) {
    const err = new Error(`${label} inválido`);
    err.status = 400;
    throw err;
  }
}

export default pool;
