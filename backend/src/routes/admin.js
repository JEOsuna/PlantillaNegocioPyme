import { Router } from 'express';
import { q, assertUUID } from '../db/index.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { sendRefundConfirmation } from '../lib/email.js';
import Stripe from 'stripe';
import { z } from 'zod';

const r = Router();
r.use(requireAuth, requireAdmin);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ── /admin/metrics ────────────────────────────────────────────────────────
r.get('/metrics', async (req, res, next) => {
  try {
    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);
    const [
      { rows: [rev] }, { rows: [ord] }, { rows: [cust] },
      { rows: mix },   { rows: daily },
    ] = await Promise.all([
      q(`SELECT COALESCE(SUM(total_mxn_cents),0)::int AS cents FROM orders
         WHERE status='paid' AND paid_at > now() - ($1 || ' days')::interval`, [days]),
      q(`SELECT COUNT(*)::int AS n, ROUND(AVG(total_mxn_cents))::int AS avg FROM orders
         WHERE status='paid' AND paid_at > now() - ($1 || ' days')::interval`, [days]),
      q(`SELECT COUNT(DISTINCT user_id)::int AS n FROM orders WHERE status='paid'`),
      q(`SELECT p.name, p.slug, COUNT(*)::int AS n, SUM(oi.unit_price_cents)::int AS revenue
         FROM order_items oi
         JOIN products p ON p.id = oi.product_id
         JOIN orders   o ON o.id = oi.order_id AND o.status='paid'
           AND o.paid_at > now() - ($1 || ' days')::interval
         GROUP BY p.name, p.slug ORDER BY n DESC`, [days]),
      q(`SELECT DATE_TRUNC('day', paid_at)::date AS day,
                COUNT(*)::int AS orders, SUM(total_mxn_cents)::int AS revenue
         FROM orders WHERE status='paid'
           AND paid_at > now() - ($1 || ' days')::interval
         GROUP BY 1 ORDER BY 1`, [days]),
    ]);
    res.json({ period_days: days, revenue_mxn: rev.cents/100,
               orders_n: ord.n, aov_mxn: (ord.avg||0)/100,
               customers_total: cust.n, product_mix: mix, daily });
  } catch (e) { next(e); }
});

// ── /admin/orders ─────────────────────────────────────────────────────────
r.get('/orders', async (req, res, next) => {
  try {
    const limit  = Math.min(Number(req.query.limit) || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const status = ['pending','paid','refunded','failed'].includes(req.query.status)
      ? req.query.status : null;
    const { rows } = await q(
      `SELECT o.id, o.total_mxn_cents, o.status, o.gateway, o.paid_at, o.created_at,
              u.email, u.name
       FROM orders o JOIN users u ON u.id = o.user_id
       WHERE ($1::text IS NULL OR o.status = $1)
       ORDER BY o.created_at DESC LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );
    res.json({ orders: rows });
  } catch (e) { next(e); }
});

// ── /admin/orders/:id/refund ──────────────────────────────────────────────
// BLOCKER FIX: full Mercado Pago refund support via their Payments API.
r.post('/orders/:id/refund', async (req, res, next) => {
  try {
    assertUUID(req.params.id, 'order id');

    const { reason } = z.object({
      reason: z.string().max(500).optional(),
    }).parse(req.body || {});

    // Fetch order + user info + product names for the refund email
    const { rows } = await q(
      `SELECT o.id, o.gateway, o.gateway_id, o.mp_payment_id,
              o.total_mxn_cents, o.status,
              u.email, u.name,
              array_agg(p.name) AS product_names
       FROM orders o
       JOIN users u ON u.id = o.user_id
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.id = $1
       GROUP BY o.id, u.email, u.name`,
      [req.params.id]
    );
    const o = rows[0];
    if (!o)              return res.status(404).json({ error: 'Orden no existe' });
    if (o.status !== 'paid')
                         return res.status(409).json({ error: 'Solo se reembolsan órdenes pagadas' });

    // ── Stripe refund ─────────────────────────────────────────────────────
    if (o.gateway === 'stripe') {
      const session = await stripe.checkout.sessions.retrieve(
        o.gateway_id, { expand: ['payment_intent'] }
      );
      await stripe.refunds.create({
        payment_intent: session.payment_intent.id,
        ...(reason && { metadata: { note: reason } }),
      });
    }

    // ── Mercado Pago refund ───────────────────────────────────────────────
    // Requires the MP payment ID stored in orders.mp_payment_id.
    // This is populated by the MP webhook (see webhooks/mercadopago.js).
    if (o.gateway === 'mp') {
      if (!o.mp_payment_id) {
        return res.status(422).json({
          error: 'No se encontró el ID de pago de Mercado Pago. Reembolsa manualmente en el panel de MP.',
          mp_panel_url: 'https://www.mercadopago.com.mx/activities',
        });
      }
      // MP Refunds API: POST /v1/payments/{id}/refunds
      const mpResp = await fetch(
        `https://api.mercadopago.com/v1/payments/${o.mp_payment_id}/refunds`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}`,
            'Content-Type':  'application/json',
            'X-Idempotency-Key': o.id,   // prevent duplicate refunds on retry
          },
          // Partial refund not supported in this flow — always full refund
          body: JSON.stringify({}),
        }
      );
      if (!mpResp.ok) {
        const err = await mpResp.json().catch(() => ({}));
        console.error('[mp-refund] failed', err);
        return res.status(502).json({
          error: 'Mercado Pago rechazó el reembolso. Verifica el panel de MP.',
          mp_error: err?.message || 'unknown',
        });
      }
    }

    // ── Update DB + revoke entitlements atomically ────────────────────────
    const pool = (await import('../db/index.js')).default;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `UPDATE orders SET status = 'refunded' WHERE id = $1`, [o.id]);
      await client.query(
        `DELETE FROM entitlements WHERE order_id = $1`, [o.id]);
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }

    // Send refund confirmation email (fire-and-forget)
    sendRefundConfirmation(o.email, {
      orderId: o.id,
      total:   o.total_mxn_cents,
      items:   o.product_names,
    }).catch(err => console.error('[email] refund confirmation failed', err));

    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ── /admin/customers ──────────────────────────────────────────────────────
r.get('/customers', async (req, res, next) => {
  try {
    const limit  = Math.min(Number(req.query.limit) || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const { rows } = await q(
      `SELECT u.id, u.email, u.name, u.role, u.created_at,
              u.last_login_at, u.email_verified_at,
              COUNT(DISTINCT o.id)::int AS orders,
              COALESCE(SUM(o.total_mxn_cents) FILTER (WHERE o.status='paid'),0)::int AS ltv_cents
       FROM users u
       LEFT JOIN orders o ON o.user_id = u.id
       WHERE u.deleted_at IS NULL
       GROUP BY u.id ORDER BY u.created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    res.json({ customers: rows });
  } catch (e) { next(e); }
});

export default r;
