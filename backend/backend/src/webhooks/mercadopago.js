import { Router } from 'express';
import crypto from 'node:crypto';
import { q } from '../db/index.js';
import { sendReceipt } from '../lib/email.js';

const r = Router();

function verifySignature(req) {
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return process.env.NODE_ENV !== 'production'; // only skip in dev
  const xSig  = req.get('x-signature') || '';
  const reqId = req.get('x-request-id') || '';
  const parts = Object.fromEntries(xSig.split(',').map(p => p.trim().split('=')));
  const dataId = req.body?.data?.id || '';
  const manifest = `id:${dataId};request-id:${reqId};ts:${parts.ts};`;
  const hash = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
  return hash === parts.v1;
}

r.post('/', async (req, res) => {
  if (!verifySignature(req)) {
    console.error('[mp-wh] invalid signature');
    return res.status(400).send('bad signature');
  }

  const type = req.body?.type;
  if (type !== 'payment') return res.json({ ok: true });

  try {
    const { MercadoPagoConfig, Payment } = await import('mercadopago');
    const mp      = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
    const payment = await new Payment(mp).get({ id: req.body.data.id });

    if (payment.status !== 'approved') return res.json({ ok: true });

    const orderId = payment.external_reference;
    if (!orderId) return res.json({ ok: true });

    const { rows } = await q(
      `SELECT o.id, o.user_id, o.total_mxn_cents, u.email,
              array_agg(oi.product_id) AS product_ids,
              array_agg(p.name)        AS names
       FROM orders o
       JOIN users u ON u.id = o.user_id
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.id = $1 GROUP BY o.id, u.email`,
      [orderId]
    );
    const o = rows[0];
    if (!o) return res.json({ ok: true });

    // ── BLOCKER FIX: store MP payment ID so admin can issue refunds ───────
    // Without this, admin.js refund route returns 422 "no mp_payment_id found".
    await q(
      `UPDATE orders SET mp_payment_id = $1 WHERE id = $2`,
      [String(payment.id), orderId]
    );

    // Use SECURITY DEFINER function — idempotent, handles FOR UPDATE lock
    await q(`SELECT fulfill_order($1, $2)`, [orderId, o.product_ids]);

    sendReceipt(o.email, {
      orderId: o.id, total: o.total_mxn_cents, items: o.names,
      downloadUrl: `${process.env.APP_URL}/app/downloads`,
    }).catch(err => console.error('[email] receipt failed', err));

    res.json({ ok: true });
  } catch (err) {
    console.error('[mp-wh] error', err);
    // Return 200 to MP so it doesn't retry immediately on our error
    // Log the failure and investigate; implement dead-letter queue if needed
    res.status(200).json({ ok: false, error: 'internal' });
  }
});

export default r;
