import { Router } from 'express';
import Stripe from 'stripe';
import { q } from '../db/index.js';
import { sendReceipt } from '../lib/email.js';

const r = Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

r.post('/', async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.get('stripe-signature'),
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[stripe-wh] invalid signature:', err.message);
    return res.status(400).send('Invalid signature');
  }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const orderId = s.metadata?.order_id;
    if (orderId) await fulfill(orderId).catch(e => console.error('[stripe-wh] fulfill failed', e));
  }

  if (event.type === 'charge.refunded') {
    await q(`UPDATE orders SET status='refunded' WHERE gateway_id=$1`, [event.data.object.payment_intent]);
  }

  res.json({ received: true });
});

async function fulfill(orderId) {
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
  if (!o) return;

  // Use SECURITY DEFINER function — handles FOR UPDATE lock + idempotency
  await q(`SELECT fulfill_order($1, $2)`, [orderId, o.product_ids]);

  sendReceipt(o.email, {
    orderId: o.id, total: o.total_mxn_cents, items: o.names,
    downloadUrl: `${process.env.APP_URL}/app/downloads`,
  }).catch(err => console.error('[email] receipt failed', err));
}

export default r;
