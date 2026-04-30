import { Router } from 'express';
import { z } from 'zod';
import { q, assertUUID } from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const r = Router();

// ── POST /checkout ────────────────────────────────────────────────────────
// BLOCKER FIX: block checkout if email not verified.
// Users can register and browse, but cannot pay until they verify their email.
// This prevents someone registering with another person's email and buying on their behalf.

r.post('/', requireAuth, async (req, res, next) => {
  try {
    const { items, gateway } = z.object({
      items: z.array(z.object({
        product_id: z.string().uuid(),
        quantity:   z.number().int().min(1).max(10),
      })).min(1).max(10),
      gateway: z.enum(['stripe', 'mp']),
    }).parse(req.body);

    // ── Email verification gate ───────────────────────────────────────────
    const { rows: [user] } = await q(
      `SELECT email_verified_at FROM users WHERE id = $1`, [req.user.sub]
    );
    if (!user?.email_verified_at) {
      return res.status(403).json({
        error: 'Debes verificar tu correo electrónico antes de realizar una compra.',
        code:  'EMAIL_NOT_VERIFIED',
      });
    }

    const ids = items.map(i => i.product_id);
    const { rows: products } = await q(
      `SELECT id, name, slug, price_mxn_cents
       FROM products WHERE id = ANY($1) AND is_active = TRUE`,
      [ids]
    );
    if (products.length !== ids.length) {
      return res.status(400).json({ error: 'Uno o más productos no están disponibles' });
    }

    const byId  = new Map(products.map(p => [p.id, p]));
    const line  = items.map(i => ({ ...byId.get(i.product_id), quantity: i.quantity }));
    const total = line.reduce((a, l) => a + l.price_mxn_cents * l.quantity, 0);

    // Create pending order
    const { rows: [order] } = await q(
      `INSERT INTO orders (user_id, total_mxn_cents, gateway, status)
       VALUES ($1, $2, $3, 'pending') RETURNING id`,
      [req.user.sub, total, gateway]
    );
    for (const l of line) {
      await q(
        `INSERT INTO order_items (order_id, product_id, unit_price_cents, quantity)
         VALUES ($1, $2, $3, $4)`,
        [order.id, l.id, l.price_mxn_cents, l.quantity]
      );
    }

    const success = `${process.env.APP_URL}/thanks?order=${order.id}`;
    const cancel  = `${process.env.APP_URL}/checkout?cancelled=1`;

    if (gateway === 'stripe') {
      const { default: Stripe } = await import('stripe');
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
      const session = await stripe.checkout.sessions.create({
        mode: 'payment',
        payment_method_types: ['card'],
        line_items: line.map(l => ({
          price_data: {
            currency:     'mxn',
            unit_amount:  l.price_mxn_cents,
            product_data: { name: l.name },
          },
          quantity: l.quantity,
        })),
        customer_email: req.user.email,
        success_url:    success,
        cancel_url:     cancel,
        metadata:       { order_id: order.id, user_id: req.user.sub },
      });
      await q(`UPDATE orders SET gateway_id = $1 WHERE id = $2`, [session.id, order.id]);
      return res.json({ url: session.url });
    }

    // Mercado Pago
    const { MercadoPagoConfig, Preference } = await import('mercadopago');
    const mp   = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
    const pref = await new Preference(mp).create({
      body: {
        items: line.map(l => ({
          id: l.id, title: l.name, quantity: l.quantity,
          unit_price: l.price_mxn_cents / 100, currency_id: 'MXN',
        })),
        payer:              { email: req.user.email },
        external_reference: order.id,
        back_urls:          { success, failure: cancel, pending: success },
        auto_return:        'approved',
        notification_url:   `${process.env.API_URL}/webhooks/mercadopago`,
      },
    });
    await q(`UPDATE orders SET gateway_id = $1 WHERE id = $2`, [pref.id, order.id]);
    res.json({ url: pref.init_point });
  } catch (e) { next(e); }
});

export default r;
