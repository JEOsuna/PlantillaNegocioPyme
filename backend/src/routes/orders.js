import { Router } from 'express';
import { userQ } from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const r = Router();

r.get('/', requireAuth, async (req, res, next) => {
  try {
    // userQ sets app.current_user_id → RLS enforces user sees only their orders
    const { rows } = await userQ(req.user.sub, req.user.role,
      `SELECT o.id, o.total_mxn_cents, o.status, o.paid_at, o.created_at,
              json_agg(json_build_object('name', p.name, 'qty', oi.quantity)) AS items
       FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.user_id = $1
       GROUP BY o.id ORDER BY o.created_at DESC`,
      [req.user.sub]
    );
    res.json({ orders: rows });
  } catch (e) { next(e); }
});

export default r;
