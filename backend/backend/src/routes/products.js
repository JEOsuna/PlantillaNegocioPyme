import { Router } from 'express';
import { q } from '../db/index.js';

const r = Router();

r.get('/', async (_req, res, next) => {
  try {
    const { rows } = await q(
      `SELECT id, slug, name, description, price_mxn_cents, version
       FROM products WHERE is_active=TRUE ORDER BY price_mxn_cents`
    );
    res.json({ products: rows });
  } catch (e) { next(e); }
});

r.get('/:slug', async (req, res, next) => {
  try {
    const { rows } = await q(
      `SELECT id, slug, name, description, price_mxn_cents, version
       FROM products WHERE slug=$1 AND is_active=TRUE`, [req.params.slug]
    );
    if (!rows[0]) return res.status(404).json({ error: 'No encontrado' });
    res.json({ product: rows[0] });
  } catch (e) { next(e); }
});

export default r;
