import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { db } from './index.js';

const products = [
  ['control-financiero', 'Control Financiero PYME', 49900, 'plantillas/control-financiero.xlsx'],
  ['inventario',         'Gestión de Inventario',    39900, 'plantillas/inventario.xlsx'],
  ['dashboard-ventas',   'Dashboard de Ventas',      44900, 'plantillas/dashboard-ventas.xlsx'],
  ['flujo-efectivo',     'Proyección de Flujo de Efectivo', 54900, 'plantillas/flujo-efectivo.xlsx'],
  ['kpi-tracker',        'Tablero de KPIs Gerenciales', 49900, 'plantillas/kpi-tracker.xlsx'],
  ['bundle',             'Paquete Completo',         159500, 'plantillas/bundle.zip'],
];

for (const [slug, name, price, key] of products) {
  await db.query(
    `INSERT INTO products (slug, name, price_mxn_cents, r2_object_key)
     VALUES ($1,$2,$3,$4) ON CONFLICT (slug) DO NOTHING`,
    [slug, name, price, key]
  );
}

const pw = await bcrypt.hash('admin123-change-me', 12);
await db.query(
  `INSERT INTO users (email, password_hash, name, role, email_verified_at)
   VALUES ($1,$2,$3,'admin',now()) ON CONFLICT (email) DO NOTHING`,
  ['[email protected]', pw, 'Admin']
);
console.log('✓ seeded'); await db.end();
