# PlantillaNegocioPyme — Backend API

Node.js + Express + PostgreSQL. Auth, checkout (Stripe + Mercado Pago), entrega digital con Cloudflare R2, panel admin, emails transaccionales (Resend).

## Estructura

```
backend/
├── package.json
├── .env.example          # copia a .env y llena con tus credenciales
├── src/
│   ├── server.js         # Express app, middleware, rutas
│   ├── db/
│   │   ├── index.js      # pool pg
│   │   ├── schema.sql    # esquema completo (users, orders, entitlements, etc.)
│   │   ├── migrate.js    # npm run db:migrate
│   │   └── seed.js       # productos iniciales + admin
│   ├── lib/
│   │   ├── jwt.js        # sign/verify JWT
│   │   ├── r2.js         # Cloudflare R2 signed URLs
│   │   └── email.js      # plantillas HTML + Resend
│   ├── middleware/
│   │   ├── auth.js       # requireAuth, requireAdmin
│   │   └── error.js
│   ├── routes/
│   │   ├── auth.js       # /register /login /logout /forgot /reset
│   │   ├── products.js   # catálogo público
│   │   ├── checkout.js   # crea orden + sesión Stripe/MP
│   │   ├── orders.js     # mis órdenes (cliente)
│   │   ├── downloads.js  # signed URLs de plantillas
│   │   └── admin.js      # /metrics /orders /refund
│   └── webhooks/
│       ├── stripe.js     # verifica firma + fulfill
│       └── mercadopago.js
```

## Setup local

```bash
cp .env.example .env        # llena DATABASE_URL, STRIPE_*, MP_*, R2_*, RESEND_*
npm install
npm run db:migrate          # crea tablas (schema.sql)
node src/db/migrate.js src/db/migrations/002_email_verify_mp_refund.sql  # migración 2
npm run db:seed             # inserta 6 productos + admin de ejemplo
npm run dev                 # API en http://localhost:3000
```

## Deploy: GoDaddy dominio + Railway app + Neon Postgres

### 1. Base de datos (Neon — gratis)
1. Entra a neon.tech → crea proyecto "plantillanegociopyme"
2. Copia la `DATABASE_URL` que te da (incluye `?sslmode=require`)

### 2. App (Railway — $5/mes)
1. railway.app → New Project → Deploy from GitHub repo (o sube con CLI)
2. Añade variables del `.env` en la pestaña Variables
3. Railway corre automáticamente `npm start`
4. Railway te da un dominio tipo `tu-app.up.railway.app`

### 3. Archivos .xlsx (Cloudflare R2)
1. Crea bucket `plantillas` en R2
2. Sube los .xlsx con las keys que usa `seed.js` (`plantillas/control-financiero.xlsx`, etc.)
3. Genera API token con permiso de Object Read y pon las credenciales en Railway

### 4. Dominio GoDaddy
En el panel de GoDaddy → DNS → agrega:
```
Tipo   Nombre   Valor
CNAME  @        tu-app.up.railway.app
CNAME  www      tu-app.up.railway.app
CNAME  api      tu-app.up.railway.app
```
En Railway → Settings → Networking → Custom Domain → añade `plantillanegociopyme.com` y `api.plantillanegociopyme.com`. Railway emite SSL automáticamente.

### 5. Webhooks
**Stripe:** Dashboard → Developers → Webhooks → Add endpoint → `https://api.tudominio.com/webhooks/stripe`
- Eventos: `checkout.session.completed`, `charge.refunded`
- Copia el signing secret a `STRIPE_WEBHOOK_SECRET`

**Mercado Pago:** Panel → Webhooks → URL `https://api.tudominio.com/webhooks/mercadopago`, eventos: `payment`

### 6. Correr migraciones en producción
Una vez desplegado, corre desde Railway CLI:
```bash
railway run npm run db:migrate
railway run node src/db/migrations/002_email_verify_mp_refund.sql
railway run npm run db:seed
```

## Endpoints principales

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/auth/register` | – | registro (email + password + name) |
| POST | `/auth/login` | – | login, devuelve cookie `session` |
| POST | `/auth/logout` | – | limpia cookie |
| POST | `/auth/forgot` | – | envía link de reset |
| POST | `/auth/reset` | – | consume token + nueva password |
| GET  | `/auth/verify?token=` | – | verifica email al hacer clic en el link |
| POST | `/auth/resend-verification` | – | reenvía email de verificación |
| GET | `/products` | – | catálogo activo |
| POST | `/checkout` | user | crea orden + URL Stripe/MP |
| GET | `/orders` | user | mis órdenes |
| GET | `/downloads` | user | mis plantillas |
| POST | `/downloads/:id` | user | nueva URL firmada 24h |
| GET | `/admin/metrics` | admin | KPIs 30d |
| GET | `/admin/orders` | admin | últimas órdenes |
| POST | `/admin/orders/:id/refund` | admin | reembolso |
| POST | `/webhooks/stripe` | firma | fulfill |
| POST | `/webhooks/mercadopago` | firma | fulfill |

## Seguridad aplicada

- **Helmet** para headers de seguridad (CSP, HSTS, etc.)
- **bcrypt cost=12** para hashes de contraseña
- **JWT + cookie httpOnly + secure + signed** para sesión
- **Rate limiting** (120 req/min global, 10/15min en auth)
- **Validación Zod** en toda entrada del usuario
- **Verificación de firma** en webhooks de Stripe y Mercado Pago
- **TLS** obligatorio en Postgres (sslmode=require)
- **URLs firmadas R2** con expiración de 24h — nunca expones el archivo directamente
- **No user enumeration** en `/auth/forgot` (siempre responde OK)
- **Tokens de reset**: random 32-byte, se guarda solo el SHA-256, expira en 1h, uso único

## Costos mensuales estimados (arranque)
- Neon Postgres: **$0** (free tier cubre hasta 3GB)
- Railway: **~$5** 
- Cloudflare R2: **~$0** (free: 10GB + sin egress fees)
- Resend: **$0** (3,000 emails/mes gratis)
- Stripe: **3.6% + $3 MXN** por transacción
- Mercado Pago: **3.49% + IVA** por transacción
- **Total infra: ~$5 USD/mes + comisiones de pago**

## Siguiente paso sugerido
Conectar un frontend (Next.js o la landing actual con React) que consuma estas APIs. Los endpoints usan cookies, así que fetch con `credentials: 'include'`.
