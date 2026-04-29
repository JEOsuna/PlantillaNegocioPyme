# Security Review — PlantillaNegocioPyme Backend
**Fecha:** 24 abril 2026 · **Revisión:** v2.0

---

## 1. Row Level Security (RLS) — PostgreSQL

### Problema encontrado (crítico)
La versión inicial usaba **cero RLS**. Toda la protección de datos dependía exclusivamente de cláusulas `WHERE user_id = $1` en el código Node. Un solo bug (una query sin WHERE, un refactor descuidado) expone todas las filas de todos los usuarios.

### Solución aplicada

**Dos roles de DB separados:**
```sql
app_api    -- Node se conecta como este; RLS activo, sin BYPASSRLS
app_admin  -- migraciones/seeds; BYPASSRLS, no se usa en producción
```

**RLS habilitado en todas las tablas de usuario:**
```
users · orders · order_items · entitlements · downloads · events
```

**Mecanismo:** cada query de usuario corre dentro de una transacción con:
```sql
SELECT set_config('app.current_user_id', '<uuid>', true)
-- true = local a la transacción → seguro con connection pooling
```

Las políticas comprueban ese GUC:
```sql
CREATE POLICY orders_own ON orders FOR SELECT
  USING (user_id = current_setting('app.current_user_id', true)::uuid);
```

**`qs(userId, sql, params)`** — nuevo helper en `db/index.js`. Cualquier query que toque filas de usuario DEBE usar `qs()`, no `q()`.

**SECURITY DEFINER para webhooks:**  
Los webhooks marcan órdenes como pagadas sin contexto de usuario. Se creó la función `fulfill_order()` con `SECURITY DEFINER` que corre con los permisos del propietario (app_admin) y usa `FOR UPDATE` para evitar race conditions con webhooks duplicados.

**Defensa doble (defense in depth):**
- Capa 1 → `WHERE e.user_id = $1` en SQL (app logic)
- Capa 2 → RLS policy en Postgres (DB layer)
- Si falla capa 1, capa 2 bloquea. Ambas deben fallar para haber un leak.

---

## 2. CORS

### Problemas encontrados

| # | Problema | Severidad |
|---|----------|-----------|
| 1 | En producción, peticiones sin `Origin` header eran aceptadas | Media |
| 2 | Lista de orígenes permitidos no estaba normalizada (trailing slashes) | Baja |
| 3 | Faltaba `app.options('*', cors())` para manejar preflights explícitamente | Baja |

### Solución aplicada

```js
const ALLOWED_ORIGINS = new Set(
  process.env.APP_URL
    .split(',')
    .map(s => s.trim().replace(/\/$/, ''))  // normaliza trailing slash
);

origin(origin, cb) {
  if (!origin) {
    // No Origin: aceptar solo en dev, rechazar en producción
    return process.env.NODE_ENV !== 'production'
      ? cb(null, true)
      : cb(Object.assign(new Error('CORS: no Origin'), { status: 403 }));
  }
  if (ALLOWED_ORIGINS.has(origin.trim().replace(/\/$/, ''))) return cb(null, true);
  cb(Object.assign(new Error('CORS: not allowed'), { status: 403 }));
}
```

**Para múltiples orígenes** (ej: landing + panel admin en subdominios distintos):
```
APP_URL=https://plantillanegociopyme.com,https://admin.plantillanegociopyme.com
```

---

## 3. Security Headers

### Headers aplicados (via Helmet + manual)

| Header | Valor | Protege contra |
|--------|-------|----------------|
| `Content-Security-Policy` | `default-src 'none'` | XSS, data injection |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Downgrade attacks, MITM |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referer leakage |
| `Cross-Origin-Opener-Policy` | `same-origin` | Cross-window attacks |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Spectre / side-channel |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cross-site resource reads |
| `Permissions-Policy` | camera, mic, geo, payment... todos `()` | Browser API abuse |
| `X-Powered-By` | eliminado | Fingerprinting |
| `X-DNS-Prefetch-Control` | `off` | Info leakage via DNS |

### Nota sobre CSP para la landing page
El backend es una **API pura** — la CSP `default-src 'none'` es correcta aquí. La landing page HTML (hospedada por separado, ej: Vercel/Cloudflare Pages) necesita su propia CSP más permisiva. No mezclar.

---

## 4. Otros fixes aplicados

### SQL injection en admin metrics (media)
**Antes:**
```js
const since = `now() - interval '30 days'`;  // string directo en SQL
q(`... AND paid_at > ${since}`);             // interpolación → injection si `since` se parametriza
```
**Después:**
```js
q(`... AND paid_at > now() - ($1 || ' days')::interval`, [days]);
```

### Validación UUID en route params (media)
**Antes:** `req.params.entitlementId` iba directo a Postgres → error con UUIDs malformados filtra tipo de DB.  
**Después:** `assertUUID()` lanza 400 antes de tocar la DB.

### Enumeración de usuarios en auth (media)
**Antes:** `/auth/register` devolvía 409 si el email ya existía (confirma existencia de usuario).  
**Después:** siempre devuelve 200 OK. El atacante no sabe si el email ya existía.

**Antes:** `/auth/login` bcrypt solo corría si existía el usuario (timing attack confirma existencia).  
**Después:** `checkPassword()` siempre corre bcrypt con un hash falso si el usuario no existe.

### Rate limit en descargas (baja)
Nuevo: 20 URLs firmadas / hora / usuario. Previene abuso de R2 para generación masiva de presigned URLs.

### Signed URL no se guarda en texto plano (baja)
**Antes:** URL firmada se guardaba en `downloads.signed_url TEXT`.  
**Después:** se guarda solo el SHA-256 (`url_hash`). La URL es un token de capacidad — no necesita vivir en la DB.

### bcrypt DoS (baja)
**Antes:** `password` sin límite superior → bcrypt con passwords de 10MB congela el proceso.  
**Después:** `z.string().min(8).max(128)` — bcrypt trunca a 72 bytes de todas formas, pero el límite evita trabajo innecesario.

### Cookie `sameSite` mejorado (baja)
**Antes:** `sameSite: 'lax'`  
**Después:** `sameSite: 'strict'` — la cookie nunca se envía en requests cross-site, cerrando vectores CSRF residuales.

### Reset password — token invalidado antes (baja)
Al pedir `/auth/forgot`, todos los tokens previos sin usar del mismo usuario se invalidan antes de crear uno nuevo. Previene acumulación de tokens activos.

### Reset password — transacción atómica (baja)
`UPDATE users` + `UPDATE password_resets SET used_at` corren dentro de una transacción. Si el segundo falla, la contraseña no cambia y el token sigue válido.

---

## 5. Checklist de despliegue

- [ ] `DATABASE_URL` usa credenciales de `app_api` (no superuser)
- [ ] `app_admin` solo se usa para `npm run db:migrate`
- [ ] `JWT_SECRET` ≥ 32 caracteres aleatorios (`openssl rand -hex 32`)
- [ ] `COOKIE_SECRET` ≥ 32 caracteres distintos al JWT_SECRET
- [ ] `STRIPE_WEBHOOK_SECRET` configurado en el dashboard de Stripe
- [ ] `MP_WEBHOOK_SECRET` configurado en el panel de Mercado Pago
- [ ] `NODE_ENV=production` en Railway
- [ ] Railway: solo expone el puerto definido en `PORT`
- [ ] R2 bucket: acceso público **desactivado** (solo URLs firmadas)
- [ ] Verificar respuesta de `/health` no expone versión ni uptime
- [ ] Registrar `plantillanegociopyme.com` en [hstspreload.org](https://hstspreload.org) después de confirmar HTTPS estable

---

## 6. Pendientes recomendados (no bloqueantes para lanzar)

| Item | Prioridad |
|------|-----------|
| Refresh token rotatorio (JWT de 15min + refresh de 7 días) | Alta |
| Verificación de email al registrar | Alta |
| Audit log (tabla `audit_log` para cambios críticos) | Media |
| Reembolso vía Mercado Pago API | Media |
| 2FA TOTP (ej: otpauth + speakeasy) | Media |
| CSP Report-To endpoint para monitorear violaciones | Baja |
| Dependency audit en CI (`npm audit --audit-level=high`) | Baja |
