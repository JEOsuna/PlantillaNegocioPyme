import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);
const FROM = process.env.EMAIL_FROM;

const wrap = (title, body) => `
<!doctype html><html><body style="font-family:Inter,sans-serif;max-width:520px;margin:40px auto;padding:0 20px;color:#0f172a">
  <div style="background:#0f172a;color:white;padding:20px;border-radius:12px 12px 0 0">
    <strong style="font-size:16px">PlantillaNegocioPyme<span style="color:#dcfce7">.com</span></strong>
  </div>
  <div style="background:white;border:1px solid #e2e8f0;border-top:0;padding:28px;border-radius:0 0 12px 12px">
    <h1 style="font-size:20px;margin:0 0 12px">${title}</h1>
    ${body}
  </div>
  <p style="font-size:12px;color:#64748b;text-align:center;margin-top:16px">
    © 2026 PlantillaNegocioPyme.com · Si no solicitaste este correo, puedes ignorarlo.
  </p>
</body></html>`;

export const sendWelcome = (to, name) =>
  resend.emails.send({ from: FROM, to, subject: '¡Bienvenido a PlantillaNegocioPyme!',
    html: wrap(`¡Hola ${name}!`, `<p>Tu cuenta está lista. Cuando compres tus plantillas te las enviaremos aquí mismo.</p>`) });

export const sendReceipt = (to, { orderId, total, items, downloadUrl }) =>
  resend.emails.send({ from: FROM, to, subject: `Recibo · Orden ${orderId.slice(0,8)}`,
    html: wrap('Gracias por tu compra',
      `<p>Tu pago se procesó correctamente. Monto: <strong>$${(total/100).toLocaleString('es-MX')} MXN</strong></p>
       <p><strong>Productos:</strong></p>
       <ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>
       <p style="margin-top:20px"><a href="${downloadUrl}" style="background:#16a34a;color:white;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block">Descargar plantillas</a></p>
       <p style="color:#64748b;font-size:13px">El link expira en 24 horas. Puedes generar nuevos links desde tu panel en cualquier momento.</p>`) });

export const sendReset = (to, link) =>
  resend.emails.send({ from: FROM, to, subject: 'Restablecer tu contraseña',
    html: wrap('Restablecer contraseña',
      `<p>Haz clic para crear una nueva contraseña. Este link expira en 1 hora.</p>
       <p><a href="${link}" style="background:#0f172a;color:white;padding:12px 20px;border-radius:8px;text-decoration:none">Crear nueva contraseña</a></p>
       <p style="color:#64748b;font-size:13px">Si no pediste este cambio, ignora este correo.</p>`) });

export const sendVerification = (to, name, link) =>
  resend.emails.send({
    from: FROM, to,
    subject: 'Confirma tu correo — PlantillaNegocioPyme',
    html: wrap(`Hola ${name}, confirma tu email`,
      `<p>Para activar tu cuenta y acceder a tus plantillas, confirma tu dirección de correo.</p>
       <p style="margin-top:20px">
         <a href="${link}" style="background:#16a34a;color:white;padding:14px 24px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:600">
           Confirmar mi correo
         </a>
       </p>
       <p style="color:#64748b;font-size:13px;margin-top:16px">
         Este link expira en 24 horas.<br/>
         Si no creaste esta cuenta, puedes ignorar este correo.
       </p>`) });

export const sendRefundConfirmation = (to, { orderId, total, items }) =>
  resend.emails.send({
    from: FROM, to,
    subject: `Reembolso procesado · Orden ${orderId.slice(0, 8)}`,
    html: wrap('Tu reembolso fue procesado',
      `<p>Hemos procesado el reembolso de tu orden por <strong>$${(total / 100).toLocaleString('es-MX')} MXN</strong>.</p>
       <p><strong>Productos reembolsados:</strong></p>
       <ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>
       <p style="color:#64748b;font-size:13px">
         El monto aparecerá en tu estado de cuenta en 3-5 días hábiles dependiendo de tu banco.<br/>
         Si tienes preguntas, escríbenos a soporte@plantillanegociopyme.com.
       </p>`) });

