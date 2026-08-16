'use strict';
const crypto = require('node:crypto');
const { json, readBody, serviceUpstream } = require('../_paxinbot');

function safeEqual(left, right) {
  const a = Buffer.from(String(left), 'utf8'); const b = Buffer.from(String(right), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function verifySignature(req, dataId) {
  const secret = String(process.env.MERCADOPAGO_WEBHOOK_SECRET || '');
  const signature = String(req.headers['x-signature'] || '');
  const requestId = String(req.headers['x-request-id'] || '');
  const parts = Object.fromEntries(signature.split(',').map(part => part.trim().split(/=(.*)/s)).filter(([key,value]) => key && value));
  if (!secret || !requestId || !parts.ts || !parts.v1 || !dataId) return false;
  const timestamp = Number(parts.ts); const timestampMs = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > 5 * 60 * 1000) return false;
  const manifest = `id:${dataId};request-id:${requestId};ts:${parts.ts};`;
  const expected = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
  return safeEqual(expected, parts.v1);
}
function mercadoPagoToken() {
  const token = String(process.env.MERCADOPAGO_ACCESS_TOKEN || '');
  if (token.length < 24) throw new Error('missing_provider_config');
  return token;
}
function webhookDiagnostic(event, details = {}) {
  console.warn(JSON.stringify({ event, ...details }));
}
function isExpandedSimulation(body) {
  const data = body?.data;
  if (!data || typeof data !== 'object' || !data.id) return false;
  return Boolean(
    (data.transactions && typeof data.transactions === 'object') ||
    Object.prototype.hasOwnProperty.call(data, 'total_paid_amount') ||
    Object.prototype.hasOwnProperty.call(data, 'transaction_amount')
  );
}
function publicPaymentSnapshot(payment) {
  return {
    statusDetail:String(payment?.status_detail || '').slice(0,100),
    paymentMethod:String(payment?.payment_type_id || '').slice(0,60),
    dateApproved:payment?.date_approved || null
  };
}
function publicOrderSnapshot(order, payment) {
  return {
    orderStatus:String(order?.status || '').slice(0,60),
    statusDetail:String(order?.status_detail || payment?.status_detail || '').slice(0,100),
    paymentMethod:String(payment?.payment_method?.type || payment?.payment_method?.id || '').slice(0,60)
  };
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
async function sendConfirmation(result) {
  const apiKey = String(process.env.RESEND_API_KEY || '');
  const from = String(process.env.RESEND_FROM_EMAIL || '');
  if (!apiKey || !from || !result?.email || !result?.processed) return;
  const amount = new Intl.NumberFormat('pt-BR', { style:'currency', currency:result.currency || 'BRL' }).format((Number(result.amountCents) || 0) / 100);
  await fetch('https://api.resend.com/emails', {
    method:'POST',
    headers:{ authorization:`Bearer ${apiKey}`, 'content-type':'application/json', 'idempotency-key':`payment-confirmed/${result.orderId}` },
    body:JSON.stringify({
      from, to:[result.email], subject:'Pagamento confirmado — Paxinbot',
      html:`<div style="background:#080808;color:#f4f4f4;padding:32px;font-family:Arial,sans-serif"><h1 style="font-size:24px">Acesso liberado</h1><p>O pagamento de <strong>${escapeHtml(result.productName)}</strong> foi confirmado.</p><p>Valor: ${escapeHtml(amount)}</p><p>Entre na Área do Cliente para consultar e, nas modalidades por tempo, ativar seu saldo quando estiver pronto para usar.</p><p style="color:#999;font-size:12px">Pedido ${escapeHtml(result.orderId)}</p></div>`
    })
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') { webhookDiagnostic('mercadopago_webhook_method_rejected', { method:String(req.method || 'unknown').slice(0,12) }); return json(res, 405, { ok:false, code:'method_not_allowed' }, { allow:'POST' }); }
  const body = await readBody(req);
  const dataId = String(req.query?.['data.id'] || req.query?.id || body?.data?.id || '');
  if (!verifySignature(req, dataId)) { webhookDiagnostic('mercadopago_webhook_signature_rejected', { reason:process.env.MERCADOPAGO_WEBHOOK_SECRET ? 'invalid_signature' : 'missing_webhook_secret' }); return json(res, 401, { ok:false, code:'invalid_signature' }); }
  const type = String(req.query?.type || body?.type || body?.action || '').toLowerCase();
  const isOrder = type === 'order' || type.startsWith('order.');
  const isPayment = !type || type === 'payment' || type.startsWith('payment.');
  if (!isOrder && !isPayment) return json(res, 200, { ok:true, ignored:true });
  // O simulador do painel envia um recurso fictício expandido. Ele deve apenas
  // validar a entrega da URL; nunca pode finalizar uma compra ou liberar acesso.
  if (isExpandedSimulation(body)) {
    webhookDiagnostic('mercadopago_webhook_simulation_acknowledged', { resource:isOrder ? 'order' : 'payment' });
    return json(res, 200, { ok:true, simulated:true });
  }

  try {
    if (isOrder) {
      const orderResponse = await fetch(`https://api.mercadopago.com/v1/orders/${encodeURIComponent(dataId)}`, { headers:{ authorization:`Bearer ${mercadoPagoToken()}` } });
      const order = await orderResponse.json().catch(() => null);
      const payment = order?.transactions?.payments?.[0];
      if (!orderResponse.ok || !order?.id || !payment?.id) { webhookDiagnostic('mercadopago_webhook_provider_lookup_failed', { resource:'order', status:Number(orderResponse.status) || 0 }); return json(res, 503, { ok:false, code:'provider_lookup_failed' }); }
      const amountCents = Math.round(Number(payment.paid_amount || payment.amount || order.total_amount) * 100);
      if (!Number.isSafeInteger(amountCents) || amountCents < 0) return json(res, 400, { ok:false });
      const providerStatus = String(payment.status || order.status || '').toLowerCase();
      const finalStatus = providerStatus === 'processed' ? 'approved' : providerStatus === 'refunded' ? 'refunded' : ['failed','canceled','cancelled','expired'].includes(providerStatus) ? 'cancelled' : providerStatus;
      const finalized = await serviceUpstream('/rest/v1/rpc/paxinbot_finalize_mercadopago_payment', {
        method:'POST', body:{
          p_payment_id:String(payment.id), p_external_reference:String(order.external_reference || ''),
          p_status:finalStatus, p_amount_cents:amountCents,
          p_currency:String(order.currency || payment.currency_id || 'BRL'), p_provider_payload:publicOrderSnapshot(order,payment)
        }
      });
      if (!finalized.response.ok) { webhookDiagnostic('mercadopago_webhook_finalization_failed', { resource:'order', status:Number(finalized.response.status) || 0 }); return json(res, 503, { ok:false, code:'finalization_failed' }); }
      await sendConfirmation(finalized.payload).catch(() => null);
      return json(res, 200, { ok:true });
    }
    const paymentResponse = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(dataId)}`, { headers:{ authorization:`Bearer ${mercadoPagoToken()}` } });
    const payment = await paymentResponse.json().catch(() => null);
    if (!paymentResponse.ok || !payment?.id) { webhookDiagnostic('mercadopago_webhook_provider_lookup_failed', { resource:'payment', status:Number(paymentResponse.status) || 0 }); return json(res, 503, { ok:false, code:'provider_lookup_failed' }); }
    const externalReference = String(payment.external_reference || '');
    const amountCents = Math.round(Number(payment.transaction_amount) * 100);
    if (!Number.isSafeInteger(amountCents) || amountCents < 0) return json(res, 400, { ok:false });
    const finalized = await serviceUpstream('/rest/v1/rpc/paxinbot_finalize_mercadopago_payment', {
      method:'POST', body:{
        p_payment_id:String(payment.id), p_external_reference:externalReference,
        p_status:String(payment.status || ''), p_amount_cents:amountCents,
        p_currency:String(payment.currency_id || ''), p_provider_payload:publicPaymentSnapshot(payment)
      }
    });
    if (!finalized.response.ok) { webhookDiagnostic('mercadopago_webhook_finalization_failed', { resource:'payment', status:Number(finalized.response.status) || 0 }); return json(res, 503, { ok:false, code:'finalization_failed' }); }
    await sendConfirmation(finalized.payload).catch(() => null);
    return json(res, 200, { ok:true });
  } catch {
    webhookDiagnostic('mercadopago_webhook_unexpected_failure');
    return json(res, 503, { ok:false, code:'unexpected_failure' });
  }
};
