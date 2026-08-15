'use strict';
const { json, readBody, browserSession, upstream, publicOrigin, sameOriginRequest, safeUpstreamError, sendTransactionalEmail } = require('../_paxinbot');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COUPON = /^[A-Z0-9_-]{3,32}$/;

function mercadoPagoToken() {
  const token = String(process.env.MERCADOPAGO_ACCESS_TOKEN || '');
  if (token.length < 24) throw new Error('O checkout ainda não foi configurado no servidor.');
  return token;
}
async function rpc(access, name, body) {
  return upstream(`/rest/v1/rpc/${name}`, { method:'POST', headers:{ authorization:`Bearer ${access}` }, body });
}
function checkoutHostAllowed(value) {
  try {
    const host = new URL(value).hostname.toLowerCase();
    return host === 'mercadopago.com.br' || host.endsWith('.mercadopago.com.br') || host === 'mercadopago.com' || host.endsWith('.mercadopago.com');
  } catch { return false; }
}
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]); }
async function createPreference(req, access, order) {
  const origin = publicOrigin(req);
  const preferenceResponse = await fetch('https://api.mercadopago.com/checkout/preferences', {
    method:'POST',
    headers:{ authorization:`Bearer ${mercadoPagoToken()}`, 'content-type':'application/json', 'x-idempotency-key':String(order.orderId) },
    body:JSON.stringify({
      items:[{ id:String(order.productId), title:String(order.productName).slice(0,120), description:String(order.productDescription || '').slice(0,220), category_id:'software', quantity:1, currency_id:'BRL', unit_price:Number(order.amountCents) / 100 }],
      payer:{ email:String(order.payerEmail || '') }, external_reference:String(order.externalReference),
      notification_url:`${origin}/api/webhooks/mercadopago?source_news=webhooks`,
      back_urls:{ success:`${origin}/conta/assinatura?checkout=success&order=${encodeURIComponent(order.orderId)}`, pending:`${origin}/conta/assinatura?checkout=pending&order=${encodeURIComponent(order.orderId)}`, failure:`${origin}/conta/assinatura?checkout=failure&order=${encodeURIComponent(order.orderId)}` },
      auto_return:'approved', statement_descriptor:'PAXINBOT', metadata:{ order_id:String(order.orderId) }
    })
  });
  const preference = await preferenceResponse.json().catch(() => null); const checkoutUrl = String(preference?.init_point || '');
  if (!preferenceResponse.ok || !preference?.id || !checkoutHostAllowed(checkoutUrl)) throw new Error('provider_error');
  const attached = await rpc(access, 'paxinbot_attach_checkout_preference', { p_order_id:order.orderId, p_preference_id:String(preference.id) });
  if (!attached.response.ok) throw new Error('attach_error');
  return checkoutUrl;
}

module.exports = async (req, res) => {
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok:false, error:'Entre na sua conta para continuar.' });

  if (req.method === 'GET') {
    const orderId = String(req.query?.orderId || '');
    if (!UUID.test(orderId)) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const { response, payload } = await rpc(session.access, 'paxinbot_get_checkout_status', { p_order_id:orderId });
    return json(res, response.ok ? 200 : 404, response.ok ? { ok:true, order:payload } : { ok:false, error:safeUpstreamError(payload, 'Pedido não encontrado.') });
  }
  if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' });
  if (!sameOriginRequest(req)) return json(res, 403, { ok:false, error:'Origem da solicitação não autorizada.' });

  const body = await readBody(req);
  const action = String(body.action || 'create');
  if (action === 'receipt') {
    const orderId = String(body.orderId || ''); if (!UUID.test(orderId)) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const receipt = await rpc(session.access, 'paxinbot_get_my_receipt', { p_order_id:orderId });
    if (!receipt.response.ok) return json(res, 400, { ok:false, error:safeUpstreamError(receipt.payload, 'Comprovante indisponível.') });
    const data = receipt.payload; const amount = new Intl.NumberFormat('pt-BR', { style:'currency', currency:data.currency || 'BRL' }).format((Number(data.amountCents) || 0) / 100);
    try {
      const result = await sendTransactionalEmail({ to:data.email, subject:'Comprovante de pagamento — Paxinbot', idempotencyKey:`receipt/${orderId}/${new Date().toISOString().slice(0,10)}`, html:`<div style="background:#080808;color:#f4f4f4;padding:32px;font-family:Arial,sans-serif"><h1 style="font-size:24px">Comprovante de pagamento</h1><p>Produto: <strong>${escapeHtml(data.productName)}</strong></p><p>Valor: ${escapeHtml(amount)}</p><p>Confirmado em: ${escapeHtml(new Date(data.paidAt).toLocaleString('pt-BR'))}</p><p style="color:#999;font-size:12px">Pedido ${escapeHtml(orderId)}</p></div>` });
      if (!result.configured) return json(res, 503, { ok:false, error:'O envio de comprovantes ainda não foi configurado.' });
      return json(res, 200, { ok:true });
    } catch { return json(res, 503, { ok:false, error:'Não foi possível enviar o comprovante agora.' }); }
  }
  if (action === 'resume') {
    const orderId = String(body.orderId || ''); if (!UUID.test(orderId)) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const resumed = await rpc(session.access, 'paxinbot_resume_checkout', { p_order_id:orderId });
    if (!resumed.response.ok) return json(res, 400, { ok:false, error:safeUpstreamError(resumed.payload, 'Não foi possível retomar o pagamento.') });
    try { return json(res, 200, { ok:true, orderId, checkoutUrl:await createPreference(req, session.access, resumed.payload) }); }
    catch { return json(res, 503, { ok:false, error:'O Mercado Pago não respondeu. Aguarde um momento e tente novamente.' }); }
  }
  if (action !== 'create') return json(res, 400, { ok:false, error:'Ação inválida.' });
  const productId = String(body.productId || '');
  const couponCode = String(body.couponCode || '').trim().toUpperCase();
  if (!UUID.test(productId) || (couponCode && !COUPON.test(couponCode))) return json(res, 400, { ok:false, error:'Produto ou cupom inválido.' });

  const prepared = await rpc(session.access, 'paxinbot_prepare_checkout', { p_product_id:productId, p_coupon_code:couponCode || null });
  if (!prepared.response.ok) return json(res, 400, { ok:false, error:safeUpstreamError(prepared.payload, 'Não foi possível preparar esta compra.') });
  const order = prepared.payload;

  try { return json(res, 201, { ok:true, orderId:order.orderId, checkoutUrl:await createPreference(req, session.access, order) }); } catch {
    await rpc(session.access, 'paxinbot_cancel_checkout', { p_order_id:order.orderId, p_reason:'provider_error' }).catch(() => null);
    return json(res, 503, { ok:false, error:'O Mercado Pago não respondeu. Aguarde um momento e tente novamente.' });
  }
};
