'use strict';
const crypto = require('node:crypto');
const { json, requireTrustedHost, readBodyResult, browserSession, upstream, downloadSigningSecret, requestRateLimit, publicOrigin, sameOriginRequest, safeUpstreamError } = require('../_paxinbot');

const WINDOWS_RELEASE = Object.freeze({
  path: '/releases/PaxinbotSetup.exe',
  fileName: 'PaxinbotSetup.exe',
  version: '1.0.0',
  sizeBytes: 101433299,
  sha256: '3139286a02c9c9746881ccacf38f922f1050e15e10a1d1d649f76f206b055387',
  expiresIn: 120
});

async function signedWindowsRelease(req, res) {
  try {
    const expires=Math.floor(Date.now()/1000)+WINDOWS_RELEASE.expiresIn;
    const nonce=crypto.randomBytes(18).toString('base64url');
    const canonical=`GET\n${WINDOWS_RELEASE.path}\n${expires}\n${nonce}`;
    const signature=crypto.createHmac('sha256',downloadSigningSecret()).update(canonical).digest('base64url');
    const url=new URL(WINDOWS_RELEASE.path,publicOrigin(req));
    url.searchParams.set('expires',String(expires)); url.searchParams.set('nonce',nonce); url.searchParams.set('signature',signature);
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    if (String(req.query?.redirect || '') === '1') {
      res.statusCode=302;
      res.setHeader('Location',url.toString());
      res.setHeader('Referrer-Policy','no-referrer');
      res.setHeader('X-Content-Type-Options','nosniff');
      return res.end();
    }
    return json(res, 200, { ok:true, data:{ url:url.toString(), fileName:WINDOWS_RELEASE.fileName, version:WINDOWS_RELEASE.version, sizeBytes:WINDOWS_RELEASE.sizeBytes, sha256:WINDOWS_RELEASE.sha256, expiresIn:WINDOWS_RELEASE.expiresIn } });
  } catch {
    return json(res, 503, { ok:false, error:'O instalador está temporariamente indisponível.' });
  }
}

const queries = {
  overview: ['paxinbot_get_my_account', () => ({})],
  devices: ['paxinbot_list_my_devices', () => ({})],
  orders: ['paxinbot_list_my_orders', () => ({})],
  products: ['paxinbot_list_active_products', () => ({})],
  preferences: ['paxinbot_get_my_preferences', () => ({})],
  activity: ['paxinbot_list_my_activity', () => ({})],
  order: ['paxinbot_get_my_order', q => ({ p_order_id:String(q.orderId || '') })],
  tickets: ['paxinbot_list_my_support_tickets', () => ({})],
  usageGrants: ['paxinbot_list_my_usage_grants', () => ({})],
  promotions: ['paxinbot_list_my_promotions', () => ({})]
};

module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  if (!['GET','POST'].includes(req.method)) return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const queryAction = String(req.query?.action || 'overview');
  if (req.method === 'GET' && queryAction === 'download') return signedWindowsRelease(req, res);
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  if (!await requestRateLimit(req, res, {
    scope:req.method === 'GET' ? 'account_read_user' : 'account_write_user',
    subject:session.user.id, limit:req.method === 'GET' ? 300 : 120, windowSeconds:600
  })) return;
  if (req.method === 'GET') {
    const item = queries[queryAction];
    if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
    if (queryAction === 'order' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(req.query?.orderId || ''))) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1](req.query || {}) });
    const checkoutReady = Boolean(process.env.MERCADOPAGO_ACCESS_TOKEN && process.env.MERCADOPAGO_WEBHOOK_SECRET && process.env.SUPABASE_SECRET_KEY);
    return json(res, response.ok ? 200 : 503, response.ok ? { ok: true, data: payload, ...(String(req.query?.action) === 'products' ? { checkoutReady } : {}) } : { ok: false, error: safeUpstreamError(payload, 'Esta área ainda não foi ativada no banco de dados.') });
  }
  if (!sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const action = String(body.action || '');
  const actions = {
    profile: ['paxinbot_update_my_profile', () => ({ p_display_name: String(body.displayName || '').trim() })],
    revokeDevice: ['paxinbot_revoke_my_device', () => ({ p_session_id: String(body.sessionId || '') })],
    revokeAllDevices: ['paxinbot_revoke_all_my_devices', () => ({})],
    preferences: ['paxinbot_update_my_preferences', () => ({ p_product_updates:body.productUpdates === true, p_support_updates:body.supportUpdates !== false })],
    createTicket: ['paxinbot_create_support_ticket', () => ({ p_category:String(body.category || ''), p_subject:String(body.subject || '').trim(), p_message:String(body.message || '').trim() })],
    replyTicket: ['paxinbot_reply_support_ticket', () => ({ p_ticket_id:String(body.ticketId || ''), p_message:String(body.message || '').trim() })],
    activateUsage: ['paxinbot_activate_usage_grant', () => ({ p_grant_id:String(body.grantId || '') })],
    claimPromotion: ['paxinbot_claim_promotion', () => ({ p_promotion_id:String(body.promotionId || '') })]
  };
  const item = actions[action];
  if (!item) return json(res, 400, { ok: false, error: 'Ação inválida.' });
  if (action === 'profile' && (String(body.displayName || '').trim().length < 2 || String(body.displayName || '').trim().length > 80)) return json(res, 400, { ok: false, error: 'O nome deve ter entre 2 e 80 caracteres.' });
  if (action === 'createTicket' && (!['technical','payment','access','other'].includes(String(body.category || '')) || String(body.subject || '').trim().length < 5 || String(body.subject || '').trim().length > 120 || String(body.message || '').trim().length < 10 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'Preencha a categoria, um assunto de 5 a 120 caracteres e uma mensagem de 10 a 3000 caracteres.' });
  if (action === 'replyTicket' && (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.ticketId || '')) || String(body.message || '').trim().length < 2 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'Resposta inválida.' });
  if (action === 'activateUsage' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.grantId || ''))) return json(res, 400, { ok:false, error:'Crédito de uso inválido.' });
  if (action === 'claimPromotion' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.promotionId || ''))) return json(res, 400, { ok:false, error:'Promoção inválida.' });
  const sensitiveLimits = {
    createTicket:['account_ticket_user', 5, 3600],
    replyTicket:['account_ticket_reply_user', 30, 3600],
    activateUsage:['account_usage_user', 20, 3600],
    claimPromotion:['account_promotion_user', 10, 3600]
  };
  if (sensitiveLimits[action]) {
    const [scope, limit, windowSeconds] = sensitiveLimits[action];
    if (!await requestRateLimit(req, res, { scope, subject:session.user.id, limit, windowSeconds })) return;
  }
  const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1]() });
  return json(res, response.ok ? 200 : 400, response.ok ? { ok: true, data: payload } : { ok: false, error: safeUpstreamError(payload) });
};
