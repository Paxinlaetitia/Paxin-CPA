'use strict';
const { json, readBody, browserSession, upstream, sameOriginRequest, safeUpstreamError } = require('../_paxinbot');

const queries = {
  overview: ['paxinbot_get_my_account', () => ({})],
  devices: ['paxinbot_list_my_devices', () => ({})],
  orders: ['paxinbot_list_my_orders', () => ({})],
  products: ['paxinbot_list_active_products', () => ({})],
  preferences: ['paxinbot_get_my_preferences', () => ({})],
  activity: ['paxinbot_list_my_activity', () => ({})],
  order: ['paxinbot_get_my_order', q => ({ p_order_id:String(q.orderId || '') })],
  tickets: ['paxinbot_list_my_support_tickets', () => ({})]
};

module.exports = async (req, res) => {
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  if (req.method === 'GET') {
    const queryAction = String(req.query?.action || 'overview');
    const item = queries[queryAction];
    if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
    if (queryAction === 'order' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(req.query?.orderId || ''))) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1](req.query || {}) });
    const checkoutReady = Boolean(process.env.MERCADOPAGO_ACCESS_TOKEN && process.env.MERCADOPAGO_WEBHOOK_SECRET && (process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY));
    return json(res, response.ok ? 200 : 503, response.ok ? { ok: true, data: payload, ...(String(req.query?.action) === 'products' ? { checkoutReady } : {}) } : { ok: false, error: safeUpstreamError(payload, 'Esta área ainda não foi ativada no banco de dados.') });
  }
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  if (!sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  const body = await readBody(req); const action = String(body.action || '');
  const actions = {
    profile: ['paxinbot_update_my_profile', () => ({ p_display_name: String(body.displayName || '').trim() })],
    revokeDevice: ['paxinbot_revoke_my_device', () => ({ p_session_id: String(body.sessionId || '') })],
    revokeAllDevices: ['paxinbot_revoke_all_my_devices', () => ({})],
    preferences: ['paxinbot_update_my_preferences', () => ({ p_product_updates:body.productUpdates === true, p_support_updates:body.supportUpdates !== false })],
    createTicket: ['paxinbot_create_support_ticket', () => ({ p_category:String(body.category || ''), p_subject:String(body.subject || '').trim(), p_message:String(body.message || '').trim() })],
    replyTicket: ['paxinbot_reply_support_ticket', () => ({ p_ticket_id:String(body.ticketId || ''), p_message:String(body.message || '').trim() })]
  };
  const item = actions[action];
  if (!item) return json(res, 400, { ok: false, error: 'Ação inválida.' });
  if (action === 'profile' && (String(body.displayName || '').trim().length < 2 || String(body.displayName || '').trim().length > 80)) return json(res, 400, { ok: false, error: 'O nome deve ter entre 2 e 80 caracteres.' });
  if (action === 'createTicket' && (!['technical','payment','access','other'].includes(String(body.category || '')) || String(body.subject || '').trim().length < 5 || String(body.subject || '').trim().length > 120 || String(body.message || '').trim().length < 10 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'Preencha a categoria, um assunto de 5 a 120 caracteres e uma mensagem de 10 a 3000 caracteres.' });
  if (action === 'replyTicket' && (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.ticketId || '')) || String(body.message || '').trim().length < 2 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'Resposta inválida.' });
  const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1]() });
  return json(res, response.ok ? 200 : 400, response.ok ? { ok: true, data: payload } : { ok: false, error: safeUpstreamError(payload) });
};
