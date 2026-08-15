'use strict';
const { json, readBody, browserSession, upstream, sameOriginRequest, safeUpstreamError } = require('../_paxinbot');

const queries = {
  overview: ['paxinbot_get_my_account', () => ({})],
  devices: ['paxinbot_list_my_devices', () => ({})],
  orders: ['paxinbot_list_my_orders', () => ({})],
  products: ['paxinbot_list_active_products', () => ({})]
};

module.exports = async (req, res) => {
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  if (req.method === 'GET') {
    const item = queries[String(req.query?.action || 'overview')];
    if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
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
    revokeAllDevices: ['paxinbot_revoke_all_my_devices', () => ({})]
  };
  const item = actions[action];
  if (!item) return json(res, 400, { ok: false, error: 'Ação inválida.' });
  if (action === 'profile' && (String(body.displayName || '').trim().length < 2 || String(body.displayName || '').trim().length > 80)) return json(res, 400, { ok: false, error: 'O nome deve ter entre 2 e 80 caracteres.' });
  const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1]() });
  return json(res, response.ok ? 200 : 400, response.ok ? { ok: true, data: payload } : { ok: false, error: safeUpstreamError(payload) });
};
