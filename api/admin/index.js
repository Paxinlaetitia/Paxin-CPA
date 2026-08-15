'use strict';
const { json, readBody, browserSession, upstream } = require('../_paxinbot');
const queries = { overview: ['paxinbot_owner_overview', () => ({})], users: ['paxinbot_owner_list_users', q => ({ p_query: String(q.q || '') })], products: ['paxinbot_owner_list_products', () => ({})], coupons: ['paxinbot_owner_list_coupons', () => ({})] };
module.exports = async (req, res) => {
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'Entre com a conta do proprietário.' });
  const ownerCheck = await upstream('/rest/v1/rpc/paxinbot_is_owner', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
  if (!ownerCheck.response.ok || ownerCheck.payload !== true) return json(res, 403, { ok: false, error: 'Esta conta está autenticada, mas ainda não foi registrada como proprietária no Supabase.' });
  if (req.method === 'GET') {
    const item = queries[String(req.query?.action || 'overview')]; if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
    const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1](req.query || {}) });
    return json(res, response.ok ? 200 : 403, response.ok ? { ok: true, data: payload } : { ok: false, error: 'O painel não encontrou as funções de proprietário no banco. Execute a migração principal novamente.' });
  }
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req); const action = String(body.action || '');
  const actions = {
    product: ['paxinbot_owner_save_product', () => ({ p_id: body.id || null, p_code: body.code, p_name: body.name, p_description: body.description || '', p_access_kind: body.accessKind, p_duration_minutes: body.accessKind === 'lifetime' ? null : Number(body.durationMinutes), p_price_cents: Number(body.priceCents), p_active: body.active !== false })],
    coupon: ['paxinbot_owner_save_coupon', () => ({ p_id: body.id || null, p_code: body.code, p_description: body.description || '', p_discount_type: body.discountType, p_discount_value: Number(body.discountValue), p_max_redemptions: body.maxRedemptions ? Number(body.maxRedemptions) : null, p_expires_at: body.expiresAt || null, p_active: body.active !== false })],
    access: ['paxinbot_owner_grant_access', () => ({ p_email: body.email, p_kind: body.kind, p_expires_at: body.kind === 'lifetime' ? null : body.expiresAt, p_source: 'owner-panel' })]
  };
  const item = actions[action]; if (!item) return json(res, 400, { ok: false, error: 'Ação inválida.' });
  const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1]() });
  return json(res, response.ok ? 200 : 400, response.ok ? { ok: true, data: payload } : { ok: false, error: 'Não foi possível salvar. Revise os dados e sua sessão.' });
};
