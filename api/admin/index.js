'use strict';
const { json, readBody, browserSession, upstream, sameOriginRequest, safeUpstreamError, sendTransactionalEmail, sha256 } = require('../_paxinbot');
const queries = {
  overview: ['paxinbot_owner_overview', () => ({})],
  users: ['paxinbot_owner_list_users', q => ({ p_query: String(q.q || '') })],
  products: ['paxinbot_owner_list_products', () => ({})],
  coupons: ['paxinbot_owner_list_coupons', () => ({})],
  orders: ['paxinbot_owner_list_orders', () => ({})],
  audit: ['paxinbot_owner_list_audit', () => ({})],
  tickets: ['paxinbot_owner_list_support_tickets', () => ({})]
};
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
  if (!sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  const body = await readBody(req); const action = String(body.action || '');
  if (action === 'product') {
    const code = String(body.code || '').trim().toLowerCase(); const name = String(body.name || '').trim(); const kind = String(body.accessKind || '');
    const duration = kind === 'lifetime' ? null : Number(body.durationMinutes); const price = Number(body.priceCents);
    if (!/^[a-z0-9_-]{3,40}$/.test(code)) return json(res, 400, { ok: false, error: 'Use um código de 3 a 40 caracteres, somente com letras minúsculas, números, hífen ou sublinhado.' });
    if (name.length < 3 || name.length > 80) return json(res, 400, { ok: false, error: 'O nome do produto deve ter entre 3 e 80 caracteres.' });
    if (!['duration','lifetime'].includes(kind) || (kind === 'duration' && (!Number.isInteger(duration) || duration < 1))) return json(res, 400, { ok: false, error: 'Informe uma duração válida para o produto por tempo.' });
    if (!Number.isInteger(price) || price < 0) return json(res, 400, { ok: false, error: 'Informe um preço válido.' });
    body.code = code; body.name = name; body.durationMinutes = duration; body.priceCents = price;
  }
  if (action === 'coupon') {
    body.code = String(body.code || '').trim().toUpperCase();
    if (!/^[A-Z0-9_-]{3,32}$/.test(body.code)) return json(res, 400, { ok: false, error: 'Use um código de cupom válido, com letras maiúsculas, números, hífen ou sublinhado.' });
    if (!['percent','fixed'].includes(body.discountType) || !Number.isFinite(Number(body.discountValue)) || Number(body.discountValue) <= 0) return json(res, 400, { ok: false, error: 'Informe um desconto válido.' });
  }
  if (action === 'access') {
    const email = String(body.email || '').trim().toLowerCase(); const kind = String(body.kind || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { ok: false, error: 'Informe o e-mail válido de um cliente cadastrado.' });
    if (!['duration','lifetime'].includes(kind) || (kind === 'duration' && (!body.expiresAt || new Date(body.expiresAt) <= new Date()))) return json(res, 400, { ok: false, error: 'Informe uma expiração futura para o acesso por tempo.' });
    body.email = email;
  }
  if (action === 'revokeAccess' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.userId || ''))) {
    return json(res, 400, { ok: false, error: 'Identificador de cliente inválido.' });
  }
  if (['ticketReply','ticketStatus'].includes(action) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.ticketId || ''))) return json(res, 400, { ok:false, error:'Chamado inválido.' });
  if (action === 'ticketReply' && (String(body.message || '').trim().length < 2 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'A resposta deve ter entre 2 e 3000 caracteres.' });
  if (action === 'ticketStatus' && !['open','in_progress','resolved','closed'].includes(String(body.status || ''))) return json(res, 400, { ok:false, error:'Status de chamado inválido.' });
  const actions = {
    product: ['paxinbot_owner_save_product', () => ({ p_id: body.id || null, p_code: body.code, p_name: body.name, p_description: body.description || '', p_access_kind: body.accessKind, p_duration_minutes: body.accessKind === 'lifetime' ? null : Number(body.durationMinutes), p_price_cents: Number(body.priceCents), p_active: body.active !== false })],
    coupon: ['paxinbot_owner_save_coupon', () => ({ p_id: body.id || null, p_code: body.code, p_description: body.description || '', p_discount_type: body.discountType, p_discount_value: Number(body.discountValue), p_max_redemptions: body.maxRedemptions ? Number(body.maxRedemptions) : null, p_expires_at: body.expiresAt || null, p_active: body.active !== false })],
    access: ['paxinbot_owner_grant_access', () => ({ p_email: body.email, p_kind: body.kind, p_expires_at: body.kind === 'lifetime' ? null : body.expiresAt, p_source: 'owner-panel' })],
    revokeAccess: ['paxinbot_owner_revoke_access', () => ({ p_user_id: body.userId })],
    ticketReply: ['paxinbot_owner_reply_support_ticket', () => ({ p_ticket_id:body.ticketId, p_message:String(body.message || '').trim() })],
    ticketStatus: ['paxinbot_owner_update_support_status', () => ({ p_ticket_id:body.ticketId, p_status:body.status })]
  };
  const item = actions[action]; if (!item) return json(res, 400, { ok: false, error: 'Ação inválida.' });
  const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1]() });
  if (response.ok && action === 'ticketReply' && payload?.notify && payload?.email) {
    const safeSubject = String(payload.subject || 'Chamado').replace(/[<>&]/g, '');
    const safeMessage = String(body.message || '').replace(/[&<>'"]/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' })[character]);
    await sendTransactionalEmail({ to:payload.email, subject:`Atualização no suporte — ${safeSubject}`, idempotencyKey:`support-reply/${payload.ticketId}/${sha256(body.message).slice(0,24)}`, html:`<div style="background:#080808;color:#f4f4f4;padding:32px;font-family:Arial,sans-serif"><h1 style="font-size:22px">Seu chamado recebeu uma resposta</h1><p>${safeMessage}</p><p>Entre na Área do Cliente para continuar o atendimento.</p></div>` }).catch(() => null);
  }
  return json(res, response.ok ? 200 : 400, response.ok ? { ok: true, data: payload } : { ok: false, error: safeUpstreamError(payload, 'Não foi possível salvar. Revise os dados informados.') });
};
