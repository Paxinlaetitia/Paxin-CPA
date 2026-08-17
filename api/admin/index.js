'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { json, requireTrustedHost, readBodyResult, browserSession, upstream, requestRateLimit, sameOriginRequest, safeUpstreamError, sendTransactionalEmail, sha256, clientAddress, recordSiteSecurityEvent } = require('../_paxinbot');
function hiddenAdminResponse(res) {
  res.statusCode = 302;
  res.setHeader('location', '/');
  res.setHeader('cache-control', 'private, no-store, max-age=0');
  res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
  return res.end();
}
function protectedAdminFile(res, name, contentType) {
  const file = path.join(__dirname, '_assets', name);
  res.statusCode = 200;
  res.setHeader('content-type', contentType);
  res.setHeader('cache-control', 'private, no-store, max-age=0');
  res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
  res.setHeader('x-content-type-options', 'nosniff');
  if (name === 'page.txt') res.setHeader('content-security-policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  return res.end(fs.readFileSync(file));
}
const queries = {
  overview: ['paxinbot_owner_overview', () => ({})],
  users: ['paxinbot_owner_list_users', q => (q.q ? { p_query: String(q.q) } : {})],
  products: ['paxinbot_owner_list_products', () => ({})],
  coupons: ['paxinbot_owner_list_coupons', () => ({})],
  promotions: ['paxinbot_owner_list_promotions', () => ({})],
  devices: ['paxinbot_owner_list_device_identities', q => (q.q ? { p_query: String(q.q) } : {})],
  security: ['paxinbot_owner_list_security_risk', q => (q.q ? { p_query: String(q.q) } : {})],
  siteSecurity: ['paxinbot_owner_list_site_security_events', () => ({ p_limit: 200 })],
  orders: ['paxinbot_owner_list_orders', q => (q.q ? { p_query: String(q.q) } : {})],
  audit: ['paxinbot_owner_list_audit', () => ({})],
  tickets: ['paxinbot_owner_list_support_tickets', () => ({})]
};
module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  const view = String(req.query?.view || '');
  if (view === 'hidden') return hiddenAdminResponse(res);
  const session = await browserSession(req, res);
  if (!session) {
    await recordSiteSecurityEvent(req, { eventType:'admin.access_denied', severity:45, subject:clientAddress(req), details:{ reasonCode:'session_missing', outcome:'hidden', status:'404' } });
    return view ? hiddenAdminResponse(res) : json(res, 401, { ok: false, error: 'Entre com a conta do proprietário.' });
  }
  const ownerCheck = await upstream('/rest/v1/rpc/paxinbot_is_owner', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
  if (!ownerCheck.response.ok || ownerCheck.payload !== true) {
    await recordSiteSecurityEvent(req, { eventType:'admin.access_denied', severity:60, actorUserId:session.user.id, details:{ reasonCode:'owner_required', outcome:'hidden', status:'404' } });
    return view ? hiddenAdminResponse(res) : json(res, 403, { ok: false, error: 'Esta conta está autenticada, mas ainda não foi registrada como proprietária no Supabase.' });
  }
  if (req.method === 'GET' && view === 'page') return protectedAdminFile(res, 'page.txt', 'text/html; charset=utf-8');
  if (req.method === 'GET' && view === 'asset') {
    if (req.query?.name === 'style') return protectedAdminFile(res, 'style.txt', 'text/css; charset=utf-8');
    if (req.query?.name === 'client') return protectedAdminFile(res, 'client.txt', 'text/javascript; charset=utf-8');
    return hiddenAdminResponse(res);
  }
  if (req.method === 'GET') {
    if (!await requestRateLimit(req, res, { scope:'admin_read_user', subject:session.user.id, limit:600, windowSeconds:600 })) return;
    const item = queries[String(req.query?.action || 'overview')]; if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
    const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1](req.query || {}) });
    return json(res, response.ok ? 200 : 403, response.ok ? { ok: true, data: payload, adminPath: '/gestao/e7fc8a8f64e6e0aed8e92b6a' } : { ok: false, error: 'O painel não encontrou as funções de proprietário no banco. Execute a migração principal novamente.' });
  }
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  if (!await requestRateLimit(req, res, { scope:'admin_write_user', subject:session.user.id, limit:120, windowSeconds:600 })) return;
  if (!sameOriginRequest(req)) {
    await recordSiteSecurityEvent(req, { eventType:'csrf.rejected', severity:55, actorUserId:session.user.id, details:{ reasonCode:'admin_origin_or_token', outcome:'blocked', method:'POST', status:'403' } });
    return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  }
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const action = String(body.action || '');
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
  if (action === 'promotion') {
    body.code = String(body.code || '').trim().toLowerCase();
    body.name = String(body.name || '').trim(); body.headline = String(body.headline || '').trim(); body.description = String(body.description || '').trim();
    body.rewardSeconds = Number(body.rewardSeconds); body.maxClaims = body.maxClaims ? Number(body.maxClaims) : null;
    if (!/^[a-z0-9_-]{3,40}$/.test(body.code)) return json(res, 400, { ok:false, error:'Use um código interno válido de 3 a 40 caracteres.' });
    if (body.name.length < 3 || body.name.length > 80 || body.headline.length < 3 || body.headline.length > 120 || body.description.length > 500) return json(res, 400, { ok:false, error:'Revise o nome, o título e a descrição da promoção.' });
    if (!['new_accounts','all_clients'].includes(String(body.audience || '')) || !Number.isInteger(body.rewardSeconds) || body.rewardSeconds < 60 || body.rewardSeconds > 315360000) return json(res, 400, { ok:false, error:'Informe o público e uma duração válida.' });
    if (body.maxClaims !== null && (!Number.isInteger(body.maxClaims) || body.maxClaims < 1)) return json(res, 400, { ok:false, error:'O limite de resgates deve ser um número positivo.' });
    if (body.startsAt && !Number.isFinite(Date.parse(body.startsAt))) return json(res, 400, { ok:false, error:'Data inicial inválida.' });
    if (body.endsAt && !Number.isFinite(Date.parse(body.endsAt))) return json(res, 400, { ok:false, error:'Data final inválida.' });
    if (body.startsAt && body.endsAt && Date.parse(body.endsAt) <= Date.parse(body.startsAt)) return json(res, 400, { ok:false, error:'A data final deve ser posterior à inicial.' });
  }
  if (action === 'access') {
    const email = String(body.email || '').trim().toLowerCase(); const kind = String(body.kind || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, 400, { ok: false, error: 'Informe o e-mail válido de um cliente cadastrado.' });
    const durationSeconds = Number(body.durationSeconds);
    if (!['usage','lifetime'].includes(kind) || (kind === 'usage' && (!Number.isInteger(durationSeconds) || durationSeconds < 60 || durationSeconds > 315360000))) return json(res, 400, { ok: false, error: 'Informe um saldo de uso entre 1 minuto e 10 anos.' });
    body.email = email;
    body.durationSeconds = durationSeconds;
  }
  if (['revokeAccess','kickUser','resetUserDevices'].includes(action) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.userId || ''))) {
    return json(res, 400, { ok: false, error: 'Identificador de cliente inválido.' });
  }
  if (action === 'userBan') {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.userId || ''))) return json(res, 400, { ok:false, error:'Identificador de cliente inválido.' });
    body.banned = body.banned === true;
    body.reason = String(body.reason || '').trim();
    if (body.banned && (body.reason.length < 3 || body.reason.length > 200)) return json(res, 400, { ok:false, error:'Informe um motivo de bloqueio entre 3 e 200 caracteres.' });
  }
  if (['approveOrder','refundOrder'].includes(action) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.orderId || ''))) {
    return json(res, 400, { ok: false, error: 'Identificador de pedido inválido.' });
  }
  if (action === 'deviceBan') {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.deviceIdentityId || ''))) return json(res, 400, { ok:false, error:'Identificador de dispositivo inválido.' });
    body.banned = body.banned === true;
    body.reason = String(body.reason || '').trim();
    if (body.banned && (body.reason.length < 3 || body.reason.length > 200)) return json(res, 400, { ok:false, error:'Informe um motivo de bloqueio entre 3 e 200 caracteres.' });
  }
  if (action === 'riskReset' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.deviceIdentityId || ''))) {
    return json(res, 400, { ok:false, error:'Identificador de risco inválido.' });
  }
  if (['ticketReply','ticketStatus'].includes(action) && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(body.ticketId || ''))) return json(res, 400, { ok:false, error:'Chamado inválido.' });
  if (action === 'ticketReply' && (String(body.message || '').trim().length < 2 || String(body.message || '').trim().length > 3000)) return json(res, 400, { ok:false, error:'A resposta deve ter entre 2 e 3000 caracteres.' });
  if (action === 'ticketStatus' && !['open','in_progress','resolved','closed'].includes(String(body.status || ''))) return json(res, 400, { ok:false, error:'Status de chamado inválido.' });
  const actions = {
    product: ['paxinbot_owner_save_product', () => ({ p_id: body.id || null, p_code: body.code, p_name: body.name, p_description: body.description || '', p_access_kind: body.accessKind, p_duration_minutes: body.accessKind === 'lifetime' ? null : Number(body.durationMinutes), p_price_cents: Number(body.priceCents), p_active: body.active !== false })],
    coupon: ['paxinbot_owner_save_coupon', () => ({ p_id: body.id || null, p_code: body.code, p_description: body.description || '', p_discount_type: body.discountType, p_discount_value: Number(body.discountValue), p_max_redemptions: body.maxRedemptions ? Number(body.maxRedemptions) : null, p_expires_at: body.expiresAt || null, p_active: body.active !== false })],
    promotion: ['paxinbot_owner_save_promotion', () => ({ p_id:body.id || null,p_code:body.code,p_name:body.name,p_headline:body.headline,p_description:body.description || '',p_audience:body.audience,p_reward_seconds:body.rewardSeconds,p_starts_at:body.startsAt || null,p_ends_at:body.endsAt || null,p_max_claims:body.maxClaims,p_active:body.active === true })],
    access: body.kind === 'lifetime'
      ? ['paxinbot_owner_grant_access', () => ({ p_email: body.email, p_kind: 'lifetime', p_expires_at: null, p_source: 'owner-panel' })]
      : ['paxinbot_owner_grant_usage', () => ({ p_email: body.email, p_total_seconds: body.durationSeconds, p_source: 'owner-panel' })],
    revokeAccess: ['paxinbot_owner_revoke_access', () => ({ p_user_id: body.userId })],
    kickUser: ['paxinbot_owner_kick_user', () => ({ p_user_id: body.userId })],
    userBan: ['paxinbot_owner_set_user_ban', () => ({ p_user_id: body.userId, p_banned: body.banned, p_reason: body.banned ? body.reason : null })],
    resetUserDevices: ['paxinbot_owner_reset_user_devices', () => ({ p_user_id: body.userId })],
    approveOrder: ['paxinbot_owner_approve_order', () => ({ p_order_id: body.orderId })],
    refundOrder: ['paxinbot_owner_refund_order', () => ({ p_order_id: body.orderId })],
    deviceBan: ['paxinbot_owner_set_device_ban', () => ({ p_device_identity_id:body.deviceIdentityId,p_banned:body.banned,p_reason:body.banned ? body.reason : null })],
    riskReset: ['paxinbot_owner_reset_security_risk', () => ({ p_device_identity_id:body.deviceIdentityId })],
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
