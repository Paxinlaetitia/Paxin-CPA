'use strict';
const crypto = require('node:crypto');
const { json, requireTrustedHost, readBodyResult, browserSession, upstream, usageRuntimeState, downloadSigningSecret, requestRateLimit, publicOrigin, sameOriginRequest, safeUpstreamError } = require('../_paxinbot');

const DEFAULT_WINDOWS_RELEASE = Object.freeze({
  path: '/releases/PaxinbotSetup.exe',
  fileName: 'PaxinbotSetup.exe',
  version: '1.0.4',
  sizeBytes: 101847870,
  sha256: '40fc88fe7edf93cbfb7f2ef9f3975f0db3cafaf07b6dbe5f0b71740c927156e7',
  expiresIn: 120
});

function getWindowsRelease() {
  let manifest = null;
  try {
    manifest = require('../releases/stable-win32-x64.json');
  } catch {
    try {
      manifest = require('../../releases/stable-win32-x64.json');
    } catch {}
  }
  const version = process.env.PAXINBOT_RELEASE_VERSION || manifest?.version || DEFAULT_WINDOWS_RELEASE.version;
  const sizeBytes = Number(process.env.PAXINBOT_RELEASE_SIZE_BYTES) || Number(manifest?.size) || DEFAULT_WINDOWS_RELEASE.sizeBytes;
  const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(1).replace('.', ',');
  return {
    path: DEFAULT_WINDOWS_RELEASE.path,
    fileName: DEFAULT_WINDOWS_RELEASE.fileName,
    version,
    sizeBytes,
    sizeFormatted: process.env.PAXINBOT_RELEASE_SIZE_FORMATTED || `${sizeMB} MB`,
    sha256: process.env.PAXINBOT_RELEASE_SHA256 || manifest?.sha256 || DEFAULT_WINDOWS_RELEASE.sha256,
    expiresIn: DEFAULT_WINDOWS_RELEASE.expiresIn
  };
}

async function signedWindowsRelease(req, res) {
  try {
    const release = getWindowsRelease();
    const expires=Math.floor(Date.now()/1000)+release.expiresIn;
    const nonce=crypto.randomBytes(18).toString('base64url');
    const canonical=`GET\n${release.path}\n${expires}\n${nonce}`;
    const signature=crypto.createHmac('sha256',downloadSigningSecret()).update(canonical).digest('base64url');
    const url=new URL(release.path,publicOrigin(req));
    url.searchParams.set('expires',String(expires)); url.searchParams.set('nonce',nonce); url.searchParams.set('signature',signature);
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    if (String(req.query?.redirect || '') === '1') {
      res.statusCode=302;
      res.setHeader('Location',url.toString());
      res.setHeader('Referrer-Policy','no-referrer');
      res.setHeader('X-Content-Type-Options','nosniff');
      return res.end();
    }
    return json(res, 200, { ok:true, data:{ url:url.toString(), fileName:release.fileName, version:release.version, sizeBytes:release.sizeBytes, sizeFormatted:release.sizeFormatted, sha256:release.sha256, expiresIn:release.expiresIn } });
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

const bootstrapQueries = Object.freeze({
  account:queries.overview,
  devices:queries.devices,
  orders:queries.orders,
  products:queries.products,
  preferences:queries.preferences,
  activity:queries.activity,
  tickets:queries.tickets,
  usageGrants:queries.usageGrants,
  promotions:queries.promotions
});

const bootstrapDefaults = Object.freeze({
  account:{ profile:{ id:'', role:'customer', display_name:'', disabled_at:null }, email:'', created_at:'' },
  devices:[],
  orders:[],
  products:[],
  preferences:{ product_updates:false, support_updates:true },
  activity:[],
  tickets:[],
  usageGrants:[],
  promotions:[]
});

async function portalBootstrap(req, res, session) {
  const started=Date.now();
  const entries=Object.entries(bootstrapQueries);
  const [accessResult, passkeyResult, ...queryResults] = await Promise.all([
    upstream('/rest/v1/rpc/paxinbot_get_my_access', { method:'POST', headers:{ authorization:`Bearer ${session.access}` }, body:{} }),
    upstream('/auth/v1/passkeys', { headers:{ authorization:`Bearer ${session.access}` } }),
    ...entries.map(([,item]) => upstream(`/rest/v1/rpc/${item[0]}`, { method:'POST', headers:{ authorization:`Bearer ${session.access}` }, body:item[1]({}) }))
  ]);

  const entitlement=accessResult.payload && typeof accessResult.payload === 'object' ? { ...accessResult.payload } : { active:false };
  if (entitlement.kind === 'usage' && /^[0-9a-f-]{36}$/i.test(String(entitlement.grantId || ''))) {
    try {
      entitlement.usageRunning=await usageRuntimeState(session.user.id, entitlement.grantId);
    } catch { entitlement.usageRunning=false; }
  }

  const data={ ...bootstrapDefaults, release: getWindowsRelease() };
  const errors={};
  queryResults.forEach((result, index) => {
    const key=entries[index][0];
    if (result.response.ok) data[key]=result.payload;
    else errors[key]=safeUpstreamError(result.payload, 'Conteúdo temporariamente indisponível.');
  });
  if (passkeyResult.response.ok) data.passkeys=Array.isArray(passkeyResult.payload) ? passkeyResult.payload.map(item => ({
    id:/^[0-9a-f-]{36}$/i.test(String(item?.id || '')) ? String(item.id) : '',
    friendlyName:String(item?.friendly_name || item?.friendlyName || 'Passkey').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0,120) || 'Passkey',
    createdAt:String(item?.created_at || item?.createdAt || '').slice(0,40),
    lastUsedAt:String(item?.last_used_at || item?.lastUsedAt || '').slice(0,40)
  })).filter(item => item.id) : [];
  else errors.passkeys='Não foi possível consultar as passkeys agora.';

  const providers=[...new Set((session.user.identities || []).map(identity => identity.provider).filter(Boolean))];
  const checkoutReady=Boolean(process.env.MERCADOPAGO_ACCESS_TOKEN && process.env.MERCADOPAGO_WEBHOOK_SECRET && process.env.SUPABASE_SECRET_KEY);
  res.setHeader('Server-Timing',`portal;dur=${Math.max(0,Date.now()-started)}`);
  return json(res, 200, {
    ok:true,
    current:{ serverNow:new Date().toISOString(), user:{ id:session.user.id, email:session.user.email, providers }, entitlement },
    data,
    checkoutReady,
    errors
  });
}

module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  if (!['GET','POST'].includes(req.method)) return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const queryAction = String(req.query?.action || 'overview');
  if (req.method === 'GET' && queryAction === 'download') return signedWindowsRelease(req, res);
  if (req.method === 'GET' && queryAction === 'release') return json(res, 200, { ok: true, data: getWindowsRelease() });
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  if (!await requestRateLimit(req, res, {
    scope:req.method === 'GET' ? 'account_read_user' : 'account_write_user',
    subject:session.user.id, limit:req.method === 'GET' ? 300 : 120, windowSeconds:600
  })) return;
  if (req.method === 'GET') {
    if (queryAction === 'bootstrap') return portalBootstrap(req, res, session);
    const item = queries[queryAction];
    if (!item) return json(res, 404, { ok: false, error: 'Consulta não encontrada.' });
    if (queryAction === 'order' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(req.query?.orderId || ''))) return json(res, 400, { ok:false, error:'Pedido inválido.' });
    const { response, payload } = await upstream(`/rest/v1/rpc/${item[0]}`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: item[1](req.query || {}) });
    const checkoutReady = Boolean(process.env.MERCADOPAGO_ACCESS_TOKEN && process.env.MERCADOPAGO_WEBHOOK_SECRET && process.env.SUPABASE_SECRET_KEY);
    return json(res, response.ok ? 200 : 503, response.ok ? { ok: true, data: payload, ...(String(req.query?.action) === 'products' ? { checkoutReady } : {}) } : { ok: false, error: safeUpstreamError(payload, 'Esta área ainda não foi ativada no banco de dados.') });
  }
  if (!sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const action = String(body.action || '');
  const requestedDeviceId = String(body.deviceIdentityId || body.sessionId || '');
  const actions = {
    profile: ['paxinbot_update_my_profile', () => ({ p_display_name: String(body.displayName || '').trim() })],
    revokeDevice: ['paxinbot_revoke_my_device', () => ({ p_session_id: requestedDeviceId })],
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
  if (action === 'revokeDevice' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestedDeviceId)) return json(res, 400, { ok:false, error:'Dispositivo inválido.' });
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
