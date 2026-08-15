'use strict';

const crypto = require('node:crypto');
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

function config() {
  const url = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = String(process.env.SUPABASE_PUBLISHABLE_KEY || '');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url) || !key.startsWith('sb_publishable_')) throw new Error('Configuração Supabase ausente no ambiente da Vercel.');
  return { url, key };
}
function serviceConfig() {
  const { url } = config();
  const key = String(process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '');
  if (!key || (!key.startsWith('sb_secret_') && key.split('.').length !== 3)) throw new Error('Chave secreta do Supabase ausente no ambiente da Vercel.');
  return { url, key };
}
function json(res, status, body, headers = {}) {
  // Vercel executa estas funções como Node HTTP handlers, não como Express.
  // Usar a API nativa evita depender de res.set()/encadeamento específico.
  res.statusCode = status;
  for (const [name, value] of Object.entries({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', ...headers })) res.setHeader(name, value);
  res.end(JSON.stringify(body));
}
function cookies(req) { return Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim().split(/=(.*)/s)).filter(([k]) => k).map(([k, v]) => [k, decodeURIComponent(v || '')])); }
function secure(req) { return process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https'); }
function sessionSecret() { return String(process.env.PAXINBOT_SESSION_SECRET || process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || ''); }
function signSessionDeadline(deadline) {
  const secret = sessionSecret(); if (!secret) return '';
  const value = String(deadline); const signature = crypto.createHmac('sha256', secret).update(value).digest('base64url'); return `${value}.${signature}`;
}
function sessionDeadline(req) {
  const raw = String(cookies(req).paxinbot_session_deadline || ''); if (!raw) return null;
  const split = raw.lastIndexOf('.'); const value = raw.slice(0, split); const signature = raw.slice(split + 1); const expected = signSessionDeadline(value); if (!expected || split < 1) return 0;
  const expectedSignature = expected.slice(expected.lastIndexOf('.') + 1); const left = Buffer.from(signature); const right = Buffer.from(expectedSignature);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return 0;
  const deadline = Number(value); return Number.isSafeInteger(deadline) && deadline > 0 ? deadline : 0;
}
function sessionCookies(req, accessToken, refreshToken, maxAge = SESSION_MAX_AGE) {
  const isClearing = maxAge <= 0; const now = Math.floor(Date.now() / 1000); const existing = isClearing ? 0 : sessionDeadline(req);
  const deadline = isClearing ? 0 : existing && existing > now ? existing : now + maxAge;
  const remaining = isClearing ? 0 : Math.max(1, Math.min(maxAge, deadline - now));
  const suffix = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${remaining}${secure(req) ? '; Secure' : ''}`;
  const result = [`paxinbot_access=${encodeURIComponent(accessToken || '')}; ${suffix}`, `paxinbot_refresh=${encodeURIComponent(refreshToken || '')}; ${suffix}`];
  const signedDeadline = isClearing ? '' : signSessionDeadline(deadline);
  result.push(`paxinbot_session_deadline=${encodeURIComponent(signedDeadline)}; ${suffix}`); return result;
}
function clearSession(req) { return sessionCookies(req, '', '', 0); }
async function upstream(path, options = {}) {
  const { url, key } = config();
  const response = await fetch(`${url}${path}`, { method: options.method || 'GET', headers: { apikey: key, 'content-type': 'application/json', ...(options.headers || {}) }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  let payload = null; try { payload = await response.json(); } catch {}
  return { response, payload };
}
async function serviceUpstream(path, options = {}) {
  const { url, key } = serviceConfig();
  const headers = { apikey: key, 'content-type': 'application/json', ...(options.headers || {}) };
  // As novas chaves sb_secret_ não são JWTs. O Bearer só é necessário para a
  // chave service_role legada; enviar sb_secret_ como Bearer causa Invalid JWT.
  if (!key.startsWith('sb_secret_')) headers.authorization = `Bearer ${key}`;
  const response = await fetch(`${url}${path}`, { method: options.method || 'GET', headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  let payload = null; try { payload = await response.json(); } catch {}
  return { response, payload };
}
async function readBody(req) {
  // O runtime pode fornecer objeto, string, Buffer ou ReadableStream. Só trate
  // como objeto já analisado quando for um registro simples; streams não têm
  // as propriedades de autenticação e precisam ser consumidos primeiro.
  const raw = req.body;
  if (raw && typeof raw === 'object' && !Buffer.isBuffer(raw) && (Object.getPrototypeOf(raw) === Object.prototype || Object.getPrototypeOf(raw) === null)) return raw;
  if (typeof raw === 'string') { try { return JSON.parse(raw || '{}'); } catch { return {}; } }
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) { try { return JSON.parse(Buffer.from(raw).toString('utf8') || '{}'); } catch { return {}; } }
  const source = raw && (typeof raw.getReader === 'function' || typeof raw[Symbol.asyncIterator] === 'function') ? raw : req;
  const chunks = [];
  if (typeof source.getReader === 'function') {
    const reader = source.getReader(); let item;
    while (!(item = await reader.read()).done) chunks.push(Buffer.from(item.value));
  } else for await (const chunk of source) chunks.push(Buffer.from(chunk));
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return {}; }
}
async function userFromAccess(access) {
  if (!access) return null;
  const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${access}` } });
  return response.ok ? payload : null;
}
async function refreshSession(refresh) {
  if (!refresh) return null;
  const { response, payload } = await upstream('/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: refresh } });
  return response.ok ? payload : null;
}
async function browserSession(req, res) {
  const deadline = sessionDeadline(req); if (deadline === 0 || (deadline && deadline <= Math.floor(Date.now() / 1000))) { res.setHeader('Set-Cookie', clearSession(req)); return null; }
  const jar = cookies(req); let access = jar.paxinbot_access; let user = await userFromAccess(access);
  if (user) return { user, access };
  const refreshed = await refreshSession(jar.paxinbot_refresh);
  if (!refreshed) return null;
  access = refreshed.access_token; user = await userFromAccess(access); if (!user) return null;
  res.setHeader('Set-Cookie', sessionCookies(req, refreshed.access_token, refreshed.refresh_token));
  return { user, access };
}
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function serverFingerprint(purpose, value) {
  const secret = sessionSecret();
  if (!secret) throw new Error('Segredo interno do servidor ausente.');
  return crypto.createHmac('sha256', secret).update(`${String(purpose)}\0${String(value)}`).digest('hex');
}
function clientAddress(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || String(req.socket?.remoteAddress || 'unknown').trim().slice(0, 128);
}
function isUuid(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '')); }
function cleanDeviceName(value) {
  const name = String(value || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80);
  return name || 'Computador Paxinbot';
}
async function serviceRateLimit(scope, subject, limit, windowSeconds) {
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_service_rate_limit', {
    method: 'POST',
    body: {
      p_scope: String(scope || '').slice(0, 40),
      p_subject_hash: serverFingerprint(scope, subject),
      p_limit: Math.max(1, Math.min(1000, Number(limit) || 1)),
      p_window_seconds: Math.max(10, Math.min(86400, Number(windowSeconds) || 60))
    }
  });
  return response.ok && payload === true;
}
function publicOrigin(req) {
  let origin = String(process.env.PUBLIC_SITE_URL || `${secure(req) ? 'https' : 'http'}://${req.headers.host || 'localhost'}`).replace(/\/$/, '');
  // O domínio configurado na Vercel usa www como host canônico. Retornos OAuth
  // no host secundário causariam redirecionamento de origem e impediriam o
  // navegador de gravar a sessão HttpOnly.
  if (origin === 'https://paxincpa.store') origin = 'https://www.paxincpa.store';
  return origin;
}
function sameOriginRequest(req) {
  const origin = String(req.headers.origin || '');
  if (!origin) return true;
  try {
    const received = new URL(origin).origin;
    const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
    const host = forwardedHost || String(req.headers.host || '').trim();
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const protocol = forwardedProto || (secure(req) ? 'https' : 'http');
    const requestOrigin = host ? new URL(`${protocol}://${host}`).origin : '';
    return received === requestOrigin || received === new URL(publicOrigin(req)).origin;
  } catch { return false; }
}
function safeUpstreamError(payload, fallback = 'Não foi possível concluir a operação.') {
  const code = String(payload?.code || '');
  const message = String(payload?.message || payload?.msg || payload?.error_description || '');
  if (code === '23505' || /duplicate key|already exists/i.test(message)) return 'Já existe um registro com esse código.';
  if (code === '23514' || /check constraint|violates constraint/i.test(message)) return 'Um ou mais dados não atendem às regras do cadastro.';
  if (code === 'PGRST202' || /function.*schema cache|could not find the function/i.test(message)) return 'A atualização do banco necessária para esta função ainda não foi aplicada.';
  if (/user_not_found/i.test(message)) return 'Nenhum cliente foi encontrado com esse e-mail.';
  if (/invalid_entitlement/i.test(message)) return 'Informe uma expiração futura para o acesso por tempo.';
  if (/product_unavailable|invalid_product/i.test(message)) return 'Esta modalidade não está mais disponível.';
  if (/product_not_payable|zero_value_checkout/i.test(message)) return 'Esta modalidade ainda não pode ser comprada pelo checkout.';
  if (/invalid_coupon|coupon_unavailable/i.test(message)) return 'O cupom é inválido, expirou ou atingiu o limite de usos.';
  if (/lifetime_already_active/i.test(message)) return 'Sua conta já possui acesso vitalício.';
  if (/checkout_rate_limited/i.test(message)) return 'Muitas tentativas de pagamento. Aguarde alguns minutos e tente novamente.';
  if (/order_not_pending/i.test(message)) return 'Este pedido não está mais aguardando pagamento.';
  if (/order_expired/i.test(message)) return 'Este pedido expirou. Inicie uma nova compra.';
  if (/receipt_unavailable/i.test(message)) return 'O comprovante só está disponível para pedidos pagos.';
  if (/invalid_ticket|invalid_message/i.test(message)) return 'Revise o assunto e a mensagem do chamado.';
  if (/ticket_rate_limited/i.test(message)) return 'Você atingiu o limite de chamados. Aguarde antes de abrir outro.';
  if (/ticket_unavailable/i.test(message)) return 'Este chamado não está disponível para essa operação.';
  return fallback;
}
function safeDeviceAuthError(payload, fallback = 'Não foi possível concluir a autorização.') {
  const message = String(payload?.message || payload?.error || '');
  if (/no_active_access/i.test(message)) return { code: 'access_required', error: 'Sua conta não possui acesso ativo ao aplicativo.' };
  if (/device_expired/i.test(message)) return { code: 'request_expired', error: 'A solicitação expirou. Inicie o login novamente no aplicativo.' };
  if (/device_consumed/i.test(message)) return { code: 'request_consumed', error: 'Esta solicitação já foi utilizada. Inicie um novo login no aplicativo.' };
  if (/device_denied/i.test(message)) return { code: 'request_denied', error: 'A autorização deste computador foi recusada.' };
  if (/device_poll_limit/i.test(message)) return { code: 'poll_limit', error: 'A solicitação excedeu o limite de tentativas. Inicie novamente.' };
  if (/device_request_invalid|invalid_device_request/i.test(message)) return { code: 'request_invalid', error: 'A solicitação do aplicativo é inválida.' };
  return { code: 'authorization_failed', error: fallback };
}
async function sendTransactionalEmail({ to, subject, html, idempotencyKey }) {
  const apiKey = String(process.env.RESEND_API_KEY || '');
  const from = String(process.env.RESEND_FROM_EMAIL || '');
  if (!apiKey || !from) return { sent:false, configured:false };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(to || '')) || !subject || !html) throw new Error('invalid_email_payload');
  const response = await fetch('https://api.resend.com/emails', {
    method:'POST', headers:{ authorization:`Bearer ${apiKey}`, 'content-type':'application/json', ...(idempotencyKey ? { 'idempotency-key':String(idempotencyKey).slice(0,256) } : {}) },
    body:JSON.stringify({ from, to:[to], subject:String(subject).slice(0,180), html })
  });
  if (!response.ok) throw new Error('email_provider_error');
  return { sent:true, configured:true };
}
module.exports = { config, serviceConfig, json, cookies, sessionCookies, clearSession, upstream, serviceUpstream, readBody, browserSession, sha256, serverFingerprint, clientAddress, isUuid, cleanDeviceName, serviceRateLimit, publicOrigin, sameOriginRequest, safeUpstreamError, safeDeviceAuthError, sendTransactionalEmail };
