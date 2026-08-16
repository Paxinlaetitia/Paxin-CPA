'use strict';

const crypto = require('node:crypto');
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
const MAX_REQUEST_BODY_BYTES = 32 * 1024;
const CSRF_COOKIE = 'paxinbot_csrf';
const CSRF_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function environmentValue(name) {
  return String(process.env[name] || '').trim();
}
function hasMinimumBytes(value, minimum) {
  return Buffer.byteLength(String(value || ''), 'utf8') >= minimum;
}

function config() {
  const url = environmentValue('SUPABASE_URL').replace(/\/$/, '');
  const key = environmentValue('SUPABASE_PUBLISHABLE_KEY');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url) || !key.startsWith('sb_publishable_')) throw new Error('Configuração Supabase ausente no ambiente da Vercel.');
  return { url, key };
}
function serviceConfig() {
  const { url } = config();
  // Não aceite nomes legados nem use outra credencial como fallback. Uma
  // função privilegiada deve falhar fechada quando a chave própria não existe.
  const key = environmentValue('SUPABASE_SECRET_KEY');
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
function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(value => value.trim().split(/=(.*)/s)).filter(([key]) => key).map(([key, value]) => {
    try { return [key, decodeURIComponent(value || '')]; } catch { return [key, '']; }
  }));
}
function secure(req) { return process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https'); }
function sessionSecret() {
  const secret = environmentValue('PAXINBOT_SESSION_SECRET');
  if (!hasMinimumBytes(secret, 32)) throw new Error('Segredo de sessão interno ausente ou inválido.');
  return secret;
}
function validateCoreEnvironment() {
  config();
  if (process.env.NODE_ENV === 'production') configuredSiteOrigin(true);
  const serviceKey = serviceConfig().key;
  const sessionKey = sessionSecret();
  const configuredSecrets = [
    ['SUPABASE_SECRET_KEY', serviceKey],
    ['PAXINBOT_SESSION_SECRET', sessionKey],
    ['MERCADOPAGO_ACCESS_TOKEN', environmentValue('MERCADOPAGO_ACCESS_TOKEN')],
    ['MERCADOPAGO_WEBHOOK_SECRET', environmentValue('MERCADOPAGO_WEBHOOK_SECRET')],
    ['RESEND_API_KEY', environmentValue('RESEND_API_KEY')]
  ].filter(([, value]) => value);
  const unique = new Set(configuredSecrets.map(([, value]) => value));
  if (unique.size !== configuredSecrets.length) throw new Error('Credenciais internas precisam ser exclusivas por finalidade.');
  return true;
}
function configuredSiteOrigin(required = false) {
  const raw = environmentValue('PUBLIC_SITE_URL');
  if (!raw) {
    if (required) throw new Error('Origem pública oficial ausente no ambiente da Vercel.');
    return '';
  }
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error('Origem pública oficial inválida.'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('Origem pública oficial inválida.');
  }
  return parsed.origin;
}
function normalizedHost(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw || raw.length > 253 || /[\s\\/]/.test(raw)) return '';
  try { return new URL(`https://${raw}`).hostname.toLowerCase(); } catch { return ''; }
}
function trustedRequestHost(req) {
  if (process.env.NODE_ENV !== 'production') return true;
  const received = normalizedHost(req.headers.host);
  if (!received) return false;
  const allowed = new Set();
  const official = configuredSiteOrigin(true);
  const officialHost = new URL(official).hostname.toLowerCase();
  allowed.add(officialHost);
  if (officialHost === 'www.paxincpa.store') allowed.add('paxincpa.store');
  if (process.env.VERCEL_ENV === 'preview') {
    const previewHost = normalizedHost(process.env.VERCEL_URL);
    if (previewHost) allowed.add(previewHost);
  }
  return allowed.has(received);
}
function requireTrustedHost(req, res) {
  if (trustedRequestHost(req)) return true;
  json(res, 404, { ok:false, code:'not_found', error:'Recurso não encontrado.' });
  return false;
}
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
class RequestBodyError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
function requestMediaType(req) {
  return String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
}
function parseRequestBodyText(text, mediaType) {
  if (!text) return {};
  if (mediaType === 'application/json') {
    let value;
    try { value = JSON.parse(text); } catch { throw new RequestBodyError(400, 'invalid_json', 'O corpo JSON da solicitação é inválido.'); }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RequestBodyError(400, 'invalid_body', 'O corpo da solicitação precisa ser um objeto JSON.');
    return value;
  }
  if (mediaType === 'application/x-www-form-urlencoded') return Object.fromEntries(new URLSearchParams(text));
  throw new RequestBodyError(415, 'unsupported_media_type', 'O formato do corpo da solicitação não é aceito.');
}
async function readBody(req, options = {}) {
  const maximum = Number(options.maximumBytes) || MAX_REQUEST_BODY_BYTES;
  const allowed = options.allowedMediaTypes || ['application/json', 'application/x-www-form-urlencoded'];
  const contentLength = Number(req.headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength > maximum) throw new RequestBodyError(413, 'payload_too_large', 'A solicitação excede o tamanho permitido.');
  const mediaType = requestMediaType(req);
  if (!allowed.includes(mediaType)) throw new RequestBodyError(415, 'unsupported_media_type', 'O formato do corpo da solicitação não é aceito.');

  // A Vercel pode entregar JSON já analisado. Mesmo nesse caso, valide tipo e
  // tamanho para que o limite não dependa da forma usada pelo runtime.
  const raw = req.body;
  if (raw && typeof raw === 'object' && !Buffer.isBuffer(raw) && !(raw instanceof Uint8Array) &&
      (Object.getPrototypeOf(raw) === Object.prototype || Object.getPrototypeOf(raw) === null)) {
    const serialized = JSON.stringify(raw);
    if (Buffer.byteLength(serialized, 'utf8') > maximum) throw new RequestBodyError(413, 'payload_too_large', 'A solicitação excede o tamanho permitido.');
    if (mediaType !== 'application/json') throw new RequestBodyError(415, 'unsupported_media_type', 'O formato do corpo da solicitação não é aceito.');
    return raw;
  }

  if (typeof raw === 'string' || Buffer.isBuffer(raw) || raw instanceof Uint8Array) {
    const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    if (buffer.length > maximum) throw new RequestBodyError(413, 'payload_too_large', 'A solicitação excede o tamanho permitido.');
    return parseRequestBodyText(buffer.toString('utf8'), mediaType);
  }

  const source = raw && (typeof raw.getReader === 'function' || typeof raw[Symbol.asyncIterator] === 'function') ? raw : req;
  const chunks = []; let total = 0;
  const append = chunk => {
    const buffer = Buffer.from(chunk); total += buffer.length;
    if (total > maximum) throw new RequestBodyError(413, 'payload_too_large', 'A solicitação excede o tamanho permitido.');
    chunks.push(buffer);
  };
  if (typeof source.getReader === 'function') {
    const reader = source.getReader(); let item;
    while (!(item = await reader.read()).done) append(item.value);
  } else for await (const chunk of source) append(chunk);
  return parseRequestBodyText(Buffer.concat(chunks).toString('utf8'), mediaType);
}
async function readBodyResult(req, res, options = {}) {
  try { return { ok: true, body: await readBody(req, options) }; }
  catch (error) {
    if (!(error instanceof RequestBodyError)) throw error;
    json(res, error.status, { ok: false, code: error.code, error: error.message });
    return { ok: false, body: null };
  }
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
function canonicalDeviceProof(value) {
  return [
    'paxinbot-device-proof-v1', value.installId, value.publicKey, value.fingerprint,
    value.fingerprintStrength, String(value.issuedAt), value.nonce, value.appVersion
  ].join('\n');
}
function verifyDeviceIdentityProof(body) {
  const proof = {
    installId: String(body?.installId || '').toLowerCase(),
    publicKey: String(body?.publicKey || ''),
    fingerprint: String(body?.fingerprint || '').toLowerCase(),
    fingerprintStrength: String(body?.fingerprintStrength || ''),
    issuedAt: Number(body?.issuedAt),
    nonce: String(body?.nonce || ''),
    appVersion: String(body?.appVersion || '').trim(),
    signature: String(body?.signature || '')
  };
  if (!isUuid(proof.installId) || !/^[A-Za-z0-9_-]{50,200}$/.test(proof.publicKey) ||
      !/^[a-f0-9]{64}$/.test(proof.fingerprint) || !['hardware', 'installation'].includes(proof.fingerprintStrength) ||
      !Number.isSafeInteger(proof.issuedAt) || Math.abs(Date.now() - proof.issuedAt) > 5 * 60 * 1000 ||
      !/^[A-Za-z0-9_-]{32}$/.test(proof.nonce) || !/^[A-Za-z0-9_-]{80,100}$/.test(proof.signature) ||
      !/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[0-9A-Za-z.-]{1,24})?$/.test(proof.appVersion)) {
    throw new Error('device_identity_invalid');
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: Buffer.from(proof.publicKey, 'base64url'), format: 'der', type: 'spki' });
  } catch { throw new Error('device_identity_invalid'); }
  if (key.asymmetricKeyType !== 'ed25519' || !crypto.verify(null, Buffer.from(canonicalDeviceProof(proof), 'utf8'), key, Buffer.from(proof.signature, 'base64url'))) {
    throw new Error('device_identity_signature_invalid');
  }
  return {
    ...proof,
    deviceKeyHash: serverFingerprint('device-key-v1', proof.publicKey),
    fingerprintHash: serverFingerprint('device-fingerprint-v1', proof.fingerprint),
    installIdHash: serverFingerprint('device-install-v1', proof.installId),
    proofNonceHash: serverFingerprint('device-proof-nonce-v1', proof.nonce)
  };
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
async function requestRateLimit(req, res, options = {}) {
  const scope = String(options.scope || '').slice(0, 40);
  const subject = String(options.subject || clientAddress(req));
  const limit = Math.max(1, Math.min(1000, Number(options.limit) || 1));
  const windowSeconds = Math.max(10, Math.min(86400, Number(options.windowSeconds) || 60));
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_service_rate_limit_v2', {
    method:'POST',
    body:{
      p_scope:scope,
      p_subject_hash:serverFingerprint(scope, subject),
      p_limit:limit,
      p_window_seconds:windowSeconds,
      p_cost:1
    }
  });
  const allowed = payload?.allowed === true;
  const remaining = Number(payload?.remaining);
  const resetAfter = Number(payload?.resetAfter);
  if (!response.ok || !Number.isInteger(remaining) || remaining < 0 || !Number.isInteger(resetAfter) || resetAfter < 1 || resetAfter > windowSeconds) {
    json(res, 503, { ok:false, code:'rate_limit_unavailable', error:'A proteção contra abuso está temporariamente indisponível. Tente novamente em instantes.' }, { 'retry-after':'10' });
    return false;
  }
  res.setHeader('RateLimit-Policy', `${limit};w=${windowSeconds}`);
  res.setHeader('RateLimit', `limit=${limit}, remaining=${Math.min(limit, remaining)}, reset=${resetAfter}`);
  if (allowed) return true;
  json(res, 429, {
    ok:false, code:'rate_limited', retryAfter:resetAfter,
    error:String(options.message || 'Muitas solicitações. Aguarde antes de tentar novamente.')
  }, { 'retry-after':String(resetAfter) });
  return false;
}
function publicOrigin(req) {
  let origin = configuredSiteOrigin(process.env.NODE_ENV === 'production') || `${secure(req) ? 'https' : 'http'}://${req.headers.host || 'localhost'}`;
  const requestHost = normalizedHost(req.headers.host);
  const previewHost = process.env.VERCEL_ENV === 'preview' ? normalizedHost(process.env.VERCEL_URL) : '';
  if (previewHost && requestHost === previewHost) origin = `https://${previewHost}`;
  // O domínio configurado na Vercel usa www como host canônico. Retornos OAuth
  // no host secundário causariam redirecionamento de origem e impediriam o
  // navegador de gravar a sessão HttpOnly.
  if (origin === 'https://paxincpa.store') origin = 'https://www.paxincpa.store';
  return origin;
}
function appendSetCookie(res, value) {
  const existing = typeof res.getHeader === 'function' ? res.getHeader('Set-Cookie') : undefined;
  const values = existing ? (Array.isArray(existing) ? existing : [existing]) : [];
  res.setHeader('Set-Cookie', [...values, value]);
}
function issueCsrfToken(req, res) {
  const current = String(cookies(req)[CSRF_COOKIE] || '');
  const token = CSRF_TOKEN_PATTERN.test(current) ? current : crypto.randomBytes(32).toString('base64url');
  const suffix = `Path=/; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}${secure(req) ? '; Secure' : ''}`;
  appendSetCookie(res, `${CSRF_COOKIE}=${encodeURIComponent(token)}; ${suffix}`);
  return token;
}
function sameOriginRequest(req) {
  const origin = String(req.headers.origin || '');
  const referer = String(req.headers.referer || '');
  if (!origin && !referer) return false;
  try {
    const received = new URL(origin || referer).origin;
    const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
    const host = forwardedHost || String(req.headers.host || '').trim();
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const protocol = forwardedProto || (secure(req) ? 'https' : 'http');
    const requestOrigin = host ? new URL(`${protocol}://${host}`).origin : '';
    const originMatches = received === requestOrigin || received === new URL(publicOrigin(req)).origin;
    const token = String(req.headers['x-paxinbot-csrf'] || '');
    const cookieToken = String(cookies(req)[CSRF_COOKIE] || '');
    if (!originMatches || !CSRF_TOKEN_PATTERN.test(token) || !CSRF_TOKEN_PATTERN.test(cookieToken)) return false;
    const left = Buffer.from(token); const right = Buffer.from(cookieToken);
    return left.length === right.length && crypto.timingSafeEqual(left, right);
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
  if (/invalid_usage_duration/i.test(message)) return 'Informe um saldo de uso válido.';
  if (/usage_grant_not_found|usage_grant_unavailable/i.test(message)) return 'Este saldo não está mais disponível para ativação.';
  if (/usage_grant_already_active/i.test(message)) return 'Já existe um saldo ativo nesta conta.';
  if (/existing_access_must_finish/i.test(message)) return 'O acesso atual precisa terminar antes de ativar outro saldo.';
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
  const upstreamCode = String(payload?.code || '').toUpperCase();
  const message = String(payload?.message || payload?.error || '');
  if (/device_banned/i.test(message)) return { code: 'device_banned', error: 'Este computador está bloqueado para usar o Paxinbot. Entre em contato com o suporte.' };
  if (/device_identity_mismatch/i.test(message)) return { code: 'device_identity_mismatch', error: 'A identidade segura deste computador não corresponde ao cadastro anterior.' };
  if (/promotion_device_already_used/i.test(message)) return { code: 'promotion_device_already_used', error: 'O presente de boas-vindas já foi utilizado neste computador.' };
  if (/device_identity_invalid|device_identity_signature_invalid|device_proof_replayed/i.test(message)) return { code: 'device_identity_invalid', error: 'A identificação segura deste computador não pôde ser validada.' };
  if (/no_active_access/i.test(message)) return { code: 'access_required', error: 'Sua conta não possui acesso ativo ao aplicativo.' };
  if (/device_expired/i.test(message)) return { code: 'request_expired', error: 'A solicitação expirou. Inicie o login novamente no aplicativo.' };
  if (/device_consumed/i.test(message)) return { code: 'request_consumed', error: 'Esta solicitação já foi utilizada. Inicie um novo login no aplicativo.' };
  if (/device_denied/i.test(message)) return { code: 'request_denied', error: 'A autorização deste computador foi recusada.' };
  if (/device_poll_limit/i.test(message)) return { code: 'poll_limit', error: 'A solicitação excedeu o limite de tentativas. Inicie novamente.' };
  if (/device_request_invalid|invalid_device_request/i.test(message)) return { code: 'request_invalid', error: 'A solicitação do aplicativo é inválida.' };
  const databaseErrors = {
    '23502': 'A estrutura da sessão está incompleta no banco.',
    '23503': 'A conta vinculada à sessão não está mais disponível.',
    '23505': 'A sessão já foi criada. Inicie uma nova autorização.',
    '23514': 'A sessão não atende às regras atuais do banco.',
    '42501': 'O serviço não possui permissão para concluir a sessão.',
    '42702': 'A função de acesso instalada no banco está incompatível.',
    '42703': 'A migração do banco está incompleta.',
    '42883': 'Uma função necessária ainda não foi instalada no banco.',
    'PGRST202': 'A atualização do banco ainda não foi reconhecida pelo servidor.'
  };
  if (databaseErrors[upstreamCode]) return { code: 'database_incompatible', diagnosticCode: upstreamCode, error: `${databaseErrors[upstreamCode]} Código ${upstreamCode}.` };
  const diagnosticCode = /^[A-Z0-9]{3,12}$/.test(upstreamCode) ? upstreamCode : 'AUTH-SESSION';
  return { code: 'authorization_failed', diagnosticCode, error: `${fallback} Código ${diagnosticCode}.` };
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
// Em produção, uma configuração central ausente não pode ser descoberta apenas
// depois de uma operação comercial ou autorização de dispositivo.
if (process.env.NODE_ENV === 'production') validateCoreEnvironment();

module.exports = { config, serviceConfig, sessionSecret, validateCoreEnvironment, configuredSiteOrigin, trustedRequestHost, requireTrustedHost, json, cookies, sessionCookies, clearSession, upstream, serviceUpstream, readBody, readBodyResult, browserSession, sha256, serverFingerprint, canonicalDeviceProof, verifyDeviceIdentityProof, clientAddress, isUuid, cleanDeviceName, serviceRateLimit, requestRateLimit, publicOrigin, issueCsrfToken, sameOriginRequest, safeUpstreamError, safeDeviceAuthError, sendTransactionalEmail };
