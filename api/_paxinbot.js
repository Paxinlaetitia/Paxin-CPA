'use strict';

const crypto = require('node:crypto');

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
function sessionCookies(req, accessToken, refreshToken, maxAge = 60 * 60 * 24 * 30) {
  const suffix = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`;
  return [`paxinbot_access=${encodeURIComponent(accessToken || '')}; ${suffix}`, `paxinbot_refresh=${encodeURIComponent(refreshToken || '')}; ${suffix}`];
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
  const jar = cookies(req); let access = jar.paxinbot_access; let user = await userFromAccess(access);
  if (user) return { user, access };
  const refreshed = await refreshSession(jar.paxinbot_refresh);
  if (!refreshed) return null;
  access = refreshed.access_token; user = await userFromAccess(access); if (!user) return null;
  res.setHeader('Set-Cookie', sessionCookies(req, refreshed.access_token, refreshed.refresh_token));
  return { user, access };
}
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
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
  try { return new URL(origin).origin === publicOrigin(req); } catch { return false; }
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
module.exports = { config, serviceConfig, json, cookies, sessionCookies, clearSession, upstream, serviceUpstream, readBody, browserSession, sha256, publicOrigin, sameOriginRequest, safeUpstreamError, sendTransactionalEmail };
