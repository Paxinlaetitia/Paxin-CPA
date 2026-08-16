'use strict';

const { config, json, cookies, sessionCookies, clearSession, upstream, serviceUpstream, readBodyResult, browserSession, clientAddress, requestRateLimit, publicOrigin, issueCsrfToken, sameOriginRequest } = require('../_paxinbot');

function temporaryVerificationCookies(req, values = {}, maxAge = 10 * 60) {
  const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
  const suffix = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${isSecure ? '; Secure' : ''}`;
  const entries = { paxinbot_verify_access: values.accessToken || '', paxinbot_verify_email: values.email || '', paxinbot_verify_purpose: values.purpose || '' };
  return Object.entries(entries).map(([name, value]) => `${name}=${encodeURIComponent(value)}; ${suffix}`);
}
function clearTemporaryVerification(req) { return temporaryVerificationCookies(req, {}, 0); }
function clearLegacyMfa(req) {
  const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
  const suffix = `Path=/; HttpOnly; SameSite=Strict; Max-Age=0${isSecure ? '; Secure' : ''}`;
  return [`paxinbot_mfa_access=; ${suffix}`, `paxinbot_mfa_refresh=; ${suffix}`];
}
function maskedEmail(email) {
  const [name = '', domain = ''] = String(email || '').split('@');
  return domain ? `${name.slice(0, 2)}${'*'.repeat(Math.max(2, Math.min(6, name.length - 2)))}@${domain}` : '';
}
function friendlyCodeError(payload, fallback) {
  const message = String(payload?.msg || payload?.message || payload?.error_description || '');
  if (/expired|token.*expired/i.test(message)) return 'O código expirou. Solicite um novo código.';
  if (/invalid.*token|token.*invalid|otp/i.test(message)) return 'O código informado é inválido ou já expirou.';
  if (/rate.?limit|too many/i.test(message)) return 'Muitas solicitações. Aguarde alguns minutos antes de tentar novamente.';
  return fallback;
}
function actionOf(req) {
  if (req.query?.action) return String(req.query.action);
  return new URL(req.url || '/', 'http://localhost').pathname.split('/').filter(Boolean).pop() || '';
}
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,22}[a-z0-9])?$/;
function normalizeUsername(value) { return String(value || '').trim().toLowerCase(); }
async function persistSignupUsername(accessToken, username) {
  if (!accessToken || !USERNAME_PATTERN.test(username)) return false;
  const { response } = await upstream('/rest/v1/rpc/paxinbot_update_my_profile', { method: 'POST', headers: { authorization: `Bearer ${accessToken}` }, body: { p_display_name: username } });
  return response.ok;
}
async function authRate(req, res, scope, limit, windowSeconds, identity = '') {
  const subject = identity ? `${clientAddress(req)}\0${String(identity).toLowerCase()}` : clientAddress(req);
  return requestRateLimit(req, res, {
    scope, subject, limit, windowSeconds,
    message:'Muitas tentativas. Aguarde antes de tentar novamente.'
  });
}

module.exports = async (req, res) => {
  const action = actionOf(req);
  if (action === 'csrf') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    return json(res, 200, { ok: true, token: issueCsrfToken(req, res) });
  }
  const protectedPosts = ['login', 'logout', 'recover', 'signup', 'session', 'password', 'verify-email-code', 'resend-email-code'];
  if (req.method === 'POST' && protectedPosts.includes(action) && !sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });

  if (action === 'login') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    const purpose = String(body.purpose || '') === 'passkey' ? 'passkey' : 'login';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 1 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe seu e-mail e sua senha.' });
    if (!await authRate(req, res, 'auth_login_ip', 30, 900) || !await authRate(req, res, 'auth_login_pair', 8, 900, email)) return;
    const authenticated = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
    if (!authenticated.response.ok || !authenticated.payload?.access_token || !authenticated.payload?.user?.id) return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
    const verifiedEmail = String(authenticated.payload.user.email || email).trim().toLowerCase();
    const sent = await upstream('/auth/v1/otp', { method: 'POST', body: { email: verifiedEmail, create_user: false } });
    if (!sent.response.ok) return json(res, 503, { ok: false, error: friendlyCodeError(sent.payload, 'Não foi possível enviar o código de verificação.') });
    res.setHeader('Set-Cookie', temporaryVerificationCookies(req, { accessToken: authenticated.payload.access_token, email: verifiedEmail, purpose }));
    return json(res, 200, { ok: true, verificationRequired: true, flow: 'login', emailMasked: maskedEmail(verifiedEmail), message: 'Enviamos um código de seis dígitos para seu e-mail.' });
  }

  if (action === 'verify-email-code') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const jar = cookies(req); const code = String(body.code || '').replace(/\s/g, '');
    const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || ''); const temporaryAccess = String(jar.paxinbot_verify_access || '');
    if (!/^[0-9]{6}$/.test(code)) return json(res, 400, { ok: false, error: 'Informe o código de seis dígitos enviado ao seu e-mail.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup', 'passkey'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (!await authRate(req, res, 'auth_verify_pair', 10, 600, email)) return;
    let passwordUser = null;
    if (purpose !== 'signup') {
      if (!temporaryAccess) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      const temporaryUser = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${temporaryAccess}` } });
      if (!temporaryUser.response.ok || !temporaryUser.payload?.id) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
      passwordUser = temporaryUser.payload;
    }
    const verified = await upstream('/auth/v1/verify', { method: 'POST', body: { email, token: code, type: purpose === 'signup' ? 'signup' : 'email' } });
    if (!verified.response.ok || !verified.payload?.access_token || !verified.payload?.user?.id) return json(res, 401, { ok: false, error: friendlyCodeError(verified.payload, 'Não foi possível confirmar o código.') });
    if (passwordUser && passwordUser.id !== verified.payload.user.id) return json(res, 401, { ok: false, error: 'O código não corresponde à conta confirmada pela senha.' });
    if (purpose === 'signup') {
      const username = normalizeUsername(verified.payload.user.user_metadata?.display_name);
      if (USERNAME_PATTERN.test(username)) await persistSignupUsername(verified.payload.access_token, username).catch(() => false);
    }
    res.setHeader('Set-Cookie', [...sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]);
    const result = { ok: true, confirmed: true, flow: purpose === 'signup' ? 'signup' : 'login' };
    if (purpose === 'passkey') result.passkeySession = { accessToken: verified.payload.access_token, refreshToken: verified.payload.refresh_token };
    return json(res, 200, result);
  }

  if (action === 'resend-email-code') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const jar = cookies(req); const email = String(jar.paxinbot_verify_email || '').trim().toLowerCase(); const purpose = String(jar.paxinbot_verify_purpose || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup', 'passkey'].includes(purpose)) return json(res, 401, { ok: false, error: 'A confirmação expirou. Inicie novamente.' });
    if (purpose !== 'signup' && !jar.paxinbot_verify_access) return json(res, 401, { ok: false, error: 'A confirmação expirou. Entre novamente com sua senha.' });
    if (!await authRate(req, res, 'auth_resend_pair', 3, 600, email)) return;
    const sent = purpose === 'signup' ? await upstream('/auth/v1/resend', { method: 'POST', body: { type: 'signup', email } }) : await upstream('/auth/v1/otp', { method: 'POST', body: { email, create_user: false } });
    if (!sent.response.ok) return json(res, 429, { ok: false, error: friendlyCodeError(sent.payload, 'Não foi possível reenviar o código agora.') });
    return json(res, 200, { ok: true, message: 'Um novo código foi enviado ao seu e-mail.' });
  }

  if (action === 'logout') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
    res.setHeader('Set-Cookie', [...clearSession(req), ...clearTemporaryVerification(req), ...clearLegacyMfa(req)]); return json(res, 200, { ok: true });
  }
  if (action === 'me') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
    const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_get_my_access', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    const providers = [...new Set((session.user.identities || []).map(identity => identity.provider).filter(Boolean))];
    const entitlement = response.ok && payload && typeof payload === 'object' ? { ...payload } : { active: false };
    if (response.ok && entitlement.kind === 'usage' && /^[0-9a-f-]{36}$/i.test(String(entitlement.grantId || ''))) {
      try {
        const filters = new URLSearchParams({
          select: 'last_seen_at,usage_paused_at',
          user_id: `eq.${session.user.id}`,
          usage_grant_id: `eq.${entitlement.grantId}`,
          revoked_at: 'is.null',
          order: 'last_seen_at.desc',
          limit: '1'
        });
        const runtime = await serviceUpstream(`/rest/v1/desktop_sessions?${filters.toString()}`);
        const desktop = runtime.response.ok && Array.isArray(runtime.payload) ? runtime.payload[0] : null;
        const lastSeen = Date.parse(desktop?.last_seen_at || '');
        entitlement.usageRunning = Boolean(desktop && !desktop.usage_paused_at && Number.isFinite(lastSeen) && Date.now() - lastSeen <= 25000);
      } catch { entitlement.usageRunning = false; }
    }
    return json(res, response.ok ? 200 : 503, { ok: response.ok, serverNow: new Date().toISOString(), user: { id: session.user.id, email: session.user.email, providers }, entitlement });
  }
  if (action === 'recover') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const email = String(parsed.body.email || '').trim().toLowerCase();
    if (!await authRate(req, res, 'auth_recover_ip', 10, 3600)) return;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (!await authRate(req, res, 'auth_recover_pair', 3, 3600, email)) return;
      await upstream('/auth/v1/recover', { method: 'POST', body: { email, redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=recovery` } });
    }
    return json(res, 200, { ok: true, message: 'Se existir uma conta para este e-mail, enviaremos as instruções.' });
  }
  if (action === 'signup') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const username = normalizeUsername(body.username); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    if (!USERNAME_PATTERN.test(username)) return json(res, 400, { ok: false, error: 'Use um nome de usuário de 3 a 24 caracteres, com letras, números, ponto, hífen ou sublinhado.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe um e-mail válido e uma senha com pelo menos 10 caracteres.' });
    if (!await authRate(req, res, 'auth_signup_ip', 10, 3600) || !await authRate(req, res, 'auth_signup_pair', 3, 3600, email)) return;
    const { response, payload } = await upstream('/auth/v1/signup', { method: 'POST', body: { email, password, data: { display_name: username }, email_redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=signup` } });
    if (!response.ok) return json(res, 400, { ok: false, error: 'Não foi possível criar a conta com esses dados.' });
    if (payload?.access_token && payload?.user?.email_confirmed_at) {
      await persistSignupUsername(payload.access_token, username).catch(() => false);
      res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
      return json(res, 200, { ok: true, confirmed: true, message: 'Conta criada e confirmada.' });
    }
    res.setHeader('Set-Cookie', temporaryVerificationCookies(req, { email, purpose: 'signup' }));
    return json(res, 200, { ok: true, verificationRequired: true, flow: 'signup', emailMasked: maskedEmail(email), message: 'Enviamos um código de seis dígitos para confirmar seu e-mail.' });
  }
  if (action === 'session') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const accessToken = String(body.accessToken || ''); const receivedRefreshToken = String(body.refreshToken || '');
    if (accessToken.length < 80) return json(res, 400, { ok: false, error: 'Sessão de autenticação inválida.' });
    if (!await authRate(req, res, 'auth_session_ip', 30, 600)) return;
    const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${accessToken}` } });
    if (!response.ok || !payload?.id) return json(res, 401, { ok: false, error: 'Não foi possível validar a sessão.' });
    const refreshToken = receivedRefreshToken.length >= 20 ? receivedRefreshToken : '';
    res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken, refreshToken ? 60 * 60 * 24 * 7 : 60 * 60));
    return json(res, 200, { ok: true, renewable: Boolean(refreshToken) });
  }
  if (action === 'password') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Sua sessão expirou. Entre novamente para alterar a senha.' });
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body; const value = String(body.password || ''); const currentPassword = String(body.currentPassword || '');
    if (value.length < 10 || value.length > 128 || currentPassword.length < 1 || currentPassword.length > 128) return json(res, 400, { ok: false, error: 'Confirme a senha atual e use uma nova senha entre 10 e 128 caracteres.' });
    if (!await authRate(req, res, 'auth_password_user', 8, 900, session.user.id)) return;
    const reauthenticated = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email: session.user.email, password: currentPassword } });
    if (!reauthenticated.response.ok || reauthenticated.payload?.user?.id !== session.user.id) return json(res, 401, { ok: false, error: 'A senha atual está incorreta.' });
    const { response, payload } = await upstream('/auth/v1/user', { method: 'PUT', headers: { authorization: `Bearer ${session.access}` }, body: { password: value } });
    if (!response.ok) return json(res, 400, { ok: false, error: payload?.msg || 'Não foi possível atualizar a senha.' });
    return json(res, 200, { ok: true });
  }
  if (action === 'config') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const { url, key } = config(); return json(res, 200, { ok: true, url, key });
  }
  if (action === 'google') {
    if (req.method !== 'GET') { res.statusCode = 405; res.end(); return; }
    if (!await authRate(req, res, 'auth_google_ip', 30, 600)) return;
    const { url } = config(); const target = new URL(`${url}/auth/v1/authorize`); const intent = String(req.query?.intent || '') === 'passkey' ? 'passkey' : 'google';
    target.searchParams.set('provider', 'google'); target.searchParams.set('redirect_to', `${publicOrigin(req)}/auth-callback.html?flow=${intent}`);
    res.writeHead(302, { Location: target.toString(), 'cache-control': 'no-store' }); res.end(); return;
  }
  return json(res, 404, { ok: false, error: 'Rota não encontrada.' });
};
