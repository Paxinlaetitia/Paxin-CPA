'use strict';

const { config, json, cookies, sessionCookies, clearSession, upstream, readBody, browserSession, publicOrigin, sameOriginRequest } = require('../_paxinbot');

function temporaryMfaCookies(req, accessToken, refreshToken, maxAge = 10 * 60) {
  const isSecure = process.env.NODE_ENV === 'production' || String(req.headers['x-forwarded-proto'] || '').includes('https');
  const suffix = `Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isSecure ? '; Secure' : ''}`;
  return [`paxinbot_mfa_access=${encodeURIComponent(accessToken || '')}; ${suffix}`, `paxinbot_mfa_refresh=${encodeURIComponent(refreshToken || '')}; ${suffix}`];
}

function clearTemporaryMfa(req) { return temporaryMfaCookies(req, '', '', 0); }
function verifiedTotpFactors(user) { return (user?.factors || []).filter(factor => factor.factor_type === 'totp' && factor.status === 'verified'); }
function jwtClaims(token) {
  try { return JSON.parse(Buffer.from(String(token || '').split('.')[1], 'base64url').toString('utf8')); } catch { return {}; }
}
function friendlyAuthError(payload, fallback) {
  const message = String(payload?.msg || payload?.message || payload?.error_description || '');
  if (/expired|challenge.*not found/i.test(message)) return 'O código expirou. Inicie a verificação novamente.';
  if (/invalid.*code|code.*invalid|totp/i.test(message)) return 'O código informado é inválido ou já expirou.';
  if (/factor.*already|already.*factor/i.test(message)) return 'Já existe uma verificação em duas etapas configurada.';
  return fallback;
}

function actionOf(req) {
  if (req.query?.action) return String(req.query.action);
  return new URL(req.url || '/', 'http://localhost').pathname.split('/').filter(Boolean).pop() || '';
}

module.exports = async (req, res) => {
  const action = actionOf(req);
  if (req.method === 'POST' && ['login', 'logout', 'recover', 'signup', 'session', 'password', 'mfa-verify', 'mfa-enroll', 'mfa-enroll-verify', 'mfa-disable'].includes(action) && !sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  if (action === 'login') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const body = await readBody(req); const email = String(body.email || '').trim(); const password = String(body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 1 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe seu e-mail e sua senha.' });
    const { response, payload } = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
    if (!response.ok) return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
    const factor = verifiedTotpFactors(payload.user)[0];
    if (factor) {
      const challenge = await upstream(`/auth/v1/factors/${factor.id}/challenge`, { method: 'POST', headers: { authorization: `Bearer ${payload.access_token}` }, body: {} });
      if (!challenge.response.ok || !challenge.payload?.id) return json(res, 503, { ok: false, error: friendlyAuthError(challenge.payload, 'Não foi possível iniciar a verificação em duas etapas.') });
      res.setHeader('Set-Cookie', temporaryMfaCookies(req, payload.access_token, payload.refresh_token));
      return json(res, 200, { ok: true, mfaRequired: true, factorId: factor.id, challengeId: challenge.payload.id });
    }
    res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
    return json(res, 200, { ok: true, passkeySession: { accessToken: payload.access_token, refreshToken: payload.refresh_token } });
  }
  if (action === 'mfa-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const body = await readBody(req); const jar = cookies(req); const accessToken = String(jar.paxinbot_mfa_access || ''); const code = String(body.code || '').replace(/\s/g, '');
    if (!accessToken || !/^[0-9]{6}$/.test(code) || !/^[0-9a-f-]{36}$/i.test(String(body.factorId || '')) || !/^[0-9a-f-]{36}$/i.test(String(body.challengeId || ''))) return json(res, 400, { ok: false, error: 'Informe o código de seis dígitos.' });
    const verified = await upstream(`/auth/v1/factors/${body.factorId}/verify`, { method: 'POST', headers: { authorization: `Bearer ${accessToken}` }, body: { challenge_id: body.challengeId, code } });
    if (!verified.response.ok || !verified.payload?.access_token) return json(res, 401, { ok: false, error: friendlyAuthError(verified.payload, 'Não foi possível confirmar o código.') });
    res.setHeader('Set-Cookie', [...sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token), ...clearTemporaryMfa(req)]);
    return json(res, 200, { ok: true, passkeySession: { accessToken: verified.payload.access_token, refreshToken: verified.payload.refresh_token } });
  }
  if (action === 'logout') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
    res.setHeader('Set-Cookie', [...clearSession(req), ...clearTemporaryMfa(req)]); return json(res, 200, { ok: true });
  }
  if (action === 'me') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
    const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_get_my_access', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    const providers = [...new Set((session.user.identities || []).map(identity => identity.provider).filter(Boolean))];
    return json(res, response.ok ? 200 : 503, { ok: response.ok, user: { id: session.user.id, email: session.user.email, providers }, entitlement: response.ok ? payload : { active: false } });
  }
  if (action === 'recover') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const { email } = await readBody(req); await upstream('/auth/v1/recover', { method: 'POST', body: { email: String(email || '').trim(), redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=recovery` } });
    return json(res, 200, { ok: true, message: 'Se existir uma conta para este e-mail, enviaremos as instruções.' });
  }
  if (action === 'signup') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const body = await readBody(req); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) return json(res, 400, { ok: false, error: 'Informe um e-mail válido e uma senha com pelo menos 10 caracteres.' });
    const { response, payload } = await upstream('/auth/v1/signup', { method: 'POST', body: { email, password, data: {}, email_redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=signup` } });
    if (!response.ok) return json(res, 400, { ok: false, error: payload?.msg || payload?.message || 'Não foi possível criar a conta.' });
    return json(res, 200, { ok: true, message: 'Confira seu e-mail para confirmar a conta antes de entrar.' });
  }
  if (action === 'session') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const body = await readBody(req); const accessToken = String(body.accessToken || ''); const receivedRefreshToken = String(body.refreshToken || '');
    if (accessToken.length < 80) return json(res, 400, { ok: false, error: 'Sessão de autenticação inválida.' });
    const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${accessToken}` } });
    if (!response.ok || !payload?.id) return json(res, 401, { ok: false, error: 'Não foi possível validar a sessão.' });
    const claims = jwtClaims(accessToken); const methods = Array.isArray(claims.amr) ? claims.amr.map(item => item?.method) : [];
    if (verifiedTotpFactors(payload).length && methods.includes('password') && claims.aal !== 'aal2') return json(res, 403, { ok: false, error: 'Conclua a verificação em duas etapas antes de continuar.' });
    // Alguns provedores OAuth podem não devolver refresh token no callback
    // implícito. A sessão por access token continua válida; ela apenas pedirá
    // novo login ao expirar, em vez de bloquear a primeira entrada.
    const refreshToken = receivedRefreshToken.length >= 20 ? receivedRefreshToken : '';
    res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken, refreshToken ? 60 * 60 * 24 * 30 : 60 * 60));
    return json(res, 200, { ok: true, renewable: Boolean(refreshToken) });
  }
  if (action === 'mfa') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre novamente para consultar a segurança da conta.' });
    const factor = verifiedTotpFactors(session.user)[0] || null;
    return json(res, 200, { ok: true, enabled: Boolean(factor), factor: factor ? { id: factor.id, friendlyName: factor.friendly_name || 'Aplicativo autenticador', createdAt: factor.created_at } : null });
  }
  if (action === 'mfa-enroll') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre novamente para configurar a verificação.' });
    if (verifiedTotpFactors(session.user).length) return json(res, 409, { ok: false, error: 'A verificação em duas etapas já está ativa.' });
    for (const factor of (session.user.factors || []).filter(item => item.factor_type === 'totp' && item.status !== 'verified')) {
      await upstream(`/auth/v1/factors/${factor.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${session.access}` } });
    }
    const enrolled = await upstream('/auth/v1/factors', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: { factor_type: 'totp', friendly_name: 'Paxinbot Authenticator', issuer: 'Paxinbot' } });
    if (!enrolled.response.ok || !enrolled.payload?.id || !enrolled.payload?.totp) return json(res, 400, { ok: false, error: friendlyAuthError(enrolled.payload, 'Não foi possível preparar a verificação em duas etapas.') });
    return json(res, 200, { ok: true, factorId: enrolled.payload.id, qrCode: enrolled.payload.totp.qr_code, secret: enrolled.payload.totp.secret, uri: enrolled.payload.totp.uri });
  }
  if (action === 'mfa-enroll-verify') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Sua sessão expirou. Entre novamente.' });
    const body = await readBody(req); const factorId = String(body.factorId || ''); const code = String(body.code || '').replace(/\s/g, '');
    if (!/^[0-9a-f-]{36}$/i.test(factorId) || !/^[0-9]{6}$/.test(code) || !(session.user.factors || []).some(factor => factor.id === factorId && factor.factor_type === 'totp')) return json(res, 400, { ok: false, error: 'Configuração ou código inválido.' });
    const challenge = await upstream(`/auth/v1/factors/${factorId}/challenge`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    if (!challenge.response.ok || !challenge.payload?.id) return json(res, 400, { ok: false, error: friendlyAuthError(challenge.payload, 'Não foi possível iniciar a confirmação.') });
    const verified = await upstream(`/auth/v1/factors/${factorId}/verify`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: { challenge_id: challenge.payload.id, code } });
    if (!verified.response.ok || !verified.payload?.access_token) return json(res, 401, { ok: false, error: friendlyAuthError(verified.payload, 'O código não pôde ser confirmado.') });
    res.setHeader('Set-Cookie', sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token));
    return json(res, 200, { ok: true });
  }
  if (action === 'mfa-disable') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Sua sessão expirou. Entre novamente.' });
    const body = await readBody(req); const factorId = String(body.factorId || ''); const code = String(body.code || '').replace(/\s/g, '');
    if (!/^[0-9a-f-]{36}$/i.test(factorId) || !/^[0-9]{6}$/.test(code) || !verifiedTotpFactors(session.user).some(factor => factor.id === factorId)) return json(res, 400, { ok: false, error: 'Informe o código atual do aplicativo autenticador.' });
    const challenge = await upstream(`/auth/v1/factors/${factorId}/challenge`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
    if (!challenge.response.ok || !challenge.payload?.id) return json(res, 400, { ok: false, error: friendlyAuthError(challenge.payload, 'Não foi possível iniciar a confirmação.') });
    const verified = await upstream(`/auth/v1/factors/${factorId}/verify`, { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: { challenge_id: challenge.payload.id, code } });
    if (!verified.response.ok || !verified.payload?.access_token) return json(res, 401, { ok: false, error: friendlyAuthError(verified.payload, 'O código não pôde ser confirmado.') });
    const removed = await upstream(`/auth/v1/factors/${factorId}`, { method: 'DELETE', headers: { authorization: `Bearer ${verified.payload.access_token}` } });
    if (!removed.response.ok) return json(res, 400, { ok: false, error: 'Não foi possível desativar a verificação em duas etapas.' });
    res.setHeader('Set-Cookie', sessionCookies(req, verified.payload.access_token, verified.payload.refresh_token));
    return json(res, 200, { ok: true });
  }
  if (action === 'password') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Sua sessão expirou. Entre novamente para alterar a senha.' });
    const { password } = await readBody(req); const value = String(password || '');
    if (value.length < 10 || value.length > 128) return json(res, 400, { ok: false, error: 'Use uma senha entre 10 e 128 caracteres.' });
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
    const { url } = config(); const target = new URL(`${url}/auth/v1/authorize`); const intent = String(req.query?.intent || '') === 'passkey' ? 'passkey' : 'google';
    target.searchParams.set('provider', 'google'); target.searchParams.set('redirect_to', `${publicOrigin(req)}/auth-callback.html?flow=${intent}`);
    res.writeHead(302, { Location: target.toString(), 'cache-control': 'no-store' }); res.end(); return;
  }
  return json(res, 404, { ok: false, error: 'Rota não encontrada.' });
};
