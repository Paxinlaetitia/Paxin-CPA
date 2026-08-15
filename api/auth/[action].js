'use strict';

const { config, json, cookies, sessionCookies, clearSession, upstream, readBody, browserSession, publicOrigin, sameOriginRequest } = require('../_paxinbot');

function actionOf(req) {
  if (req.query?.action) return String(req.query.action);
  return new URL(req.url || '/', 'http://localhost').pathname.split('/').filter(Boolean).pop() || '';
}

module.exports = async (req, res) => {
  const action = actionOf(req);
  if (req.method === 'POST' && ['login', 'logout', 'recover', 'signup', 'session', 'password'].includes(action) && !sameOriginRequest(req)) return json(res, 403, { ok: false, error: 'Origem da solicitação não autorizada.' });
  if (action === 'login') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const body = await readBody(req); const email = String(body.email || '').trim(); const password = String(body.password || '');
    const { response, payload } = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
    if (!response.ok) return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
    res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
    return json(res, 200, { ok: true, passkeySession: { accessToken: payload.access_token, refreshToken: payload.refresh_token } });
  }
  if (action === 'logout') {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
    const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
    res.setHeader('Set-Cookie', clearSession(req)); return json(res, 200, { ok: true });
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
    // Alguns provedores OAuth podem não devolver refresh token no callback
    // implícito. A sessão por access token continua válida; ela apenas pedirá
    // novo login ao expirar, em vez de bloquear a primeira entrada.
    const refreshToken = receivedRefreshToken.length >= 20 ? receivedRefreshToken : '';
    res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken, refreshToken ? 60 * 60 * 24 * 30 : 60 * 60));
    return json(res, 200, { ok: true, renewable: Boolean(refreshToken) });
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
