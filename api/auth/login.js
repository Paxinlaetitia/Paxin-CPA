'use strict';
const { json, readBody, sessionCookies, upstream } = require('../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req); const email = String(body.email || '').trim(); const password = String(body.password || '');
  const { response, payload } = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  if (!response.ok) return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
  res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
  // Não persista estes valores no navegador. Eles existem somente em memória
  // durante esta página para que o cliente possa cadastrar uma passkey logo
  // após autenticar com senha.
  return json(res, 200, { ok: true, passkeySession: { accessToken: payload.access_token, refreshToken: payload.refresh_token } });
};
