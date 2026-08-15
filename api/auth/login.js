'use strict';
const { json, readBody, sessionCookies, upstream } = require('../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req); const email = String(body.email || '').trim(); const password = String(body.password || '');
  const { response, payload } = await upstream('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  if (!response.ok) return json(res, 401, { ok: false, error: 'E-mail ou senha incorretos.' });
  res.setHeader('Set-Cookie', sessionCookies(req, payload.access_token, payload.refresh_token));
  return json(res, 200, { ok: true });
};
