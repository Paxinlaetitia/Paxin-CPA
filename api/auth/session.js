'use strict';
const { json, readBody, sessionCookies, upstream } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req);
  const accessToken = String(body.accessToken || '');
  const refreshToken = String(body.refreshToken || '');
  if (accessToken.length < 80 || refreshToken.length < 20) return json(res, 400, { ok: false, error: 'Sessão de autenticação inválida.' });
  const { response, payload } = await upstream('/auth/v1/user', { headers: { authorization: `Bearer ${accessToken}` } });
  if (!response.ok || !payload?.id) return json(res, 401, { ok: false, error: 'Não foi possível validar a sessão.' });
  res.setHeader('Set-Cookie', sessionCookies(req, accessToken, refreshToken));
  return json(res, 200, { ok: true });
};
