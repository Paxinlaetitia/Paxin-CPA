'use strict';
const { json, readBody, browserSession, upstream } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const session = await browserSession(req, res);
  if (!session) return json(res, 401, { ok: false, error: 'A sessão de recuperação expirou. Solicite um novo link.' });
  const { password } = await readBody(req); const value = String(password || '');
  if (value.length < 10 || value.length > 128) return json(res, 400, { ok: false, error: 'Use uma senha entre 10 e 128 caracteres.' });
  const { response, payload } = await upstream('/auth/v1/user', { method: 'PUT', headers: { authorization: `Bearer ${session.access}` }, body: { password: value } });
  if (!response.ok) return json(res, 400, { ok: false, error: payload?.msg || 'Não foi possível atualizar a senha.' });
  return json(res, 200, { ok: true });
};
