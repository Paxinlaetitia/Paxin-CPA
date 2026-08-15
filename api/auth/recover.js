'use strict';
const { json, readBody, upstream, publicOrigin } = require('../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const { email } = await readBody(req); await upstream('/auth/v1/recover', { method: 'POST', body: { email: String(email || '').trim(), redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=recovery` } });
  return json(res, 200, { ok: true, message: 'Se existir uma conta para este e-mail, enviaremos as instruções.' });
};
