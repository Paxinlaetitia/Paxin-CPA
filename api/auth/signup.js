'use strict';
const { json, readBody, upstream, publicOrigin } = require('../_paxinbot');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) {
    return json(res, 400, { ok: false, error: 'Informe um e-mail válido e uma senha com pelo menos 10 caracteres.' });
  }
  const { response, payload } = await upstream('/auth/v1/signup', {
    method: 'POST',
    body: { email, password, data: {}, gotrue_meta_security: {}, email_redirect_to: `${publicOrigin(req)}/auth-callback.html?flow=signup` }
  });
  if (!response.ok) return json(res, 400, { ok: false, error: payload?.msg || payload?.message || 'Não foi possível criar a conta.' });
  return json(res, 200, { ok: true, message: 'Confira seu e-mail para confirmar a conta antes de entrar.' });
};
