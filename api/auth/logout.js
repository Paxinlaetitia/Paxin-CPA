'use strict';
const { json, cookies, clearSession, upstream } = require('../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const access = cookies(req).paxinbot_access; if (access) await upstream('/auth/v1/logout', { method: 'POST', headers: { authorization: `Bearer ${access}` } });
  res.setHeader('Set-Cookie', clearSession(req)); return json(res, 200, { ok: true });
};
