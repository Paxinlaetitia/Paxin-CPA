'use strict';
const { json, browserSession, upstream } = require('../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_get_my_access', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: {} });
  return json(res, response.ok ? 200 : 503, { ok: response.ok, user: { id: session.user.id, email: session.user.email }, entitlement: response.ok ? payload : { active: false } });
};
