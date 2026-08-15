'use strict';
const { json, readBody, browserSession, upstream } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  const body = await readBody(req); const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_device_approve', { method: 'POST', headers: { authorization: `Bearer ${session.access}` }, body: { p_request_id: body.requestId, p_user_code: body.userCode } });
  if (!response.ok) return json(res, 403, { ok: false, error: 'Esta solicitação não pode ser autorizada com a conta atual.' });
  return json(res, 200, { ok: true, deviceName: payload.deviceName });
};
