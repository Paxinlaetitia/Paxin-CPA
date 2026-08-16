'use strict';
const { json, readBody, browserSession, serviceUpstream, serviceRateLimit, isUuid, safeDeviceAuthError } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const session = await browserSession(req, res); if (!session) return json(res, 401, { ok: false, error: 'Entre na sua conta para continuar.' });
  const body = await readBody(req);
  const userCode = String(body.userCode || '').toUpperCase().trim();
  if (!isUuid(body.requestId) || !/^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){2}$/.test(userCode)) return json(res, 400, { ok: false, error: 'Código de autorização inválido.' });
  if (!await serviceRateLimit('device_approve_user', session.user.id, 20, 600)) return json(res, 429, { ok: false, error: 'Muitas tentativas. Aguarde alguns minutos.' }, { 'retry-after': '60' });
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_device_approve_v3', { method: 'POST', body: { p_request_id: body.requestId, p_user_code: userCode, p_user_id: session.user.id } });
  if (!response.ok) return json(res, 403, { ok: false, ...safeDeviceAuthError(payload, 'Esta solicitação não pode ser autorizada com a conta atual.') });
  return json(res, 200, { ok: true, deviceName: payload.deviceName });
};
