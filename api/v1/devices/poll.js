'use strict';
const { json, readBody, serviceUpstream, serviceRateLimit, clientAddress, isUuid, sha256, safeDeviceAuthError } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req);
  if (!isUuid(body.requestId) || !/^[A-Za-z0-9_-]{43}$/.test(String(body.secret || ''))) return json(res, 400, { ok: false, error: 'Solicitação inválida.' });
  if (!await serviceRateLimit('device_poll_ip', clientAddress(req), 180, 600)) return json(res, 429, { ok: false, error: 'Muitas tentativas. Aguarde antes de continuar.', status: 'slow_down', intervalMs: 10000 }, { 'retry-after': '10' });
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_device_poll_v3', { method: 'POST', body: { p_request_id: body.requestId, p_secret_hash: sha256(body.secret) } });
  if (!response.ok) return json(res, 400, { ok: false, ...safeDeviceAuthError(payload, 'Não foi possível validar esta solicitação.') });
  return json(res, 200, { ok: true, ...payload, minAppVersion: '1.0.0' });
};
