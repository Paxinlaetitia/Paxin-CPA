'use strict';
const { json, readBody, upstream, sha256 } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req); const { response, payload } = await upstream('/rest/v1/rpc/paxinbot_device_poll', { method: 'POST', body: { p_request_id: body.requestId, p_secret_hash: sha256(body.secret || '') } });
  if (!response.ok) return json(res, 400, { ok: false, error: 'Solicitação inválida, expirada ou sem acesso ativo.' });
  return json(res, 200, { ok: true, ...payload, appVersion: '2.6.0' });
};
