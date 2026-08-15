'use strict';
const crypto = require('node:crypto'); const { json, readBody, upstream, sha256, publicOrigin } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req); const requestId = crypto.randomUUID(); const secret = crypto.randomBytes(32).toString('base64url'); const userCode = crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
  const { response } = await upstream('/rest/v1/rpc/paxinbot_device_start', { method: 'POST', body: { p_request_id: requestId, p_secret_hash: sha256(secret), p_user_code: userCode, p_device_name: String(body.deviceName || 'Computador Paxinbot'), p_app_version: String(body.appVersion || '1.0.0') } });
  if (!response.ok) return json(res, 503, { ok: false, error: 'Não foi possível iniciar a autorização.' });
  return json(res, 201, { ok: true, requestId, secret, userCode, expiresAt: new Date(Date.now() + 600000).toISOString(), intervalMs: 1800, verificationUrl: `${publicOrigin(req)}/activate.html?request=${encodeURIComponent(requestId)}&code=${encodeURIComponent(userCode)}` });
};
