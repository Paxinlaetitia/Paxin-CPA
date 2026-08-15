'use strict';
const crypto = require('node:crypto');
const { json, readBody, serviceUpstream, serviceRateLimit, clientAddress, sha256, cleanDeviceName, publicOrigin } = require('../../_paxinbot');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const body = await readBody(req);
  const appVersion = String(body.appVersion || '').trim();
  if (!/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[0-9A-Za-z.-]{1,24})?$/.test(appVersion)) return json(res, 400, { ok: false, error: 'Versão do aplicativo inválida.' });
  if (!await serviceRateLimit('device_start_ip', clientAddress(req), 10, 600)) return json(res, 429, { ok: false, error: 'Muitas solicitações. Aguarde alguns minutos.', retryAfter: 60 }, { 'retry-after': '60' });
  const requestId = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString('base64url');
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rawCode = Array.from(crypto.randomBytes(12), byte => alphabet[byte % alphabet.length]).join('');
  const userCode = rawCode.match(/.{4}/g).join('-');
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_device_start_v2', { method: 'POST', body: { p_request_id: requestId, p_secret_hash: sha256(secret), p_user_code: userCode, p_device_name: cleanDeviceName(body.deviceName), p_app_version: appVersion } });
  if (!response.ok) return json(res, 503, { ok: false, error: 'Não foi possível iniciar a autorização.' });
  return json(res, 201, { ok: true, requestId, secret, userCode, expiresAt: payload?.expiresAt || new Date(Date.now() + 600000).toISOString(), intervalMs: 5000, verificationUrl: `${publicOrigin(req)}/activate?request=${encodeURIComponent(requestId)}&code=${encodeURIComponent(userCode)}` });
};
