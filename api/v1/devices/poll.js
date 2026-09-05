'use strict';
const { json, requireTrustedHost, readBodyResult, serviceUpstream, serviceRateLimit, clientAddress, isUuid, sha256, safeDeviceAuthError } = require('../../_paxinbot');
async function handlePoll(req, res) {
  if (!requireTrustedHost(req, res)) return;
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body;
  if (!isUuid(body.requestId) || !/^[A-Za-z0-9_-]{43}$/.test(String(body.secret || ''))) return json(res, 400, { ok: false, error: 'Solicitação inválida.' });
  if (!await serviceRateLimit('device_poll_ip', clientAddress(req), 180, 600)) return json(res, 429, { ok: false, error: 'Muitas tentativas. Aguarde antes de continuar.', status: 'slow_down', intervalMs: 10000 }, { 'retry-after': '10' });
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_device_poll_v4', { method: 'POST', body: { p_request_id: body.requestId, p_secret_hash: sha256(body.secret) }, signal: AbortSignal.timeout(10000) });
  if (!response.ok && (response.status >= 500 || response.status === 401 || response.status === 403 || response.status === 404)) return json(res, 503, { ok: false, error: 'A autorização está temporariamente indisponível.' });
  if (!response.ok) return json(res, 400, { ok: false, ...safeDeviceAuthError(payload, 'Não foi possível validar esta solicitação.') });
  if (!payload || !['pending', 'approved', 'denied'].includes(payload.status)) return json(res, 503, { ok: false, error: 'A autorização está temporariamente indisponível.' });
  if (payload.status === 'approved' && (typeof payload.profile?.nickname !== 'string' || !(payload.profile.avatarUrl === null || typeof payload.profile.avatarUrl === 'string'))) return json(res, 503, { ok: false, error: 'O perfil da autorização está temporariamente indisponível.' });
  return json(res, 200, { ok: true, ...payload, minAppVersion: '1.0.0' });
}

module.exports = async (req, res) => {
  try { return await handlePoll(req, res); }
  catch { return json(res, 503, { ok: false, error: 'A autorização está temporariamente indisponível.' }); }
};
