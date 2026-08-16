'use strict';
const { json, readBodyResult, serviceUpstream, serviceRateLimit, sha256, isUuid } = require('../../_paxinbot');

const SECURITY_EVENT_TYPES = new Set([
  'integrity_failure','release_rollback_blocked','debug_flag_detected',
  'device_identity_mismatch','device_proof_replayed','auth_rate_limited',
  'session_rejected','update_signature_failure','runtime_contract_failure'
]);
const SECURITY_DETAIL_KEYS = new Set(['reasonCode','component','operation','outcome']);

function validSecurityEvent(body) {
  if (!isUuid(body?.eventId) || !SECURITY_EVENT_TYPES.has(String(body?.type || ''))) return false;
  if (!/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[0-9A-Za-z.-]{1,24})?$/.test(String(body?.appVersion || ''))) return false;
  if (!Number.isInteger(body?.releaseSequence) || body.releaseSequence < 1 || body.releaseSequence > 2147483647) return false;
  const occurredAt = Date.parse(String(body?.occurredAt || ''));
  if (!Number.isFinite(occurredAt) || occurredAt < Date.now() - 7 * 86400000 || occurredAt > Date.now() + 600000) return false;
  const details = body?.details === undefined ? {} : body.details;
  if (!details || Array.isArray(details) || typeof details !== 'object') return false;
  const entries = Object.entries(details);
  return entries.length <= 4 && entries.every(([key, value]) => SECURITY_DETAIL_KEYS.has(key) && typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(value));
}

module.exports = async (req, res) => {
  if (!['GET', 'POST'].includes(req.method)) return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const match = String(req.headers.authorization || '').match(/^Bearer\s+([a-f0-9]{64})$/i); if (!match) return json(res, 401, { ok: false, error: 'Sessão do aplicativo ausente.' });
  if (req.method === 'POST' && String(req.query?.action || '') === 'security-event') {
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body;
    if (!validSecurityEvent(body)) return json(res, 400, { ok:false, error:'Evento de segurança inválido.' });
    if (!await serviceRateLimit('security_event_token', match[1], 60, 3600)) return json(res, 429, { ok:false, error:'Limite de eventos de segurança atingido.' }, { 'retry-after':'60' });
    const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_record_security_event', { method:'POST', body:{
      p_token_hash:sha256(match[1]), p_event_id:body.eventId, p_event_type:body.type,
      p_occurred_at:body.occurredAt, p_app_version:body.appVersion,
      p_release_sequence:body.releaseSequence, p_details:body.details || {}
    } });
    if (!response.ok) return json(res, 503, { ok:false, error:'O registro seguro ainda não está disponível.' });
    return json(res, 202, { ok:true, action:payload?.action === 'reauthenticate' ? 'reauthenticate' : 'allow' });
  }
  const pause = req.method === 'POST';
  if (!await serviceRateLimit(pause ? 'desktop_usage_pause' : 'desktop_session', match[1], pause ? 120 : 600, 3600)) return json(res, 429, { ok: false, error: 'Muitas validações de sessão. Aguarde e tente novamente.' }, { 'retry-after': '30' });
  const rpc = pause ? 'paxinbot_pause_desktop_usage_v3' : 'paxinbot_desktop_session_v3';
  const { response, payload } = await serviceUpstream(`/rest/v1/rpc/${rpc}`, { method: 'POST', body: { p_token_hash: sha256(match[1]) } });
  if (!response.ok || payload?.active === false) return json(res, 401, { ok: false, error: payload?.reason === 'usage_exhausted' ? 'Seu saldo de uso terminou.' : payload?.reason === 'risk_reauthentication_required' ? 'Uma verificação de segurança exige nova autorização deste computador.' : 'Sessão do aplicativo inválida, expirada ou sem acesso ativo.', reason: payload?.reason || 'session_invalid' });
  return json(res, 200, { ok: true, ...payload, ...(pause ? {} : { minAppVersion: '1.0.0' }) });
};
