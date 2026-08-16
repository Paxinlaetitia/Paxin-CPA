'use strict';
const crypto = require('node:crypto');
const { json, readBodyResult, serviceUpstream, serviceRateLimit, clientAddress, sha256, cleanDeviceName, publicOrigin, verifyDeviceIdentityProof, safeDeviceAuthError } = require('../../_paxinbot');
async function recordServerSignal(identity,type,appVersion) {
  if (!identity || !['device_identity_mismatch','device_proof_replayed','auth_rate_limited'].includes(type)) return;
  await serviceUpstream('/rest/v1/rpc/paxinbot_record_device_security_event',{ method:'POST',body:{
    p_device_key_hash:identity.deviceKeyHash,p_fingerprint_hash:identity.fingerprintHash,
    p_event_id:crypto.randomUUID(),p_event_type:type,p_app_version:appVersion
  } }).catch(()=>null);
}
module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'Método não permitido.' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return; const body = parsed.body;
  const appVersion = String(body.appVersion || '').trim();
  if (!/^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[0-9A-Za-z.-]{1,24})?$/.test(appVersion)) return json(res, 400, { ok: false, error: 'Versão do aplicativo inválida.' });
  let identity;
  try { identity = verifyDeviceIdentityProof(body); }
  catch (error) { return json(res, 400, { ok: false, ...safeDeviceAuthError({ message:error?.message }, 'A identificação segura deste computador é inválida.') }); }
  if (!await serviceRateLimit('device_start_ip', clientAddress(req), 10, 600)) { await recordServerSignal(identity,'auth_rate_limited',appVersion); return json(res, 429, { ok: false, error: 'Muitas solicitações. Aguarde alguns minutos.', retryAfter: 60 }, { 'retry-after': '60' }); }
  if (!await serviceRateLimit('device_start_key', identity.deviceKeyHash, 20, 600)) { await recordServerSignal(identity,'auth_rate_limited',appVersion); return json(res, 429, { ok: false, error: 'Muitas solicitações deste computador. Aguarde alguns minutos.', retryAfter: 60 }, { 'retry-after': '60' }); }
  const requestId = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString('base64url');
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const rawCode = Array.from(crypto.randomBytes(12), byte => alphabet[byte % alphabet.length]).join('');
  const userCode = rawCode.match(/.{4}/g).join('-');
  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_device_start_v3', { method: 'POST', body: {
    p_request_id: requestId, p_secret_hash: sha256(secret), p_user_code: userCode,
    p_device_name: cleanDeviceName(body.deviceName), p_app_version: appVersion,
    p_install_id_hash: identity.installIdHash, p_device_key_hash: identity.deviceKeyHash,
    p_fingerprint_hash: identity.fingerprintHash, p_public_key: identity.publicKey,
    p_fingerprint_strength: identity.fingerprintStrength, p_proof_nonce_hash: identity.proofNonceHash
  } });
  if (!response.ok) {
    const safe=safeDeviceAuthError(payload,'Não foi possível iniciar a autorização.');
    const raw=String(payload?.message || payload?.error || '');
    if (/device_proof_replayed/i.test(raw)) await recordServerSignal(identity,'device_proof_replayed',appVersion);
    else if (safe.code==='device_identity_mismatch') await recordServerSignal(identity,'device_identity_mismatch',appVersion);
    return json(res,403,{ ok:false,...safe });
  }
  return json(res, 201, { ok: true, requestId, secret, userCode, expiresAt: payload?.expiresAt || new Date(Date.now() + 600000).toISOString(), intervalMs: 5000, verificationUrl: `${publicOrigin(req)}/activate?request=${encodeURIComponent(requestId)}&code=${encodeURIComponent(userCode)}` });
};
