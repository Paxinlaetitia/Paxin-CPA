'use strict';

const { json, requireTrustedHost, readBodyResult, serviceUpstream, serviceRateLimit, sha256 } = require('../../_paxinbot');
const {
  parseReleaseRequest, readReleaseEnvironment, assertOfficialRelease, createAuthorization,
  safeDenialReason
} = require('../../../server/protected-release-crypto');
const { securityDiagnostic } = require('../../../server/security-log');

module.exports = async (req, res) => {
  if (!requireTrustedHost(req, res)) return;
  if (req.method !== 'POST') return json(res, 405, { ok:false, error:'Método não permitido.' }, { allow:'POST' });
  const tokenMatch = String(req.headers.authorization || '').match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!tokenMatch) return json(res, 401, { ok:false, error:'Sessão do aplicativo ausente.' });

  let request; let release;
  try {
    const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
    request = parseReleaseRequest(parsed.body);
    release = readReleaseEnvironment();
    assertOfficialRelease(request, release);
  } catch (error) {
    const unavailable = String(error?.message || '') === 'protected_release_environment_invalid';
    return json(res, unavailable ? 503 : 400, { ok:false, error:unavailable ? 'A versão protegida ainda não está disponível.' : 'Esta versão do aplicativo não está autorizada.' });
  }

  if (!await serviceRateLimit('protected_release', tokenMatch[1], 30, 3600)) {
    return json(res, 429, { ok:false, error:'Muitas solicitações de autorização. Entre novamente.' }, { 'retry-after':'60' });
  }

  const { response, payload } = await serviceUpstream('/rest/v1/rpc/paxinbot_authorize_protected_release', {
    method:'POST',
    body:{
      p_token_hash:sha256(tokenMatch[1]), p_version:request.version,
      p_sequence:request.sequence, p_integrity_digest:request.integrityDigest,
      p_index_digest:request.moduleIndexDigest, p_request_nonce_hash:sha256(request.requestNonce)
    }
  });
  if (!response.ok || payload?.allowed !== true) {
    securityDiagnostic('protected_release.denied', {
      reason:safeDenialReason(payload), upstreamStatus:Number(response.status) || 0
    });
    return json(res, 401, { ok:false, error:'A sessão, o dispositivo ou o acesso não autoriza esta versão.' });
  }

  try {
    const authorization = createAuthorization({ request, release, identity:payload });
    return json(res, 200, { ok:true, authorization });
  } catch {
    return json(res, 503, { ok:false, error:'Não foi possível preparar a autorização protegida.' });
  } finally {
    release.contentKey.fill(0);
  }
};
