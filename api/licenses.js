'use strict';

const crypto = require('node:crypto');
const {
  json, requireTrustedHost, readBodyResult, serviceUpstream,
  serviceRateLimit, clientAddress, sha256, isUuid
} = require('./_paxinbot');
const {
  ACTIONS, LicenseProtocolError, licenseCandidates, releaseKeys, verifyProof,
  signResponse, responsePayload, databaseError
} = require('../server/cpa-licensing');
const adminHandler = require('../server/cpa-licensing-admin');

function failure(res, error) {
  const known = error instanceof LicenseProtocolError ? error : new LicenseProtocolError('server_unavailable', 503);
  return json(res, known.status, { ok: false, code: known.code });
}

async function rpc(name, body, timeout = 10000) {
  const result = await serviceUpstream(`/rest/v1/rpc/${name}`, {
    method: 'POST', body, signal: AbortSignal.timeout(timeout)
  });
  if (!result.response.ok) throw databaseError(result.payload, result.response.status);
  return result.payload;
}

async function recordDenial(category, request) {
  if (!/^license\.denied_(?:invalid_proof|invalid_key|expired|suspended|revoked|banned|hwid_mismatch|device_banned|session_expired|release_unknown)$/.test(category)) return;
  await serviceUpstream('/rest/v1/rpc/cpa_license_record_denial', { method:'POST', body:{
    p_category:category,
    p_hwid:request?.hwid || null,
    p_session_token_hash:request?.sessionToken ? sha256(request.sessionToken) : null
  } }).catch(() => null);
}

async function challenge(req, res, body) {
  const requestedAction = String(body.action || '');
  const payloadHash = String(body.payloadHash || '').toLowerCase();
  if (!ACTIONS.has(requestedAction) || !/^[a-f0-9]{64}$/.test(payloadHash)) throw new LicenseProtocolError('invalid_request');
  if (!await serviceRateLimit('cpa_license_challenge', clientAddress(req), 600, 60)) return json(res, 429, { ok:false, code:'rate_limited' }, { 'retry-after':'5' });
  const challengeId = crypto.randomUUID();
  const nonce = crypto.randomBytes(32).toString('base64url');
  await rpc('cpa_license_create_challenge', {
    p_challenge_id: challengeId,
    p_action: requestedAction,
    p_payload_hash: payloadHash,
    p_nonce: nonce
  });
  return json(res, 201, { ok: true, challengeId, nonce, expiresIn: 60 });
}

async function perform(req, res, action, body) {
  if (!isUuid(body.challengeId) || typeof body.payload !== 'string' || typeof body.signature !== 'string') {
    throw new LicenseProtocolError('invalid_request');
  }
  if (!await serviceRateLimit(`cpa_license_${action}`, clientAddress(req), 1200, 60)) return json(res, 429, { ok:false, code:'rate_limited' }, { 'retry-after':'5' });

  // This is intentionally the first database operation. It makes every
  // syntactically addressable challenge single-use even when proof validation fails.
  const challengeState = await rpc('cpa_license_consume_challenge', { p_challenge_id: body.challengeId });
  if (!challengeState || challengeState.status === 'expired') throw new LicenseProtocolError('expired', 401);
  if (challengeState.status === 'replay') throw new LicenseProtocolError('replay', 409);
  if (challengeState.action !== action) throw new LicenseProtocolError('invalid_proof', 401);

  let request;
  try {
    request = verifyProof({
      challengeId: body.challengeId,
      nonce: challengeState.nonce,
      action,
      payloadEncoded: body.payload,
      signature: body.signature,
      expectedPayloadHash: challengeState.payloadHash
    });
  } catch (error) {
    await recordDenial('license.denied_invalid_proof');
    throw error;
  }
  const hwidLimit = action === 'activate' ? 30 : 600;
  if (!await serviceRateLimit(`cpa_license_hwid_${action === 'activate' ? 'activation' : 'session'}`, request.hwid, hwidLimit, 60)) throw new LicenseProtocolError('rate_limited', 429);
  const releases = releaseKeys();
  if (!Object.hasOwn(releases, request.releaseId)) throw new LicenseProtocolError('release_unknown', 400);
  await rpc('cpa_license_register_proof', {
    p_challenge_id: body.challengeId,
    p_request_nonce_hash: sha256(request.requestNonce)
  });

  let result;
  let sessionToken = request.sessionToken;
  try {
    if (action === 'activate') {
      const candidates = licenseCandidates(request.licenseKey);
      if (!await serviceRateLimit('cpa_license_key', candidates[0].hash, 20, 60)) throw new LicenseProtocolError('rate_limited', 429);
      sessionToken = crypto.randomBytes(32).toString('base64url');
      result = await rpc('cpa_license_activate', {
        p_candidates: candidates,
        p_hwid: request.hwid,
        p_public_key: request.publicKey,
        p_public_key_hash: request.publicKeyHash,
        p_release_id: request.releaseId,
        p_session_token_hash: sha256(sessionToken)
      });
    } else if (action === 'refresh') {
      sessionToken = crypto.randomBytes(32).toString('base64url');
      result = await rpc('cpa_license_refresh', {
        p_session_token_hash: sha256(request.sessionToken),
        p_new_session_token_hash: sha256(sessionToken),
        p_hwid: request.hwid,
        p_public_key_hash: request.publicKeyHash,
        p_release_id: request.releaseId
      });
    } else if (action === 'authorize') {
      result = await rpc('cpa_license_authorize', {
        p_session_token_hash: sha256(request.sessionToken),
        p_hwid: request.hwid,
        p_public_key_hash: request.publicKeyHash,
        p_release_id: request.releaseId,
        p_scope: request.scope
      });
    } else {
      result = await rpc('cpa_license_logout', {
        p_session_token_hash: sha256(request.sessionToken),
        p_hwid: request.hwid,
        p_public_key_hash: request.publicKeyHash
      });
      sessionToken = '';
    }
  } catch (error) {
    if (error instanceof LicenseProtocolError && error.code !== 'rate_limited' && error.code !== 'server_unavailable') await recordDenial(`license.denied_${error.code}`, request);
    throw error;
  }
  if (!result || !isUuid(result.licenseId)) throw new LicenseProtocolError('server_unavailable', 503);
  const signed = responsePayload(action, request, result, sessionToken, action === 'authorize' ? releases[request.releaseId] : '');
  return json(res, 200, signResponse(signed));
}

async function handle(req, res) {
  if (!requireTrustedHost(req, res)) return;
  if (String(req.query?.channel || '') === 'admin') return adminHandler(req, res);
  if (req.method !== 'POST') return json(res, 405, { ok:false, code:'invalid_request' });
  const parsed = await readBodyResult(req, res); if (!parsed.ok) return;
  const action = String(req.query?.action || '');
  if (action === 'challenge') return challenge(req, res, parsed.body);
  if (!ACTIONS.has(action)) throw new LicenseProtocolError('invalid_request');
  return perform(req, res, action, parsed.body);
}

module.exports = async (req, res) => {
  try { return await handle(req, res); }
  catch (error) { return failure(res, error); }
};
