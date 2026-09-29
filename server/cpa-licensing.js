'use strict';

const crypto = require('node:crypto');

const PRODUCT_CODE = 'cash-hunters';
const PROTOCOL = 'PAXINCPA/1';
const MAX_SESSION_SECONDS = 120;
const ACTIONS = new Set(['activate', 'refresh', 'authorize', 'logout']);
const SCOPES = new Set(['start', 'manager', 'operation', 'browser']);
const ERROR_CODES = new Set([
  'invalid_key', 'expired', 'suspended', 'revoked', 'banned', 'hwid_mismatch',
  'device_banned', 'session_expired', 'invalid_proof', 'replay', 'rate_limited',
  'server_unavailable', 'invalid_request', 'release_unknown'
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const B64_64 = /^[A-Za-z0-9_-]{86}$/;
const HEX_256 = /^[a-f0-9]{64}$/;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;

class LicenseProtocolError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = ERROR_CODES.has(code) ? code : 'invalid_request';
    this.status = status;
  }
}

function decodeJsonObject(encoded) {
  if (typeof encoded !== 'string' || encoded.length < 2 || encoded.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new LicenseProtocolError('invalid_request');
  }
  let value;
  try { value = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); }
  catch { throw new LicenseProtocolError('invalid_request'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new LicenseProtocolError('invalid_request');
  return value;
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function parseJsonMap(raw, name) {
  let parsed;
  try { parsed = JSON.parse(String(raw || '')); }
  catch { throw new Error(`${name} inválido.`); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object' || Object.keys(parsed).length < 1) throw new Error(`${name} inválido.`);
  return parsed;
}

function pepperConfig(env = process.env) {
  const peppers = parseJsonMap(env.CPA_LICENSE_HMAC_PEPPERS, 'CPA_LICENSE_HMAC_PEPPERS');
  const currentVersion = String(env.CPA_LICENSE_HMAC_CURRENT_VERSION || '');
  for (const [version, secret] of Object.entries(peppers)) {
    if (!/^[A-Za-z0-9._-]{1,32}$/.test(version) || Buffer.byteLength(String(secret), 'utf8') < 32) throw new Error('Configuração de pepper inválida.');
  }
  if (!Object.hasOwn(peppers, currentVersion)) throw new Error('Versão atual do pepper ausente.');
  return { peppers, currentVersion };
}

function licenseDigest(licenseKey, secret) {
  return crypto.createHmac('sha256', String(secret)).update(`${PRODUCT_CODE}\0${licenseKey}`, 'utf8').digest('hex');
}

function licenseCandidates(licenseKey, env = process.env) {
  if (!B64_32.test(String(licenseKey || ''))) throw new LicenseProtocolError('invalid_key', 401);
  const { peppers } = pepperConfig(env);
  return Object.entries(peppers).map(([version, secret]) => ({ version, hash: licenseDigest(licenseKey, secret) }));
}

function generateLicense(env = process.env) {
  const licenseKey = crypto.randomBytes(32).toString('base64url');
  const { peppers, currentVersion } = pepperConfig(env);
  return {
    licenseKey,
    keyId: crypto.randomBytes(12).toString('base64url'),
    keyPrefix: licenseKey.slice(0, 8),
    pepperVersion: currentVersion,
    keyHash: licenseDigest(licenseKey, peppers[currentVersion])
  };
}

function signingConfig(env = process.env) {
  const entries = parseJsonMap(env.CPA_LICENSE_SIGNING_KEYS, 'CPA_LICENSE_SIGNING_KEYS');
  const currentKid = String(env.CPA_LICENSE_SIGNING_CURRENT_KID || '');
  if (!Object.hasOwn(entries, currentKid) || !/^[A-Za-z0-9._-]{1,48}$/.test(currentKid)) throw new Error('Chave de assinatura atual ausente.');
  const keys = {};
  for (const [kid, encoded] of Object.entries(entries)) {
    if (!/^[A-Za-z0-9._-]{1,48}$/.test(kid) || !/^[A-Za-z0-9_-]+$/.test(String(encoded))) throw new Error('Configuração de assinatura inválida.');
    let key;
    try { key = crypto.createPrivateKey({ key: Buffer.from(encoded, 'base64url'), format: 'der', type: 'pkcs8' }); }
    catch { throw new Error('Configuração de assinatura inválida.'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Configuração de assinatura inválida.');
    keys[kid] = key;
  }
  return { keys, currentKid };
}

function releaseKeys(env = process.env) {
  const entries = parseJsonMap(env.CPA_RELEASE_KEYS, 'CPA_RELEASE_KEYS');
  for (const [releaseId, encoded] of Object.entries(entries)) {
    if (!RELEASE_ID.test(releaseId) || !B64_32.test(String(encoded))) throw new Error('Mapa de releases inválido.');
  }
  return entries;
}

function validatePayload(action, payload) {
  if (!ACTIONS.has(action) || !payload || typeof payload !== 'object') throw new LicenseProtocolError('invalid_request');
  const value = {
    requestNonce: String(payload.requestNonce || ''),
    hwid: String(payload.hwid || '').toLowerCase(),
    publicKey: String(payload.publicKey || ''),
    releaseId: String(payload.releaseId || ''),
    licenseKey: payload.licenseKey === undefined ? '' : String(payload.licenseKey),
    sessionToken: payload.sessionToken === undefined ? '' : String(payload.sessionToken),
    scope: payload.scope === undefined ? '' : String(payload.scope)
  };
  if (!B64_32.test(value.requestNonce) || !HEX_256.test(value.hwid) || !RELEASE_ID.test(value.releaseId) ||
      !/^[A-Za-z0-9_-]{40,255}$/.test(value.publicKey)) throw new LicenseProtocolError('invalid_request');
  if (action === 'activate' ? !B64_32.test(value.licenseKey) : !B64_32.test(value.sessionToken)) throw new LicenseProtocolError('invalid_request');
  if (action === 'authorize' && !SCOPES.has(value.scope)) throw new LicenseProtocolError('invalid_request');
  let publicKeyDer;
  let publicKeyObject;
  try {
    publicKeyDer = Buffer.from(value.publicKey, 'base64url');
    publicKeyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
  } catch { throw new LicenseProtocolError('invalid_request'); }
  if (publicKeyObject.asymmetricKeyType !== 'ed25519') throw new LicenseProtocolError('invalid_request');
  return { ...value, publicKeyDer, publicKeyObject, publicKeyHash: sha256Buffer(publicKeyDer) };
}

function proofMessage({ challengeId, nonce, action, payloadHash }) {
  return `${PROTOCOL}\n${challengeId}\n${nonce}\n${action}\n${payloadHash}`;
}

function verifyProof({ challengeId, nonce, action, payloadEncoded, signature, expectedPayloadHash }) {
  if (!UUID.test(String(challengeId || '')) || !B64_32.test(String(nonce || '')) || !B64_64.test(String(signature || ''))) {
    throw new LicenseProtocolError('invalid_proof', 401);
  }
  const payloadBytes = Buffer.from(String(payloadEncoded), 'base64url');
  const payloadHash = sha256Buffer(payloadBytes);
  if (!HEX_256.test(String(expectedPayloadHash || '')) || payloadHash !== expectedPayloadHash) throw new LicenseProtocolError('invalid_proof', 401);
  const payload = validatePayload(action, decodeJsonObject(payloadEncoded));
  const valid = crypto.verify(null, Buffer.from(proofMessage({ challengeId, nonce, action, payloadHash }), 'utf8'), payload.publicKeyObject, Buffer.from(signature, 'base64url'));
  if (!valid) throw new LicenseProtocolError('invalid_proof', 401);
  return payload;
}

function signResponse(payload, env = process.env) {
  const { keys, currentKid } = signingConfig(env);
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto.sign(null, Buffer.from(`${PROTOCOL}.response\n${encoded}`, 'utf8'), keys[currentKid]).toString('base64url');
  return { ok: true, kid: currentKid, payload: encoded, signature };
}

function responsePayload(action, request, result, sessionToken, releaseKey) {
  if (!result || !UUID.test(String(result.licenseId || '')) || !Number.isInteger(result.expiresIn) ||
      !Number.isFinite(Date.parse(String(result.serverTime || ''))) ||
      !(result.licenseExpiresAt === null || Number.isFinite(Date.parse(String(result.licenseExpiresAt || ''))))) {
    throw new LicenseProtocolError('server_unavailable', 503);
  }
  const expiresIn = Math.max(0, Math.min(MAX_SESSION_SECONDS, result.expiresIn));
  if (action !== 'logout' && expiresIn < 1) throw new LicenseProtocolError('session_expired', 401);
  return {
    requestNonce: request.requestNonce,
    action,
    hwid: request.hwid,
    publicKeyHash: request.publicKeyHash,
    licenseId: String(result.licenseId || ''),
    sessionToken: String(sessionToken || request.sessionToken || ''),
    serverTime: String(result.serverTime),
    expiresIn,
    licenseExpiresAt: result.licenseExpiresAt || null,
    status: 'valid',
    ...(action === 'authorize' ? { scope: request.scope } : {}),
    releaseId: request.releaseId,
    ...(releaseKey ? { releaseKey } : {})
  };
}

function databaseError(payload, status = 400) {
  const raw = String(payload?.message || payload?.error || '').trim().toLowerCase();
  const token = raw.match(/^(invalid_key|expired|suspended|revoked|banned|hwid_mismatch|device_banned|session_expired|replay|release_unknown|invalid_request)(?:\s|$)/)?.[1];
  if (token) return new LicenseProtocolError(token, token === 'invalid_request' ? 400 : token === 'replay' ? 409 : 401);
  if (status === 429) return new LicenseProtocolError('rate_limited', 429);
  return new LicenseProtocolError(status >= 500 || status === 404 ? 'server_unavailable' : 'invalid_request', status >= 500 || status === 404 ? 503 : 400);
}

module.exports = {
  PRODUCT_CODE, PROTOCOL, MAX_SESSION_SECONDS, ACTIONS, SCOPES, LicenseProtocolError,
  decodeJsonObject, sha256Buffer, pepperConfig, licenseDigest, licenseCandidates,
  generateLicense, signingConfig, releaseKeys, validatePayload, proofMessage,
  verifyProof, signResponse, responsePayload, databaseError
};
