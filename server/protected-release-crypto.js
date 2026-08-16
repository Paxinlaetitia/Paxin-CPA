'use strict';

const crypto = require('node:crypto');

const AUTH_SCHEMA = 'paxinbot.module-authorization/v1';
const RELEASE_RE = /^\d{1,4}(?:\.\d{1,4}){1,3}(?:-[0-9A-Za-z.-]{1,24})?$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

function parseReleaseRequest(body) {
  const value = {
    version: String(body?.version || '').trim(),
    sequence: Number(body?.sequence),
    integrityDigest: String(body?.integrityDigest || '').toLowerCase(),
    moduleIndexDigest: String(body?.moduleIndexDigest || '').toLowerCase(),
    requestNonce: String(body?.requestNonce || ''),
    clientPublicKey: String(body?.clientPublicKey || '')
  };
  if (!RELEASE_RE.test(value.version) || !Number.isSafeInteger(value.sequence) || value.sequence < 1 ||
      !SHA256_RE.test(value.integrityDigest) || !SHA256_RE.test(value.moduleIndexDigest) ||
      !BASE64URL_RE.test(value.requestNonce) || Buffer.from(value.requestNonce, 'base64url').length !== 32 ||
      !BASE64URL_RE.test(value.clientPublicKey) || value.clientPublicKey.length < 50 || value.clientPublicKey.length > 200) {
    throw new Error('protected_release_request_invalid');
  }
  let key;
  try { key = crypto.createPublicKey({ key: Buffer.from(value.clientPublicKey, 'base64url'), format: 'der', type: 'spki' }); }
  catch { throw new Error('protected_release_request_invalid'); }
  if (key.asymmetricKeyType !== 'x25519') throw new Error('protected_release_request_invalid');
  return { ...value, clientKey: key };
}

function readReleaseEnvironment(env = process.env) {
  const value = {
    version: String(env.PAXINBOT_PROTECTED_RELEASE_VERSION || '').trim(),
    sequence: Number(env.PAXINBOT_PROTECTED_RELEASE_SEQUENCE),
    integrityDigest: String(env.PAXINBOT_PROTECTED_INTEGRITY_SHA256 || '').toLowerCase(),
    moduleIndexDigest: String(env.PAXINBOT_PROTECTED_INDEX_SHA256 || '').toLowerCase(),
    keyId: String(env.PAXINBOT_MODULE_AUTH_KEY_ID || '').trim(),
    contentKey: Buffer.from(String(env.PAXINBOT_MODULE_CONTENT_KEY || ''), 'base64url')
  };
  if (!RELEASE_RE.test(value.version) || !Number.isSafeInteger(value.sequence) || value.sequence < 1 ||
      !SHA256_RE.test(value.integrityDigest) || !SHA256_RE.test(value.moduleIndexDigest) ||
      !/^[A-Za-z0-9._-]{8,80}$/.test(value.keyId) || value.contentKey.length !== 32) {
    throw new Error('protected_release_environment_invalid');
  }
  try {
    value.signingKey = crypto.createPrivateKey({
      key: Buffer.from(String(env.PAXINBOT_MODULE_AUTH_PRIVATE_KEY || ''), 'base64url'),
      format: 'der', type: 'pkcs8'
    });
  } catch { throw new Error('protected_release_environment_invalid'); }
  if (value.signingKey.asymmetricKeyType !== 'ed25519') throw new Error('protected_release_environment_invalid');
  return value;
}

function assertOfficialRelease(request, release) {
  if (request.version !== release.version || request.sequence !== release.sequence ||
      request.integrityDigest !== release.integrityDigest || request.moduleIndexDigest !== release.moduleIndexDigest) {
    throw new Error('protected_release_not_allowed');
  }
}

function authorizationAad(value) {
  return stableStringify({
    schema: AUTH_SCHEMA,
    userId: value.userId,
    sessionId: value.sessionId,
    deviceIdentityId: value.deviceIdentityId,
    version: value.version,
    sequence: value.sequence,
    integrityDigest: value.integrityDigest,
    moduleIndexDigest: value.moduleIndexDigest,
    requestNonce: value.requestNonce,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    clientPublicKey: value.clientPublicKey,
    serverPublicKey: value.serverPublicKey
  });
}

function createAuthorization({ request, release, identity, now = Date.now(), ttlMs = 90000 } = {}) {
  if (!identity || !/^[0-9a-f-]{36}$/i.test(String(identity.userId || '')) ||
      !/^[0-9a-f-]{36}$/i.test(String(identity.sessionId || '')) ||
      !/^[0-9a-f-]{36}$/i.test(String(identity.deviceIdentityId || ''))) {
    throw new Error('protected_release_identity_invalid');
  }
  assertOfficialRelease(request, release);
  const serverPair = crypto.generateKeyPairSync('x25519');
  const serverPublicKey = serverPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + Math.max(30000, Math.min(120000, Number(ttlMs) || 90000))).toISOString();
  const metadata = {
    userId: String(identity.userId), sessionId: String(identity.sessionId),
    deviceIdentityId: String(identity.deviceIdentityId), version: request.version,
    sequence: request.sequence, integrityDigest: request.integrityDigest,
    moduleIndexDigest: request.moduleIndexDigest, requestNonce: request.requestNonce,
    issuedAt, expiresAt, clientPublicKey: request.clientPublicKey, serverPublicKey
  };
  const aad = Buffer.from(authorizationAad(metadata), 'utf8');
  const shared = crypto.diffieHellman({ privateKey: serverPair.privateKey, publicKey: request.clientKey });
  const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(request.requestNonce, 'base64url'), Buffer.from(`paxinbot-module-wrap-v1\0${identity.sessionId}`, 'utf8'), 32));
  const wrapNonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapNonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const wrappedKey = Buffer.concat([cipher.update(release.contentKey), cipher.final()]);
  const wrapTag = cipher.getAuthTag();
  shared.fill(0); wrapKey.fill(0);
  const unsigned = {
    schema: AUTH_SCHEMA, keyId: release.keyId, ...metadata,
    wrap: {
      algorithm: 'X25519-HKDF-SHA256+A256GCM',
      nonce: wrapNonce.toString('base64url'),
      ciphertext: wrappedKey.toString('base64url'),
      tag: wrapTag.toString('base64url')
    }
  };
  const signature = crypto.sign(null, Buffer.from(stableStringify(unsigned), 'utf8'), release.signingKey).toString('base64url');
  return { ...unsigned, signature: { algorithm: 'Ed25519', keyId: release.keyId, value: signature } };
}

const SAFE_DENIAL_REASONS = new Set([
  'service_role_required', 'protected_release_request_invalid',
  'desktop_session_invalid', 'protected_release_version_mismatch',
  'account_unverified', 'account_disabled', 'device_banned',
  'risk_reauthentication_required', 'no_active_access',
  'protected_release_nonce_replayed'
]);

function safeDenialReason(payload) {
  const reason = String(payload && payload.message || '').trim();
  return SAFE_DENIAL_REASONS.has(reason) ? reason : 'upstream_rejected';
}

module.exports = {
  AUTH_SCHEMA, stableStringify, parseReleaseRequest, readReleaseEnvironment,
  assertOfficialRelease, authorizationAad, createAuthorization, safeDenialReason
};
