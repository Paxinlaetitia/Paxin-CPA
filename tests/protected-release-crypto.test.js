'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  AUTH_SCHEMA, stableStringify, parseReleaseRequest, readReleaseEnvironment,
  createAuthorization, authorizationAad, safeDenialReason
} = require('../server/protected-release-crypto');

function fixture() {
  const client = crypto.generateKeyPairSync('x25519');
  const signer = crypto.generateKeyPairSync('ed25519');
  const requestNonce = crypto.randomBytes(32).toString('base64url');
  const request = parseReleaseRequest({
    version:'1.0.0', sequence:9, integrityDigest:'a'.repeat(64),
    moduleIndexDigest:'b'.repeat(64), requestNonce,
    clientPublicKey:client.publicKey.export({ format:'der', type:'spki' }).toString('base64url')
  });
  const release = readReleaseEnvironment({
    PAXINBOT_PROTECTED_RELEASE_VERSION:'1.0.0', PAXINBOT_PROTECTED_RELEASE_SEQUENCE:'9',
    PAXINBOT_PROTECTED_INTEGRITY_SHA256:'a'.repeat(64), PAXINBOT_PROTECTED_INDEX_SHA256:'b'.repeat(64),
    PAXINBOT_MODULE_CONTENT_KEY:crypto.randomBytes(32).toString('base64url'),
    PAXINBOT_MODULE_AUTH_PRIVATE_KEY:signer.privateKey.export({ format:'der', type:'pkcs8' }).toString('base64url'),
    PAXINBOT_MODULE_AUTH_KEY_ID:'module-auth-test-1'
  });
  return { client, signer, request, release };
}

test('emite autorizacao assinada e a chave so abre com a chave X25519 correta', () => {
  const { client, signer, request, release } = fixture();
  const expectedContentKey = Buffer.from(release.contentKey);
  const auth = createAuthorization({ request, release, identity:{
    userId:'11111111-1111-4111-8111-111111111111',
    sessionId:'22222222-2222-4222-8222-222222222222',
    deviceIdentityId:'33333333-3333-4333-8333-333333333333'
  }, now:Date.parse('2026-08-16T12:00:00.000Z') });
  assert.equal(auth.schema, AUTH_SCHEMA);
  const unsigned = { ...auth }; delete unsigned.signature;
  assert.equal(crypto.verify(null, Buffer.from(stableStringify(unsigned)), signer.publicKey, Buffer.from(auth.signature.value, 'base64url')), true);
  const serverKey = crypto.createPublicKey({ key:Buffer.from(auth.serverPublicKey,'base64url'), format:'der', type:'spki' });
  const shared = crypto.diffieHellman({ privateKey:client.privateKey, publicKey:serverKey });
  const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(auth.requestNonce,'base64url'), Buffer.from(`paxinbot-module-wrap-v1\0${auth.sessionId}`), 32));
  const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, Buffer.from(auth.wrap.nonce,'base64url'));
  decipher.setAAD(Buffer.from(authorizationAad(auth)));
  decipher.setAuthTag(Buffer.from(auth.wrap.tag,'base64url'));
  const opened = Buffer.concat([decipher.update(Buffer.from(auth.wrap.ciphertext,'base64url')), decipher.final()]);
  assert.deepEqual(opened, expectedContentKey);
  shared.fill(0); wrapKey.fill(0); opened.fill(0); expectedContentKey.fill(0); release.contentKey.fill(0);
});

test('rejeita release, nonce e chave efemera fora do contrato', () => {
  const { request, release } = fixture();
  assert.throws(() => parseReleaseRequest({ ...request, requestNonce:'curto' }), /protected_release_request_invalid/);
  assert.throws(() => parseReleaseRequest({ ...request, clientPublicKey:crypto.randomBytes(40).toString('base64url') }), /protected_release_request_invalid/);
  assert.throws(() => createAuthorization({ request:{...request,sequence:8}, release, identity:{} }), /protected_release_identity_invalid|protected_release_not_allowed/);
  release.contentKey.fill(0);
});

test('alteracao do envelope invalida a assinatura', () => {
  const { signer, request, release } = fixture();
  const auth = createAuthorization({ request, release, identity:{
    userId:'11111111-1111-4111-8111-111111111111', sessionId:'22222222-2222-4222-8222-222222222222',
    deviceIdentityId:'33333333-3333-4333-8333-333333333333'
  } });
  const signature = Buffer.from(auth.signature.value,'base64url');
  const unsigned = { ...auth }; delete unsigned.signature; unsigned.sequence = 10;
  assert.equal(crypto.verify(null, Buffer.from(stableStringify(unsigned)), signer.publicKey, signature), false);
  release.contentKey.fill(0);
});

test('registra somente motivos de recusa permitidos', () => {
  assert.equal(safeDenialReason({ message:'device_banned' }), 'device_banned');
  assert.equal(safeDenialReason({ message:'sensitive database detail' }), 'upstream_rejected');
  assert.equal(safeDenialReason(null), 'upstream_rejected');
});
