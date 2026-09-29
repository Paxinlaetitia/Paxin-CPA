'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const licensing = require('../server/cpa-licensing');
const migration = fs.readFileSync(path.join(__dirname, '..', 'supabase/migrations/20260929_cpa_licenses.sql'), 'utf8');

function environment() {
  const signing = crypto.generateKeyPairSync('ed25519');
  return {
    CPA_LICENSE_HMAC_PEPPERS: JSON.stringify({ v1:'test-pepper-with-at-least-thirty-two-bytes-123' }),
    CPA_LICENSE_HMAC_CURRENT_VERSION:'v1',
    CPA_LICENSE_SIGNING_KEYS:JSON.stringify({ test:signing.privateKey.export({ format:'der', type:'pkcs8' }).toString('base64url') }),
    CPA_LICENSE_SIGNING_CURRENT_KID:'test',
    CPA_RELEASE_KEYS:JSON.stringify({ 'cash-hunters-1.6.0-test':crypto.randomBytes(32).toString('base64url') })
  };
}

test('license keys are random, one-way and versioned for rotation', () => {
  const env=environment(); const first=licensing.generateLicense(env); const second=licensing.generateLicense(env);
  assert.match(first.licenseKey,/^[A-Za-z0-9_-]{43}$/);
  assert.equal(first.pepperVersion,'v1');
  assert.notEqual(first.licenseKey,second.licenseKey);
  assert.notEqual(first.keyHash,first.licenseKey);
  assert.deepEqual(licensing.licenseCandidates(first.licenseKey,env),[{ version:'v1',hash:first.keyHash }]);
});

test('Ed25519 proof binds challenge, nonce, action and exact payload bytes', () => {
  const pair=crypto.generateKeyPairSync('ed25519');
  const publicKey=pair.publicKey.export({ format:'der',type:'spki' }).toString('base64url');
  const value={requestNonce:crypto.randomBytes(32).toString('base64url'),hwid:'a'.repeat(64),publicKey,releaseId:'cash-hunters-1.6.0-test',sessionToken:crypto.randomBytes(32).toString('base64url')};
  const encoded=Buffer.from(JSON.stringify(value)).toString('base64url'); const payloadHash=licensing.sha256Buffer(Buffer.from(encoded,'base64url'));
  const challengeId=crypto.randomUUID(),nonce=crypto.randomBytes(32).toString('base64url'),action='refresh';
  const signature=crypto.sign(null,Buffer.from(licensing.proofMessage({challengeId,nonce,action,payloadHash})),pair.privateKey).toString('base64url');
  assert.equal(licensing.verifyProof({challengeId,nonce,action,payloadEncoded:encoded,signature,expectedPayloadHash:payloadHash}).publicKeyHash,licensing.sha256Buffer(Buffer.from(publicKey,'base64url')));
  assert.throws(()=>licensing.verifyProof({challengeId,nonce:crypto.randomBytes(32).toString('base64url'),action,payloadEncoded:encoded,signature,expectedPayloadHash:payloadHash}),error=>error.code==='invalid_proof');
});

test('signed response verifies with the pinned public key and caps leases at 120 seconds', () => {
  const env=environment(); const privateKey=JSON.parse(env.CPA_LICENSE_SIGNING_KEYS).test;
  const publicKey=crypto.createPublicKey(crypto.createPrivateKey({key:Buffer.from(privateKey,'base64url'),format:'der',type:'pkcs8'}));
  const request={requestNonce:'n'.repeat(43),hwid:'a'.repeat(64),publicKeyHash:'b'.repeat(64),sessionToken:'s'.repeat(43),releaseId:'cash-hunters-1.6.0-test',scope:'manager'};
  const payload=licensing.responsePayload('authorize',request,{licenseId:crypto.randomUUID(),expiresIn:999,serverTime:new Date().toISOString(),licenseExpiresAt:null},'',crypto.randomBytes(32).toString('base64url'));
  assert.equal(payload.expiresIn,120); assert.equal(payload.scope,'manager');
  const signed=licensing.signResponse(payload,env);
  assert.equal(crypto.verify(null,Buffer.from(`PAXINCPA/1.response\n${signed.payload}`),publicKey,Buffer.from(signed.signature,'base64url')),true);
});

test('database errors use exact tokens so device/session errors are not collapsed', () => {
  assert.equal(licensing.databaseError({message:'device_banned'}).code,'device_banned');
  assert.equal(licensing.databaseError({message:'session_expired'}).code,'session_expired');
  assert.equal(licensing.databaseError({message:'expired'}).code,'expired');
  assert.equal(licensing.databaseError({message:'private detail: device_banned'}).code,'invalid_request');
});

test('migration keeps Cash Hunters authority isolated and fail-closed', () => {
  for(const table of ['cpa_licenses','cpa_devices','cpa_sessions','cpa_challenges','cpa_audit']) assert.match(migration,new RegExp(`create table if not exists public\\.${table}`));
  assert.doesNotMatch(migration,/insert into public\.entitlements|update public\.entitlements|paxinbot_active_entitlement/);
  assert.match(migration,/auth\.role\(\) is distinct from 'service_role'/);
  assert.match(migration,/status in \('pending','inactive','active','suspended','revoked','banned'\)/);
  assert.match(migration,/l\.status='pending' and l\.activation_policy='first' and l\.activated_at is null/);
  assert.match(migration,/least\(now\(\)\+interval '120 seconds'/);
  assert.match(migration,/months' then return p_base\+make_interval\(months=>p_value\)/);
  assert.match(migration,/set timezone='UTC'/);
  assert.match(migration,/activeSessions/); assert.match(migration,/sessionLastSeenAt/);
  assert.match(migration,/cpa_license_record_denial/);
  assert.match(migration,/^begin;[\s\S]*commit;\s*$/m);
  assert.match(migration,/cpa_challenges where expires_at<now\(\)-interval '24 hours'/);
  assert.match(migration,/cpa_sessions where expires_at<now\(\)-interval '30 days'/);
  assert.match(migration,/cpa_audit where created_at<now\(\)-interval '365 days'/);
  assert.match(migration,/pg_advisory_xact_lock\(hashtextextended\('cash-hunters:'\|\|p_hwid,0\)\)/);
  assert.equal((migration.match(/s\.token_hash is distinct from p_session_token_hash/g)||[]).length,3);
  for(const table of ['cpa_licenses','cpa_devices','cpa_device_bans','cpa_sessions','cpa_challenges','cpa_audit']) assert.match(migration,new RegExp(`alter table public\\.${table} enable row level security`));
});
