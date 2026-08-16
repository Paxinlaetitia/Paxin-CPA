'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET = 'test-only-session-secret-that-is-not-deployed';
process.env.PUBLIC_SITE_URL = 'https://www.paxincpa.store';

function request(body = {}, headers = {}) {
  return { method: 'POST', body, headers, socket: { remoteAddress: '127.0.0.1' } };
}

function response() {
  const headers = {};
  return {
    statusCode: 0,
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    end(value) { this.body = JSON.parse(value); },
    headers
  };
}

function jsonReply(status, payload) {
  return Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => payload });
}

function signedDeviceProof(overrides = {}) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const proof = {
    installId:crypto.randomUUID(),
    publicKey:pair.publicKey.export({ format:'der',type:'spki' }).toString('base64url'),
    fingerprint:crypto.randomBytes(32).toString('hex'),
    fingerprintStrength:'hardware', issuedAt:Date.now(), nonce:crypto.randomBytes(24).toString('base64url'),
    appVersion:'1.0.0', ...overrides
  };
  const { canonicalDeviceProof } = require('../api/_paxinbot');
  proof.signature=crypto.sign(null,Buffer.from(canonicalDeviceProof(proof)),pair.privateKey).toString('base64url');
  return proof;
}

test('device start keeps server secrets out of configuration and returns a short-lived challenge', async () => {
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
    if (url.endsWith('/paxinbot_device_start_v3')) return jsonReply(200, { expiresAt: '2030-01-01T00:10:00.000Z' });
    return jsonReply(404, {});
  };
  const handler = require('../api/v1/devices/start');
  const res = response();
  await handler(request({ deviceName: 'PC\u0000 Teste', ...signedDeviceProof() }, { host: 'www.paxincpa.store' }), res);
  assert.equal(res.statusCode, 201);
  assert.equal(res.body.ok, true);
  assert.match(res.body.secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(res.body.intervalMs, 5000);
  assert.match(res.body.verificationUrl, /^https:\/\/www\.paxincpa\.store\/activate\?/);
  const startPayload = JSON.parse(calls[2].options.body);
  assert.equal(startPayload.p_device_name, 'PC Teste');
  assert.match(startPayload.p_secret_hash, /^[a-f0-9]{64}$/);
  assert.match(startPayload.p_fingerprint_hash, /^[a-f0-9]{64}$/);
  assert.match(startPayload.p_device_key_hash, /^[a-f0-9]{64}$/);
  assert.equal(String(calls[2].options.headers.apikey).startsWith('sb_secret_'), true);
});

test('device start rejects a tampered identity proof before the database', async () => {
  let called=false; global.fetch=async()=>{ called=true; return jsonReply(500,{}); };
  const proof=signedDeviceProof(); proof.fingerprint='f'.repeat(64);
  const handler=require('../api/v1/devices/start'); const res=response();
  await handler(request(proof),res);
  assert.equal(res.statusCode,400); assert.equal(called,false); assert.equal(res.body.code,'device_identity_invalid');
});

test('device start rejects malformed versions before reaching the database', async () => {
  let called = false;
  global.fetch = async () => { called = true; return jsonReply(500, {}); };
  const handler = require('../api/v1/devices/start');
  const res = response();
  await handler(request({ appVersion: '<script>' }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(called, false);
});

test('poll rejects malformed challenges without hashing arbitrary input', async () => {
  let called = false;
  global.fetch = async () => { called = true; return jsonReply(500, {}); };
  const handler = require('../api/v1/devices/poll');
  const res = response();
  await handler(request({ requestId: 'not-a-uuid', secret: 'short' }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(called, false);
});

test('desktop endpoint only accepts the opaque token format issued by the server', async () => {
  let called = false;
  global.fetch = async () => { called = true; return jsonReply(500, {}); };
  const handler = require('../api/v1/desktop/session');
  const req = request(); req.method = 'GET'; req.headers.authorization = 'Bearer arbitrary-jwt';
  const res = response();
  await handler(req, res);
  assert.equal(res.statusCode, 401);
  assert.equal(called, false);
});

test('desktop pause closes the metered interval through the dedicated RPC', async () => {
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
    if (url.endsWith('/paxinbot_pause_desktop_usage_v3')) return jsonReply(200, { active: true, paused: true, remainingSeconds: 2190 });
    return jsonReply(404, {});
  };
  const handler = require('../api/v1/desktop/session');
  const req = request(); req.method = 'POST'; req.headers.authorization = `Bearer ${'a'.repeat(64)}`;
  const res = response();
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.paused, true);
  assert.match(calls[1].url, /paxinbot_pause_desktop_usage_v3$/);
  assert.deepEqual(JSON.parse(calls[1].options.body), { p_token_hash: 'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb' });
});

test('database authorization failures are translated without exposing internals', () => {
  const { safeDeviceAuthError } = require('../api/_paxinbot');
  assert.deepEqual(safeDeviceAuthError({ message: 'no_active_access' }), {
    code: 'access_required',
    error: 'Sua conta não possui acesso ativo ao aplicativo.'
  });
  assert.deepEqual(safeDeviceAuthError({ message: 'device_expired' }), {
    code: 'request_expired',
    error: 'A solicitação expirou. Inicie o login novamente no aplicativo.'
  });
  assert.equal(safeDeviceAuthError({ message: 'SQL details that must stay private' }).code, 'authorization_failed');
  assert.deepEqual(safeDeviceAuthError({ code: '42702', message: 'internal database detail' }), {
    code: 'database_incompatible',
    diagnosticCode: '42702',
    error: 'A função de acesso instalada no banco está incompatível. Código 42702.'
  });
});

test('desktop session migration resolves pgcrypto from the Supabase extensions schema', () => {
  const migration = fs.readFileSync(
    path.join(__dirname, '..', 'supabase', 'migrations', '20260821_desktop_crypto_schema.sql'),
    'utf8'
  );
  assert.match(migration, /extensions\.gen_random_bytes\(32\)/);
  assert.match(migration, /extensions\.digest\(v_token, 'sha256'\)/);
  assert.doesNotMatch(migration, /(?<!\.)\bgen_random_bytes\(/);
  assert.doesNotMatch(migration, /(?<!\.)\bdigest\(/);
});

test('device identity migration enforces bans and one promotional claim per machine', () => {
  const migration=fs.readFileSync(path.join(__dirname,'..','supabase','migrations','20260826_device_identity.sql'),'utf8');
  assert.match(migration,/create table if not exists public\.device_identities/i);
  assert.match(migration,/device_proof_replayed/i);
  assert.match(migration,/promotion_device_already_used/i);
  assert.match(migration,/where fingerprint_hash=v_identity\.fingerprint_hash/i);
  assert.match(migration,/update public\.desktop_sessions set revoked_at/i);
  assert.match(migration,/paxinbot_owner_set_device_ban/i);
  assert.doesNotMatch(migration,/grant (select|insert|update|delete) on table public\.device_identities/i);
});
