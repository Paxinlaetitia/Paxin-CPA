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
  return { method: 'POST', body, headers: { 'content-type':'application/json', ...headers }, socket: { remoteAddress: '127.0.0.1' } };
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
    if (url.endsWith('/paxinbot_desktop_session_v4')) return jsonReply(200, { active: true, paused: true, remainingSeconds: 2190 });
    return jsonReply(404, {});
  };
  const handler = require('../api/v1/desktop/session');
  const req = request(); req.method = 'POST'; req.headers.authorization = `Bearer ${'a'.repeat(64)}`;
  const res = response();
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.paused, true);
  assert.match(calls[1].url, /paxinbot_desktop_session_v4$/);
  assert.deepEqual(JSON.parse(calls[1].options.body), { p_token_hash: 'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb', p_action: 'pause' });
});

test('desktop profile and operation use distinct database actions and return the account profile', async () => {
  const handler = require('../api/v1/desktop/session');
  const profile = { nickname: 'Conta de teste', avatarUrl: null };
  for (const action of ['profile', 'session']) {
    const calls = [];
    global.fetch = async (url, options) => {
      if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
      calls.push({ url, body: JSON.parse(options.body) });
      return jsonReply(200, { active: true, profile, entitlement: { active: true, kind: 'usage', remainingSeconds: 2200 }, sessionExpiresAt: '2030-01-31T00:00:00Z' });
    };
    const req = request({}, { authorization: `Bearer ${'a'.repeat(64)}` });
    req.method = 'GET'; req.query = action === 'profile' ? { action } : {};
    const res = response(); await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.profile, profile);
    assert.equal(res.body.entitlement.remainingSeconds, 2200);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /paxinbot_desktop_session_v4$/);
    assert.equal(calls[0].body.p_action, action);
    assert.equal(calls[0].body.p_token_hash, crypto.createHash('sha256').update('a'.repeat(64)).digest('hex'));
  }
});

test('desktop upstream failures and malformed success never invalidate the bearer', async () => {
  const handler = require('../api/v1/desktop/session');
  const cases = [
    ...[400, 401, 403, 404, 429, 500, 503].map(status => () => jsonReply(status, { active: false, reason: 'session_invalid', message: 'private database detail' })),
    () => jsonReply(200, null),
    () => jsonReply(200, {}),
    () => jsonReply(200, { active: true }),
    () => { throw new Error('private connection detail'); }
  ];
  for (const reply of cases) {
    global.fetch = async url => url.endsWith('/paxinbot_service_rate_limit') ? jsonReply(200, true) : reply();
    const req = request({}, { authorization: `Bearer ${'a'.repeat(64)}` }); req.method = 'GET'; req.query = { action: 'profile' };
    const res = response(); await handler(req, res);
    assert.equal(res.statusCode, 503);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.reason, undefined);
    assert.doesNotMatch(JSON.stringify(res.body), /private|session_invalid/);
  }
});

test('only an authoritative inactive session returns 401', async () => {
  const handler = require('../api/v1/desktop/session');
  for (const reason of ['session_invalid', 'device_banned', 'account_disabled', 'risk_reauthentication_required', 'no_active_access', 'usage_exhausted']) {
    global.fetch = async url => jsonReply(200, url.endsWith('/paxinbot_service_rate_limit') ? true : { active: false, reason });
    const req = request({}, { authorization: `Bearer ${'a'.repeat(64)}` }); req.method = 'GET'; req.query = { action: 'profile' };
    const res = response(); await handler(req, res);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.reason, reason);
  }
});

test('desktop logout selects only the bearer while other POST actions still pause', async () => {
  const handler = require('../api/v1/desktop/session');
  for (const action of ['logout', 'profile', 'unknown']) {
    let parameters;
    global.fetch = async (url, options) => {
      if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
      parameters = JSON.parse(options.body);
      return jsonReply(200, action === 'logout' ? { active: false, loggedOut: true, paused: true } : { active: true, paused: true });
    };
    const req = request({ userId: crypto.randomUUID(), sessionId: crypto.randomUUID() }, { authorization: `Bearer ${'a'.repeat(64)}` }); req.query = { action };
    const res = response(); await handler(req, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.paused, true);
    assert.deepEqual(Object.keys(parameters).sort(), ['p_action', 'p_token_hash']);
    assert.equal(parameters.p_action, action === 'logout' ? 'logout' : 'pause');
    if (action === 'logout') assert.deepEqual(res.body, { ok: true, active: false, loggedOut: true, paused: true });
  }
});

test('desktop logout does not acknowledge a missing revocation confirmation', async () => {
  global.fetch = async url => jsonReply(200, url.endsWith('/paxinbot_service_rate_limit') ? true : { active: true });
  const req = request({}, { authorization: `Bearer ${'a'.repeat(64)}` }); req.query = { action: 'logout' };
  const res = response(); await require('../api/v1/desktop/session')(req, res);
  assert.equal(res.statusCode, 503);
});

test('poll carries the real profile only after approval through the persistent-session RPC', async () => {
  const handler = require('../api/v1/devices/poll');
  for (const status of ['pending', 'approved']) {
    const profile = { nickname: 'Conta de teste', avatarUrl: null };
    const payload = status === 'approved' ? { status, desktopToken: 'b'.repeat(64), profile, sessionExpiresAt: '2030-01-31T00:00:00Z' } : { status, intervalMs: 5000 };
    let rpc;
    global.fetch = async url => {
      if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
      rpc = url; return jsonReply(200, payload);
    };
    const res = response(); await handler(request({ requestId: crypto.randomUUID(), secret: 'a'.repeat(43) }), res);
    assert.equal(res.statusCode, 200);
    assert.match(rpc, /paxinbot_device_poll_v4$/);
    assert.deepEqual(res.body.profile, status === 'approved' ? profile : undefined);
  }
});

test('poll reports unavailable migrations and connection failures as retryable', async () => {
  const handler = require('../api/v1/devices/poll');
  for (const status of [401, 403, 404, 500, 503, null]) {
    global.fetch = async url => {
      if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
      if (status === null) throw new Error('private connection detail');
      return jsonReply(status, { message: 'private database detail' });
    };
    const res = response(); await handler(request({ requestId: crypto.randomUUID(), secret: 'a'.repeat(43) }), res);
    assert.equal(res.statusCode, 503);
    assert.doesNotMatch(JSON.stringify(res.body), /private/);
  }
});

test('persistent-session migration guards profile reads without advancing usage accounting', () => {
  const migration = fs.readFileSync(path.join(__dirname, '..', 'supabase/migrations/20260904_desktop_persistent_session.sql'), 'utf8');
  const validation = migration.split("if v_session.revoked_at is not null")[1].split("if p_action='profile' then")[0];
  for (const guard of ['expires_at<=now()', 'device_identity_id is null', 'banned_at is not null', 'fingerprint_hash=v_identity.fingerprint_hash', 'restricted_until>now()', 'profile.disabled_at is null', 'paxinbot_active_entitlement', 'user_id=v_session.user_id']) assert.ok(validation.includes(guard), guard);
  const profileBranch = migration.split("if p_action='profile' then")[1].split("elsif p_action='pause' then")[0];
  assert.doesNotMatch(validation + profileBranch, /update public\.usage_grants|set last_seen_at|set usage_paused_at|paxinbot_desktop_session_v2\(|paxinbot_pause_desktop_usage\(/);
  assert.match(migration, /v_result->>'active' is distinct from 'true' then return v_result; end if;\s+update public\.desktop_sessions set expires_at=now\(\)\+interval '30 days'/);
  assert.doesNotMatch(migration, /update public\.entitlements/);
  const logout = migration.split("if p_action='logout' then")[1].split('if v_session.revoked_at is not null')[0];
  assert.match(logout, /where id=v_session\.id/);
  assert.doesNotMatch(logout, /paxinbot_pause_desktop_usage|where usage_grant_id=|where user_id=/);
  assert.match(migration, /set usage_paused_at=now\(\),expires_at=now\(\)\+interval '30 days'/);
  assert.match(migration, /'nickname',coalesce\(nullif\(btrim\(profile\.display_name\),''\)/);
  assert.match(migration, /'avatarUrl',case when to_jsonb\(profile\) \? 'avatar_data' then to_jsonb\(profile\)->>'avatar_data'/);
  assert.match(migration, /account\.raw_user_meta_data->>'avatar_url'/);
  for (const signature of ['paxinbot_desktop_session_v4(text,text)', 'paxinbot_device_poll_v4(uuid,text)']) {
    assert.ok(migration.includes(`revoke all on function public.${signature} from public,anon,authenticated;`));
    assert.ok(migration.includes(`grant execute on function public.${signature} to service_role;`));
  }
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
