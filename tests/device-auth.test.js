'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

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

test('device start keeps server secrets out of configuration and returns a short-lived challenge', async () => {
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/paxinbot_service_rate_limit')) return jsonReply(200, true);
    if (url.endsWith('/paxinbot_device_start_v2')) return jsonReply(200, { expiresAt: '2030-01-01T00:10:00.000Z' });
    return jsonReply(404, {});
  };
  const handler = require('../api/v1/devices/start');
  const res = response();
  await handler(request({ deviceName: 'PC\u0000 Teste', appVersion: '1.0.0' }, { host: 'www.paxincpa.store' }), res);
  assert.equal(res.statusCode, 201);
  assert.equal(res.body.ok, true);
  assert.match(res.body.secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(res.body.intervalMs, 5000);
  assert.match(res.body.verificationUrl, /^https:\/\/www\.paxincpa\.store\/activate\?/);
  const startPayload = JSON.parse(calls[1].options.body);
  assert.equal(startPayload.p_device_name, 'PC Teste');
  assert.match(startPayload.p_secret_hash, /^[a-f0-9]{64}$/);
  assert.equal(String(calls[1].options.headers.apikey).startsWith('sb_secret_'), true);
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
});
