'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET = 'test-only-session-secret-that-is-not-deployed';
process.env.PUBLIC_SITE_URL = 'https://www.paxincpa.store';

const handler = require('../api/auth/[action]');

function request(body) {
  const csrf='a'.repeat(43);
  return { method:'POST', query:{ action:'signup' }, url:'/api/auth/signup', body, headers:{ origin:'https://www.paxincpa.store', host:'www.paxincpa.store', 'x-forwarded-proto':'https', 'content-type':'application/json', cookie:`paxinbot_csrf=${csrf}`, 'x-paxinbot-csrf':csrf } };
}
function response() {
  const headers = {};
  return { statusCode:0, headers, setHeader(name, value) { headers[name.toLowerCase()] = value; }, end(value) { this.body = JSON.parse(value); } };
}
function jsonReply(status, payload) {
  return Promise.resolve({ ok:status >= 200 && status < 300, status, json:async () => payload });
}

test('signup rejects invalid usernames before contacting the identity provider', async () => {
  let called = false;
  global.fetch = async () => { called = true; return jsonReply(500, {}); };
  const res = response();
  await handler(request({ username:'nome com espaço', email:'cliente@example.com', password:'uma-senha-segura' }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(called, false);
  assert.match(res.body.error, /nome de usuário/i);
});

test('signup normalizes and stores the username as authenticated profile metadata', async () => {
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/paxinbot_service_rate_limit_v2')) return jsonReply(200, { allowed:true, remaining:9, resetAfter:3600 });
    return jsonReply(200, { user:{ id:'2bb411cf-c4cd-4404-9ac2-f49fe9cd11b0' } });
  };
  const res = response();
  await handler(request({ username:'  Guilherme.137  ', email:'CLIENTE@EXAMPLE.COM', password:'uma-senha-segura' }), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verificationRequired, true);
  const payload = JSON.parse(calls[2].options.body);
  assert.equal(payload.email, 'cliente@example.com');
  assert.deepEqual(payload.data, { display_name:'guilherme.137' });
  assert.equal(Object.hasOwn(payload, 'passwordConfirm'), false);
});
