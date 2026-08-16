'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET = 'test-only-session-secret-that-is-not-deployed';
process.env.PUBLIC_SITE_URL = 'https://www.paxincpa.store';

const handler = require('../api/auth/[action].js');
const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

function response() {
  const headers = {};
  return {
    statusCode:0, headers,
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    getHeader(name) { return headers[name.toLowerCase()]; },
    end(value = '') { this.body = value ? JSON.parse(value) : null; }
  };
}

function request(action, method = 'GET', body, csrf = '') {
  return {
    method, query:{ action }, url:`/api/auth/${action}`, body,
    headers:{
      host:'www.paxincpa.store', origin:'https://www.paxincpa.store',
      'x-forwarded-proto':'https', 'content-type':'application/json',
      cookie:`paxinbot_access=access-token${csrf ? `; paxinbot_csrf=${csrf}` : ''}`,
      ...(csrf ? { 'x-paxinbot-csrf':csrf } : {})
    }
  };
}

function upstream(payload, status = 200) {
  return { ok:status >= 200 && status < 300, status, async json() { return payload; } };
}

test('authenticated session lists passkey devices without exposing session tokens', async () => {
  const originalFetch = global.fetch; const calls = [];
  global.fetch = async (url, options = {}) => {
    calls.push({ url:String(url), options });
    if (String(url).endsWith('/auth/v1/user')) return upstream({ id:'11111111-1111-4111-8111-111111111111', email:'user@example.com' });
    if (String(url).endsWith('/auth/v1/passkeys')) return upstream([{ id:'22222222-2222-4222-8222-222222222222', friendly_name:'Windows Hello', created_at:'2026-08-16T10:00:00Z', last_used_at:'2026-08-16T11:00:00Z' }]);
    throw new Error(`Unexpected fetch: ${url}`);
  };
  try {
    const res = response(); await handler(request('passkeys'), res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, [{ id:'22222222-2222-4222-8222-222222222222', friendlyName:'Windows Hello', createdAt:'2026-08-16T10:00:00Z', lastUsedAt:'2026-08-16T11:00:00Z' }]);
    assert.equal(JSON.stringify(res.body).includes('access-token'), false);
    assert.match(calls[1].options.headers.authorization, /^Bearer access-token$/);
  } finally { global.fetch = originalFetch; }
});

test('passkey enrollment uses the existing HttpOnly browser session and CSRF', async () => {
  const source = `${read('auth-client.js')}\n${read('api/auth/[action].js')}\n${read('cliente.html')}`;
  assert.match(source, /passkeys\/registration\/options/);
  assert.match(source, /passkeys\/registration\/verify/);
  assert.match(source, /navigator\.credentials\.create/);
  assert.match(source, /data-remove-passkey/);
  assert.match(source, /passkey-delete/);
  assert.doesNotMatch(source, /passkey-password-confirm|passkey-dialog|paxinbot_passkey_session|intent=passkey/);
  assert.doesNotMatch(read('auth-client.js'), /setSession\(\{ access_token:passkey/);
  assert.match(read('api/auth/[action].js'), /auth\.passkey_failure/);
  assert.match(read('cliente.html'), /auth-client\.js\?v=20260816-3/);

  const csrf = 'a'.repeat(43); const originalFetch = global.fetch; const calls = [];
  global.fetch = async (url, options = {}) => {
    calls.push(String(url));
    if (String(url).endsWith('/auth/v1/user')) return upstream({ id:'11111111-1111-4111-8111-111111111111', email:'user@example.com' });
    if (String(url).includes('/rest/v1/rpc/paxinbot_service_rate_limit_v2')) return upstream({ allowed:true, remaining:7, resetAfter:600 });
    if (String(url).endsWith('/auth/v1/passkeys/registration/options')) return upstream({ challenge_id:'33333333-3333-4333-8333-333333333333', options:{ challenge:'AQ', user:{ id:'Ag', name:'user@example.com', displayName:'User' }, rp:{ id:'paxincpa.store', name:'Paxinbot' }, pubKeyCredParams:[] } });
    throw new Error(`Unexpected fetch: ${url}`);
  };
  try {
    const res = response(); await handler(request('passkey-register-options', 'POST', {}, csrf), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.challengeId, '33333333-3333-4333-8333-333333333333');
    assert.ok(calls.some(url => url.endsWith('/auth/v1/passkeys/registration/options')));
  } finally { global.fetch = originalFetch; }
});
