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

const handler = require('../api/account/index.js');
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

function request() {
  return {
    method:'GET', query:{ action:'bootstrap' }, url:'/api/account?action=bootstrap',
    headers:{
      host:'www.paxincpa.store', origin:'https://www.paxincpa.store',
      'x-forwarded-proto':'https', cookie:'paxinbot_access=access-token'
    }
  };
}

function upstream(payload, status = 200) {
  return { ok:status >= 200 && status < 300, status, async json() { return payload; } };
}

test('portal bootstrap preserves authentication and abuse protection while batching the dashboard', async () => {
  const originalFetch = global.fetch;
  const calls = [];
  const rpcPayloads = {
    paxinbot_get_my_access:{ active:true, kind:'lifetime' },
    paxinbot_get_my_account:{ profile:{ displayName:'Cliente' } },
    paxinbot_list_my_devices:[],
    paxinbot_list_my_orders:[],
    paxinbot_list_active_products:[],
    paxinbot_get_my_preferences:{ productUpdates:false, supportUpdates:true },
    paxinbot_list_my_activity:[],
    paxinbot_list_my_support_tickets:[],
    paxinbot_list_my_usage_grants:[],
    paxinbot_list_my_promotions:[]
  };
  global.fetch = async (url, options = {}) => {
    const target = String(url); calls.push({ target, options });
    if (target.endsWith('/auth/v1/user')) return upstream({
      id:'11111111-1111-4111-8111-111111111111', email:'user@example.com',
      identities:[{ provider:'email' }]
    });
    if (target.includes('/rest/v1/rpc/paxinbot_service_rate_limit_v2')) return upstream({ allowed:true, remaining:299, resetAfter:600 });
    if (target.endsWith('/auth/v1/passkeys')) return upstream([{ id:'22222222-2222-4222-8222-222222222222', friendly_name:'Windows Hello' }]);
    const rpc = target.match(/\/rest\/v1\/rpc\/([^?]+)/)?.[1];
    if (rpc && Object.hasOwn(rpcPayloads, rpc)) return upstream(rpcPayloads[rpc]);
    throw new Error(`Unexpected fetch: ${target}`);
  };
  try {
    const res = response();
    await handler(request(), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.current.user.email, 'user@example.com');
    assert.equal(res.body.current.entitlement.kind, 'lifetime');
    assert.equal(res.body.data.passkeys[0].friendlyName, 'Windows Hello');
    assert.match(res.headers['server-timing'], /^portal;dur=\d+$/);
    assert.equal(JSON.stringify(res.body).includes('access-token'), false);
    assert.equal(calls.filter(call => call.target.endsWith('/auth/v1/user')).length, 1);
    assert.equal(calls.filter(call => call.target.includes('paxinbot_service_rate_limit_v2')).length, 1);
    assert.equal(calls.filter(call => call.target.includes('/rest/v1/rpc/paxinbot_get_my_account')).length, 1);
    assert.ok(calls.filter(call => call.target.includes('/rest/v1/rpc/')).length <= 11);
  } finally { global.fetch = originalFetch; }
});

test('client portal uses one bootstrap request instead of one request per panel', () => {
  const source = read('auth-client.js');
  const section = source.match(/async function loadPortalData\(\) \{([\s\S]*?)\r?\n\}\r?\n\r?\nasync function loginWithPasskey/)?.[1] || '';
  assert.match(section, /\/api\/account\?action=bootstrap/);
  assert.doesNotMatch(section, /Promise\.all|action=devices|action=orders|action=products|\/api\/auth\/passkeys/);
  assert.match(read('api/account/index.js'), /Server-Timing/);
});

test('frequent portal lookups have matching database indexes and public catalog reuse', () => {
  const migration = read('supabase/migrations/20260901_portal_performance.sql');
  assert.match(migration, /desktop_sessions\s*\(user_id,\s*last_seen_at desc\)/i);
  assert.match(migration, /desktop_sessions\s*\(user_id,\s*expires_at desc\)[\s\S]*where revoked_at is null/i);
  assert.match(migration, /audit_events\s*\(user_id,\s*created_at desc\)/i);
  assert.match(read('script.js'), /paxinbot_catalog_cache_v1/);
  assert.match(read('auth-client.js'), /paxinbot_catalog_cache_v1/);
  assert.match(read('scripts/release-audit.js'), /migração posterior ao fechamento de privilégios amplia a superfície/);
});
