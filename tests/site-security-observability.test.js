'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_unique_backend_credential';
process.env.PAXINBOT_SESSION_SECRET = 'unique-session-secret-with-at-least-32-bytes';

const helpers = require('../api/_paxinbot');
const root = path.join(__dirname, '..');

function response() {
  const headers = new Map();
  return {
    headersSent:false,
    setHeader(name,value) { headers.set(String(name).toLowerCase(), value); },
    getHeader(name) { return headers.get(String(name).toLowerCase()); }
  };
}

test('request correlation id is stable, random and exposed in the response', () => {
  const req = { url:'/api/auth/login?token=must-not-appear', headers:{} };
  const res = response();
  const first = helpers.requestId(req, res);
  const second = helpers.requestId(req, res);
  assert.match(first, /^[0-9a-f-]{36}$/i);
  assert.equal(second, first);
  assert.equal(res.getHeader('x-paxinbot-request-id'), first);
  assert.equal(helpers.requestRoute(req), '/api/auth/login');
});

test('site security event hashes subjects and accepts only enumerated details', () => {
  const raw = 'cliente@example.com\0' + '198.51.100.10';
  const event = helpers.siteSecurityEvent({
    url:'/api/auth/login?email=cliente@example.com',
    headers:{ 'cf-ray':'8ab12cd34ef56789-GRU' }
  }, {
    eventType:'auth.login_rejected', severity:35, subject:raw,
    details:{ reasonCode:'invalid_credentials', outcome:'rejected', token:'secret', email:'cliente@example.com' }
  });
  assert.equal(event.route, '/api/auth/login');
  assert.match(event.subjectHash, /^[a-f0-9]{64}$/);
  assert.match(event.edgeTraceHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(event.details, { reasonCode:'invalid_credentials', outcome:'rejected' });
  assert.doesNotMatch(JSON.stringify(event), /cliente@example|198\.51\.100\.10|secret/);
});

test('unknown security events fail closed before persistence', () => {
  assert.throws(() => helpers.siteSecurityEvent({ url:'/api/test', headers:{} }, {
    eventType:'arbitrary.event', severity:10
  }), /site_security_event_invalid/);
});

test('migration keeps event storage private and validates its RPC payload', () => {
  const sql = fs.readFileSync(path.join(root, 'supabase/migrations/20260830_site_security_observability.sql'), 'utf8');
  assert.match(sql, /enable row level security/i);
  assert.match(sql, /revoke all on table public\.site_security_events from public, anon, authenticated/i);
  assert.match(sql, /auth\.role\(\) <> 'service_role'/i);
  assert.match(sql, /jsonb_object_keys\(v_details\)/i);
  assert.match(sql, /interval '90 days'/i);
  assert.doesNotMatch(sql, /\b(ip_address|email_address|user_agent|access_token|refresh_token|password)\b/i);
});

test('Cloudflare guide respects monitoring limits of the Free plan', () => {
  const guide = fs.readFileSync(path.join(root, 'docs/security/cloudflare-activation-guide.md'), 'utf8');
  assert.match(guide, /HTTP DDoS Attack Alert/);
  assert.match(guide, /Security Events Alert.*Business e Enterprise/s);
  assert.match(guide, /últimas 24 horas/);
  assert.match(guide, /entrega garantida\s+é por e-mail/s);
});
