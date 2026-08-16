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

const { readBody, readBodyResult, issueCsrfToken, sameOriginRequest } = require('../api/_paxinbot');

function request(body, headers = {}) {
  return { method:'POST', body, headers:{ host:'www.paxincpa.store', 'x-forwarded-proto':'https', ...headers } };
}
function response() {
  const headers = {};
  return {
    statusCode:0, headers,
    setHeader(name, value) { headers[name.toLowerCase()] = value; },
    getHeader(name) { return headers[name.toLowerCase()]; },
    end(value) { this.body = JSON.parse(value); }
  };
}

test('request parser accepts a bounded JSON object', async () => {
  assert.deepEqual(await readBody(request({ action:'save' }, { 'content-type':'application/json' })), { action:'save' });
});

test('request parser rejects unsupported, malformed and oversized bodies', async () => {
  const unsupported=response();
  assert.equal((await readBodyResult(request('action=save', { 'content-type':'text/plain' }), unsupported)).ok, false);
  assert.equal(unsupported.statusCode, 415);
  assert.equal(unsupported.body.code, 'unsupported_media_type');

  const malformed=response();
  assert.equal((await readBodyResult(request('{broken', { 'content-type':'application/json' }), malformed)).ok, false);
  assert.equal(malformed.statusCode, 400);
  assert.equal(malformed.body.code, 'invalid_json');

  const oversized=response();
  assert.equal((await readBodyResult(request({ value:'x'.repeat(33 * 1024) }, { 'content-type':'application/json' }), oversized)).ok, false);
  assert.equal(oversized.statusCode, 413);
  assert.equal(oversized.body.code, 'payload_too_large');
});

test('same-origin browser writes require a matching double-submit token', () => {
  const token='a'.repeat(43);
  const base={ origin:'https://www.paxincpa.store', 'content-type':'application/json' };
  assert.equal(sameOriginRequest(request({}, base)), false);
  assert.equal(sameOriginRequest(request({}, { ...base, cookie:`paxinbot_csrf=${token}`, 'x-paxinbot-csrf':'b'.repeat(43) })), false);
  assert.equal(sameOriginRequest(request({}, { ...base, cookie:`paxinbot_csrf=${token}`, 'x-paxinbot-csrf':token })), true);
  assert.equal(sameOriginRequest(request({}, { ...base, origin:'https://attacker.invalid', cookie:`paxinbot_csrf=${token}`, 'x-paxinbot-csrf':token })), false);
  assert.equal(sameOriginRequest(request({}, { 'content-type':'application/json', cookie:`paxinbot_csrf=${token}`, 'x-paxinbot-csrf':token })), false);
});

test('CSRF endpoint helper issues a secure, same-site cookie', () => {
  const req=request(null, {}); const res=response(); const token=issueCsrfToken(req,res);
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(String(res.headers['set-cookie']), /paxinbot_csrf=/);
  assert.match(String(res.headers['set-cookie']), /SameSite=Strict/);
  assert.match(String(res.headers['set-cookie']), /; Secure/);
});

test('browser clients attach CSRF and execute only the vendored Supabase SDK', () => {
  const root=path.join(__dirname,'..');
  const client=fs.readFileSync(path.join(root,'auth-client.js'),'utf8');
  const callback=fs.readFileSync(path.join(root,'auth-callback.js'),'utf8');
  const admin=fs.readFileSync(path.join(root,'api','admin','_assets','client.txt'),'utf8');
  const html=fs.readFileSync(path.join(root,'cliente.html'),'utf8');
  assert.match(client,/\/api\/auth\/csrf/);
  assert.match(client,/x-paxinbot-csrf/);
  assert.match(callback,/x-paxinbot-csrf/);
  assert.match(admin,/x-paxinbot-csrf/);
  assert.doesNotMatch(`${client}\n${callback}\n${html}`,/cdn\.jsdelivr|unpkg/i);
  assert.match(html,/assets\/vendor\/supabase-2\.105\.0\.js/);
  const vendor=fs.readFileSync(path.join(root,'assets','vendor','supabase-2.105.0.js'));
  assert.equal(crypto.createHash('sha256').update(vendor).digest('hex'),'24e8c00dc25da420ee741068b60bcdb5f62cb3598d8834058acf37ec6ee1a724');
});

test('Vercel enforces browser hardening and isolates private routes from cache', () => {
  const config=JSON.parse(fs.readFileSync(path.join(__dirname,'..','vercel.json'),'utf8'));
  const global=config.headers.find(entry=>entry.source==='/(.*)');
  const headers=Object.fromEntries(global.headers.map(item=>[item.key.toLowerCase(),item.value]));
  assert.equal(headers['x-content-type-options'],'nosniff');
  assert.equal(headers['x-frame-options'],'DENY');
  assert.match(headers['permissions-policy'],/camera=\(\)/);
  assert.match(headers['content-security-policy'],/object-src 'none'/);
  assert.match(headers['content-security-policy'],/upgrade-insecure-requests/);
  assert.doesNotMatch(headers['content-security-policy'],/script-src[^;]*unsafe-inline/);
  assert.equal(headers['content-security-policy-report-only'],undefined);
  assert.equal(headers['cross-origin-opener-policy'],'same-origin-allow-popups');
  assert.equal(headers['cross-origin-resource-policy'],'same-origin');
  for (const source of ['/api/:path*','/conta/:path*','/gestao/:path*']) {
    const rule=config.headers.find(entry=>entry.source===source);
    assert.match(rule.headers.find(item=>item.key.toLowerCase()==='cache-control').value,/no-store/);
  }
});

test('legal pages are static, hardened and linked from account-sensitive flows', () => {
  const root=path.join(__dirname,'..');
  const pages=['privacidade.html','termos.html','reembolso.html'];
  for (const name of pages) {
    const html=fs.readFileSync(path.join(root,name),'utf8');
    assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)/i);
    assert.doesNotMatch(html,/<form\b/i);
    assert.doesNotMatch(html,/\b(?:SUPABASE_SECRET_KEY|MERCADOPAGO_ACCESS_TOKEN|PAXINBOT_SESSION_SECRET)\b/);
    assert.match(html,/src="\/site-shell\.js"/);
    assert.match(html,/Vigência: 16 de agosto de 2026/);
  }
  const shell=fs.readFileSync(path.join(root,'site-shell.js'),'utf8');
  const client=fs.readFileSync(path.join(root,'cliente.html'),'utf8');
  for (const route of ['/privacidade','/termos','/reembolso']) assert.match(shell,new RegExp(`href="${route}"`));
  assert.match(client,/href="\/termos"[^>]*rel="noopener"/);
  assert.match(client,/href="\/privacidade"[^>]*rel="noopener"/);
  assert.match(client,/href="\/reembolso"[^>]*rel="noopener"/);
});
