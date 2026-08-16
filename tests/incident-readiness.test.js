'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const crypto = require('node:crypto');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('Cloudflare Worker overwrites an attacker supplied origin header', () => {
  const worker = read('cloudflare/origin-gate-worker.mjs');
  assert.match(worker, /headers\.delete\(ORIGIN_HEADER\)/);
  assert.match(worker, /headers\.set\(ORIGIN_HEADER, secret\)/);
  assert.match(worker, /secretBytes < 32 \|\| secretBytes > 128/);
  assert.doesNotMatch(worker, /sb_secret_|APP_USR-|BEGIN PRIVATE KEY/);
});

test('Cloudflare Worker forwards only its own bound origin secret', async () => {
  const moduleUrl = `${pathToFileURL(path.join(root, 'cloudflare/origin-gate-worker.mjs')).href}?test=${Date.now()}`;
  const worker = (await import(moduleUrl)).default;
  const originalFetch = global.fetch;
  try {
    global.fetch = async request => new Response(request.headers.get('x-paxinbot-origin-key'));
    const response = await worker.fetch(new Request('https://www.paxincpa.store/api/catalog', {
      headers:{ 'x-paxinbot-origin-key':'attacker-value' }
    }), { PAXINBOT_ORIGIN_GATE_SECRET:'worker-bound-origin-secret-with-at-least-32-bytes' });
    assert.equal(await response.text(), 'worker-bound-origin-secret-with-at-least-32-bytes');
  } finally { global.fetch = originalFetch; }
});

test('Cloudflare Worker validates a short token and streams only the fixed R2 installer', async () => {
  const moduleUrl = `${pathToFileURL(path.join(root, 'cloudflare/origin-gate-worker.mjs')).href}?download=${Date.now()}`;
  const worker = (await import(moduleUrl)).default;
  const secret='worker-download-signing-secret-with-at-least-32-bytes';
  const expires=Math.floor(Date.now()/1000)+120; const nonce='abcdefghijklmnopqrstuvwx';
  const canonical=`GET\n/releases/PaxinbotSetup.exe\n${expires}\n${nonce}`;
  const signature=crypto.createHmac('sha256',secret).update(canonical).digest('base64url');
  let requested='';
  const bucket={ get:async key=>{ requested=key; return { body:'installer',size:9,httpEtag:'"etag"',writeHttpMetadata(){} }; } };
  const response=await worker.fetch(new Request(`https://www.paxincpa.store/releases/PaxinbotSetup.exe?expires=${expires}&nonce=${nonce}&signature=${signature}`),{ PAXINBOT_DOWNLOAD_SIGNING_SECRET:secret,PAXINBOT_RELEASES:bucket });
  assert.equal(response.status,200); assert.equal(requested,'PaxinbotSetup.exe'); assert.equal(await response.text(),'installer');
  assert.equal(response.headers.get('content-disposition'),'attachment; filename="PaxinbotSetup.exe"');
  assert.equal(response.headers.get('cache-control'),'private, no-store, max-age=0');
});

test('Cloudflare Worker rejects expired or tampered download tokens before R2', async () => {
  const moduleUrl = `${pathToFileURL(path.join(root, 'cloudflare/origin-gate-worker.mjs')).href}?expired=${Date.now()}`;
  const worker = (await import(moduleUrl)).default; let called=false;
  const bucket={ get:async()=>{ called=true; return null; } };
  const response=await worker.fetch(new Request('https://www.paxincpa.store/releases/PaxinbotSetup.exe?expires=1000000000&nonce=abcdefghijklmnopqrstuvwx&signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),{ PAXINBOT_DOWNLOAD_SIGNING_SECRET:'worker-download-signing-secret-with-at-least-32-bytes',PAXINBOT_RELEASES:bucket });
  assert.equal(response.status,403); assert.equal(called,false);
});

test('origin gate remains opt-in and never blocks a Vercel preview', () => {
  const helper = read('api/_paxinbot.js');
  assert.match(helper, /if \(process\.env\.NODE_ENV !== 'production' \|\| process\.env\.VERCEL_ENV === 'preview'\) return true/);
  assert.match(helper, /x-paxinbot-origin-key/);
  assert.match(helper, /crypto\.timingSafeEqual/);
  assert.match(helper, /edge\.origin_rejected/);
});

test('incident documentation contains containment, recovery, rotation and postmortem procedures', () => {
  const runbook = read('docs/security/incident-response-runbook.md');
  for (const heading of ['Classificação', 'Primeiros 15 minutos', 'Contenção', 'Rotação de segredos', 'Recuperação', 'Comunicação', 'Pós-incidente']) {
    assert.match(runbook, new RegExp(`## ${heading}`));
  }
  assert.match(runbook, /nunca.*logs.*segredos/is);
  assert.match(runbook, /rollback/i);
});

test('public security policy does not expose a private contact or credential', () => {
  const policy = read('SECURITY.md');
  assert.match(policy, /divulgação responsável/i);
  assert.match(policy, /Área do Cliente/);
  assert.doesNotMatch(policy, /sb_secret_|APP_USR-|service_role|BEGIN PRIVATE KEY/);
});
