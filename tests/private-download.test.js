'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.join(__dirname, '..');
const helperPath = require.resolve('../api/_paxinbot');
const handlerPath = require.resolve('../api/account');

function response() {
  return { statusCode:0, headers:{}, setHeader(name,value){ this.headers[String(name).toLowerCase()]=value; }, end(value){ this.body=String(value || ''); } };
}

const TEST_DOWNLOAD_SECRET='download-signing-secret-used-only-by-tests-123';

function loadHandler(authenticated = true, secret = TEST_DOWNLOAD_SECRET) {
  delete require.cache[handlerPath];
  require.cache[helperPath] = {
    id:helperPath, filename:helperPath, loaded:true,
    exports:{
      requireTrustedHost:()=>true,
      browserSession:async()=>authenticated ? ({ user:{ id:'97d6e6d3-1e1c-4fe8-8bff-144e23635528' }, access:'session' }) : null,
      requestRateLimit:async()=>true,
      downloadSigningSecret:()=>{ if (!secret) throw new Error('missing'); return secret; },
      publicOrigin:()=> 'https://www.paxincpa.store',
      upstream:async()=>({ response:{ ok:true }, payload:{} }),
      json:(res,status,payload)=>{ res.statusCode=status; res.end(JSON.stringify(payload)); },
      readBodyResult:async()=>({ ok:true, body:{} }),
      sameOriginRequest:()=>true,
      safeUpstreamError:()=> 'Erro'
    }
  };
  return require('../api/account');
}

test('release is served only through the R2-bound Worker', () => {
  const worker=fs.readFileSync(path.join(root,'cloudflare/origin-gate-worker.mjs'),'utf8');
  const account=fs.readFileSync(path.join(root,'api/account/index.js'),'utf8');
  assert.match(worker,/env\.PAXINBOT_RELEASES\.get\(RELEASE_OBJECT/);
  assert.match(worker,/PAXINBOT_DOWNLOAD_SIGNING_SECRET/);
  assert.match(worker,/content-disposition','attachment; filename="PaxinbotSetup\.exe"'/);
  assert.doesNotMatch(account,/serviceUpstream|storage\/v1|r2\.dev/);
  assert.equal(fs.existsSync(path.join(root,'supabase/migrations/20260901_private_app_download.sql')),false);
});

test('public visitor receives only a short-lived signed installer URL', async () => {
  const handler=loadHandler(false);
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  const payload=JSON.parse(res.body);
  assert.equal(res.statusCode,200);
  assert.equal(payload.data.expiresIn,120);
  assert.equal(payload.data.fileName,'PaxinbotSetup.exe');
  assert.match(payload.data.sha256, /^[a-f0-9]{64}$/);
  const signed=new URL(payload.data.url);
  assert.equal(signed.origin,'https://www.paxincpa.store');
  assert.equal(signed.pathname,'/releases/PaxinbotSetup.exe');
  assert.match(signed.searchParams.get('nonce'),/^[A-Za-z0-9_-]{24}$/);
  assert.match(signed.searchParams.get('signature'),/^[A-Za-z0-9_-]{43}$/);
  const expires=Number(signed.searchParams.get('expires'));
  assert.ok(expires-Math.floor(Date.now()/1000)>0 && expires-Math.floor(Date.now()/1000)<=120);
  const canonical=`GET\n${signed.pathname}\n${expires}\n${signed.searchParams.get('nonce')}`;
  const expected=crypto.createHmac('sha256',TEST_DOWNLOAD_SECRET).update(canonical).digest('base64url');
  assert.equal(signed.searchParams.get('signature'),expected);
  assert.equal(res.headers['cache-control'],'private, no-store, max-age=0');
});

test('public download does not require a browser session', async () => {
  const handler=loadHandler(false);
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  assert.equal(res.statusCode,200);
  assert.equal(JSON.parse(res.body).data.fileName,'PaxinbotSetup.exe');
});

test('public download button redirects to the short-lived Worker URL', async () => {
  const handler=loadHandler(false);
  const res=response();
  await handler({ method:'GET', query:{ action:'download', redirect:'1' }, headers:{}, socket:{} }, res);
  assert.equal(res.statusCode,302);
  const location=new URL(res.headers.location);
  assert.equal(location.pathname,'/releases/PaxinbotSetup.exe');
  assert.match(location.searchParams.get('signature'),/^[A-Za-z0-9_-]{43}$/);
  assert.equal(res.headers['cache-control'],'private, no-store, max-age=0');
});

test('download fails closed when its dedicated secret is absent', async () => {
  const handler=loadHandler(false,'');
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  assert.equal(res.statusCode,503);
  assert.doesNotMatch(res.body,/secret|token|signature/i);
});

test('client download remains short-lived and does not expose a permanent asset URL', () => {
  const page=fs.readFileSync(path.join(root,'cliente.html'),'utf8');
  const client=fs.readFileSync(path.join(root,'auth-client.js'),'utf8');
  assert.match(page,/id="account-download-installer"/);
  assert.match(client,/PaxinbotAuth\.request\('\/api\/account\?action=download'\)/);
  assert.doesNotMatch(page,/storage\/v1\/object\/(?:public|sign)/);
  assert.equal(fs.existsSync(path.join(root,'PaxinbotSetup.exe')),false);
});

test('public download actions point directly to the short-lived download endpoint', () => {
  const publicFiles=['index.html','produto.html','download.html','site-shell.js'].map(file=>fs.readFileSync(path.join(root,file),'utf8')).join('\n');
  assert.match(publicFiles,/\/api\/account\?action=download&amp;redirect=1/);
  assert.doesNotMatch(publicFiles,/\/conta\/downloads\?mode=signup/);
});

test('hardened update discovery fails closed without an offline-signed manifest', async t => {
  const previous = process.env.PAXINBOT_UPDATE_MANIFEST;
  delete process.env.PAXINBOT_UPDATE_MANIFEST;
  t.after(() => { if (previous === undefined) delete process.env.PAXINBOT_UPDATE_MANIFEST; else process.env.PAXINBOT_UPDATE_MANIFEST = previous; });
  const handler = loadHandler(false);
  const res = response();
  await handler({ method: 'GET', query: { action: 'download', protocol: 'signed-v1' }, headers: {}, socket: {} }, res);
  assert.equal(res.statusCode, 503);
  assert.doesNotMatch(res.body, /secret|signature|keyId/);
});

test('hardened discovery uses signed fields and rejects tampering; legacy discovery remains compatible', async t => {
  const modulePath = require.resolve('../server/update-manifest');
  const keyPath = require.resolve('../server/release-public-key.json');
  const oldModule = require.cache[modulePath], oldKey = require.cache[keyPath];
  const previous = process.env.PAXINBOT_UPDATE_MANIFEST;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const trust = { algorithm: 'Ed25519', keyId: crypto.createHash('sha256').update(der).digest('hex').slice(0, 24), publicKey: der.toString('base64url') };
  require.cache[keyPath] = { id: keyPath, filename: keyPath, loaded: true, exports: trust };
  delete require.cache[modulePath];
  t.after(() => {
    if (oldModule) require.cache[modulePath] = oldModule; else delete require.cache[modulePath];
    if (oldKey) require.cache[keyPath] = oldKey; else delete require.cache[keyPath];
    if (previous === undefined) delete process.env.PAXINBOT_UPDATE_MANIFEST; else process.env.PAXINBOT_UPDATE_MANIFEST = previous;
  });
  const stable = value => value === null || typeof value !== 'object' ? JSON.stringify(value) :
    `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  const document = { schema: 'paxinbot.update/v1', product: 'Paxinbot', platform: 'win32-x64', channel: 'stable', version: '1.0.8', sequence: 32,
    createdAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), integrityDigest: 'a'.repeat(64),
    installer: { url: 'https://paxincpa.store/releases/PaxinbotSetup.exe', size: 1048576, sha256: 'b'.repeat(64) } };
  const sign = value => ({ ...value, signature: { algorithm: 'Ed25519', keyId: trust.keyId, value: crypto.sign(null, Buffer.from(stable(value)), privateKey).toString('base64url') } });
  process.env.PAXINBOT_UPDATE_MANIFEST = JSON.stringify(sign(document));
  const handler = loadHandler(false), res = response();
  const req = { method: 'GET', query: { action: 'download', protocol: 'signed-v1' }, headers: {}, socket: {} };
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  const data = JSON.parse(res.body).data;
  assert.equal(data.version, document.version);
  assert.equal(data.sha256, document.installer.sha256);
  assert.equal(data.sizeBytes, document.installer.size);
  assert.deepEqual(data.manifest, sign(document));
  process.env.PAXINBOT_UPDATE_MANIFEST = JSON.stringify({ ...sign(document), version: '9.0.0' });
  const tampered = response(); await handler(req, tampered); assert.equal(tampered.statusCode, 503);
  process.env.PAXINBOT_UPDATE_MANIFEST = JSON.stringify(sign({ ...document, expiresAt: new Date(Date.now() - 1).toISOString() }));
  const expired = response(); await handler(req, expired); assert.equal(expired.statusCode, 503);
  const legacy = response(); await handler({ ...req, query: { action: 'download' } }, legacy); assert.equal(legacy.statusCode, 200);
});
