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
  assert.equal(payload.data.sha256,'62347372c777e5bde78497c18943c8985fbd0f444d925d2c26f71c424d7b8354');
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
