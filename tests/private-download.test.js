'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const helperPath = require.resolve('../api/_paxinbot');
const handlerPath = require.resolve('../api/account');

function response() {
  return { statusCode:0, headers:{}, setHeader(name,value){ this.headers[String(name).toLowerCase()]=value; }, end(value){ this.body=String(value || ''); } };
}

function loadHandler(signedURL, authenticated = true) {
  delete require.cache[handlerPath];
  require.cache[helperPath] = {
    id:helperPath, filename:helperPath, loaded:true,
    exports:{
      requireTrustedHost:()=>true,
      browserSession:async()=>authenticated ? ({ user:{ id:'97d6e6d3-1e1c-4fe8-8bff-144e23635528' }, access:'session' }) : null,
      requestRateLimit:async()=>true,
      serviceConfig:()=>({ url:'https://project.supabase.co', key:'sb_secret_test' }),
      serviceUpstream:async()=>({ response:{ ok:true }, payload:{ signedURL } }),
      upstream:async()=>({ response:{ ok:true }, payload:{} }),
      json:(res,status,payload)=>{ res.statusCode=status; res.end(JSON.stringify(payload)); },
      readBodyResult:async()=>({ ok:true, body:{} }),
      sameOriginRequest:()=>true,
      safeUpstreamError:()=> 'Erro'
    }
  };
  return require('../api/account');
}

test('private release bucket remains non-public and has a bounded executable size', () => {
  const sql=fs.readFileSync(path.join(root,'supabase/migrations/20260901_private_app_download.sql'),'utf8');
  assert.match(sql, /'paxinbot-releases'[\s\S]*false[\s\S]*157286400/i);
  assert.doesNotMatch(sql, /create\s+policy/i);
});

test('authenticated account receives only a short-lived signed installer URL', async () => {
  const handler=loadHandler('/object/sign/paxinbot-releases/windows/PaxinbotSetup.exe?token=signed');
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  const payload=JSON.parse(res.body);
  assert.equal(res.statusCode,200);
  assert.equal(payload.data.expiresIn,120);
  assert.equal(payload.data.fileName,'PaxinbotSetup.exe');
  assert.equal(payload.data.sha256,'3139286a02c9c9746881ccacf38f922f1050e15e10a1d1d649f76f206b055387');
  assert.match(payload.data.url,/^https:\/\/project\.supabase\.co\/storage\/v1\/object\/sign\/paxinbot-releases\/windows\/PaxinbotSetup\.exe\?/);
  assert.equal(res.headers['cache-control'],'private, no-store, max-age=0');
});

test('download is unavailable without a browser session', async () => {
  const handler=loadHandler('/object/sign/paxinbot-releases/windows/PaxinbotSetup.exe?token=signed',false);
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  assert.equal(res.statusCode,401);
  assert.doesNotMatch(res.body,/signed|supabase|sha256/i);
});

test('a signed URL from another origin is rejected', async () => {
  const handler=loadHandler('https://attacker.example/PaxinbotSetup.exe');
  const res=response();
  await handler({ method:'GET', query:{ action:'download' }, headers:{}, socket:{} }, res);
  assert.equal(res.statusCode,503);
  assert.doesNotMatch(res.body,/attacker\.example|token/i);
});

test('client download is account-bound and does not expose a permanent asset URL', () => {
  const page=fs.readFileSync(path.join(root,'cliente.html'),'utf8');
  const client=fs.readFileSync(path.join(root,'auth-client.js'),'utf8');
  assert.match(page,/id="account-download-installer"/);
  assert.match(client,/PaxinbotAuth\.request\('\/api\/account\?action=download'\)/);
  assert.doesNotMatch(page,/storage\/v1\/object\/(?:public|sign)/);
  assert.equal(fs.existsSync(path.join(root,'PaxinbotSetup.exe')),false);
});

test('public download actions open signup and preserve the protected downloads destination', () => {
  const client=fs.readFileSync(path.join(root,'auth-client.js'),'utf8');
  const callback=fs.readFileSync(path.join(root,'auth-callback.js'),'utf8');
  const publicFiles=['index.html','produto.html','download.html','site-shell.js'].map(file=>fs.readFileSync(path.join(root,file),'utf8')).join('\n');
  assert.match(publicFiles,/\/conta\/downloads\?mode=signup/);
  assert.match(client,/setAuthMode\(requestedAuthMode\(\)\)/);
  assert.match(client,/paxinbot_auth_return',accountRoutes\.downloads/);
  assert.match(callback,/parsed\.pathname === '\/conta\/downloads'/);
});
