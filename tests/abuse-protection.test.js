'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

process.env.NODE_ENV='test';
process.env.SUPABASE_URL='https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY='sb_publishable_test';
process.env.SUPABASE_SECRET_KEY='sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET='test-only-session-secret-that-is-not-deployed';

const { requestRateLimit }=require('../api/_paxinbot');

function req() { return { headers:{ 'x-forwarded-for':'203.0.113.42',host:'www.paxincpa.store','x-forwarded-proto':'https' },socket:{} }; }
function res() { return { statusCode:0,headers:{},setHeader(name,value){this.headers[name.toLowerCase()]=value;},end(value){this.body=JSON.parse(value);} }; }
function reply(status,payload) { return Promise.resolve({ ok:status>=200&&status<300,status,json:async()=>payload }); }

test('distributed limiter hashes the subject and returns standard rate headers',async()=>{
  let body;
  global.fetch=async(url,options)=>{ assert.match(url,/paxinbot_service_rate_limit_v2$/); body=JSON.parse(options.body); return reply(200,{ allowed:true,remaining:7,resetAfter:90 }); };
  const response=res();
  assert.equal(await requestRateLimit(req(),response,{ scope:'auth_login_ip',subject:'203.0.113.42',limit:30,windowSeconds:900 }),true);
  assert.match(body.p_subject_hash,/^[a-f0-9]{64}$/);
  assert.notEqual(body.p_subject_hash,'203.0.113.42');
  assert.equal(response.headers['ratelimit-policy'],'30;w=900');
  assert.equal(response.headers.ratelimit,'limit=30, remaining=7, reset=90');
});

test('distributed limiter emits 429, falls back only for a missing v2 migration and otherwise fails closed',async()=>{
  global.fetch=async()=>reply(200,{ allowed:false,remaining:0,resetAfter:45 });
  const blocked=res();
  assert.equal(await requestRateLimit(req(),blocked,{ scope:'checkout_create_user',subject:'user-id',limit:10,windowSeconds:600 }),false);
  assert.equal(blocked.statusCode,429); assert.equal(blocked.body.code,'rate_limited'); assert.equal(blocked.headers['retry-after'],'45');

  let calls=0;
  global.fetch=async()=>++calls===1 ? reply(404,{ code:'PGRST202' }) : reply(200,true);
  const compatible=res();
  assert.equal(await requestRateLimit(req(),compatible,{ scope:'checkout_create_user',subject:'user-id',limit:10,windowSeconds:600 }),true);
  assert.equal(calls,2);
  assert.equal(compatible.headers['ratelimit-policy'],'10;w=600');

  global.fetch=async()=>reply(503,{ code:'UPSTREAM_DOWN' });
  const unavailable=res();
  assert.equal(await requestRateLimit(req(),unavailable,{ scope:'checkout_create_user',subject:'user-id',limit:10,windowSeconds:600 }),false);
  assert.equal(unavailable.statusCode,503); assert.equal(unavailable.body.code,'rate_limit_unavailable');
});

test('migration keeps counters private, atomic and bounded',()=>{
  const sql=fs.readFileSync(path.join(__dirname,'..','supabase','migrations','20260829_api_abuse_limits.sql'),'utf8');
  assert.match(sql,/for update/i);
  assert.match(sql,/security definer/i);
  assert.match(sql,/api_rate_limits_window_started_idx/i);
  assert.match(sql,/window_started_at < now\(\) - interval '2 days'/i);
  assert.match(sql,/p_subject_hash !~ '\^\[a-f0-9\]\{64\}\$'/i);
  assert.match(sql,/revoke all on function .* from public, anon, authenticated/i);
  assert.match(sql,/grant execute on function .* to service_role/i);
  assert.doesNotMatch(sql,/grant .*api_rate_limits.*authenticated/i);
});

test('missing v2 limiter is remembered by warm instances to avoid repeated 404 latency',async()=>{
  let v2Calls=0; let legacyCalls=0;
  global.fetch=async url=>{
    if (String(url).endsWith('paxinbot_service_rate_limit_v2')) { v2Calls++; return reply(404,{ code:'PGRST202' }); }
    if (String(url).endsWith('paxinbot_service_rate_limit')) { legacyCalls++; return reply(200,true); }
    throw new Error(`Unexpected fetch: ${url}`);
  };
  assert.equal(await requestRateLimit(req(),res(),{ scope:'auth_google_ip',subject:'203.0.113.42',limit:30,windowSeconds:600 }),true);
  assert.equal(await requestRateLimit(req(),res(),{ scope:'auth_google_ip',subject:'203.0.113.42',limit:30,windowSeconds:600 }),true);
  assert.ok(v2Calls <= 1);
  assert.equal(legacyCalls,2);
});

test('sensitive web flows use separate scopes and Cloudflare stays staged',()=>{
  const root=path.join(__dirname,'..');
  const source=['api/auth/[action].js','api/account/index.js','api/checkout/index.js','api/admin/index.js'].map(file=>fs.readFileSync(path.join(root,file),'utf8')).join('\n');
  for (const scope of ['auth_login_ip','auth_signup_ip','auth_recover_ip','account_ticket_user','checkout_create_user','admin_write_user']) assert.match(source,new RegExp(scope));
  const cloudflare=fs.readFileSync(path.join(root,'docs','security','cloudflare-package-3.md'),'utf8');
  assert.match(cloudflare,/20/); assert.match(cloudflare,/10 segundos/); assert.match(cloudflare,/não devem ser\s+ativadas/i);
});
