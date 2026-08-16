'use strict';

const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const test=require('node:test');

process.env.NODE_ENV='test';
process.env.SUPABASE_URL='https://example.supabase.co';
process.env.SUPABASE_PUBLISHABLE_KEY='sb_publishable_test';
process.env.SUPABASE_SECRET_KEY='sb_secret_test';
process.env.PAXINBOT_SESSION_SECRET='test-only-session-secret-that-is-not-deployed';

function response() { return { statusCode:0,headers:{},setHeader(name,value){this.headers[name.toLowerCase()]=value;},end(value){this.body=JSON.parse(value);} }; }
function reply(status,payload) { return Promise.resolve({ ok:status>=200&&status<300,status,json:async()=>payload }); }
function request(body) { return { method:'POST',query:{ action:'security-event' },body,headers:{ authorization:`Bearer ${'a'.repeat(64)}`,'content-type':'application/json' },socket:{} }; }
function event(overrides={}) { return { eventId:'5c24bfb9-f29d-4eb0-a3bf-59bd2fdcefd6',type:'runtime_contract_failure',occurredAt:new Date().toISOString(),appVersion:'1.0.0',releaseSequence:8,details:{ reasonCode:'ipc_contract',component:'ipc-guard',operation:'invoke',outcome:'blocked' },...overrides }; }

test('desktop security endpoint accepts only the minimal allowlisted contract',async()=>{
  const calls=[]; global.fetch=async(url,options)=>{ calls.push({ url,options }); if(url.endsWith('/paxinbot_service_rate_limit')) return reply(200,true); if(url.endsWith('/paxinbot_record_security_event')) return reply(200,{ ok:true,action:'reauthenticate' }); return reply(404,{}); };
  delete require.cache[require.resolve('../api/v1/desktop/session')];
  const handler=require('../api/v1/desktop/session'); const res=response(); await handler(request(event()),res);
  assert.equal(res.statusCode,202); assert.equal(res.body.action,'reauthenticate');
  const payload=JSON.parse(calls[1].options.body);
  assert.match(payload.p_token_hash,/^[a-f0-9]{64}$/); assert.equal(payload.p_event_type,'runtime_contract_failure');
  assert.equal(Object.hasOwn(payload,'token'),false); assert.equal(Object.hasOwn(payload.p_details,'url'),false);
});

test('desktop security endpoint rejects arbitrary fields before the database',async()=>{
  let called=false; global.fetch=async()=>{ called=true; return reply(500,{}); };
  delete require.cache[require.resolve('../api/v1/desktop/session')];
  const handler=require('../api/v1/desktop/session'); const res=response();
  await handler(request(event({ details:{ url:'https://private.invalid',text:'typed value' } })),res);
  assert.equal(res.statusCode,400); assert.equal(called,false);
});

test('risk migration uses fixed scores, graduated reauthentication and owner-only permanent bans',()=>{
  const migration=fs.readFileSync(path.join(__dirname,'..','supabase','migrations','20260827_security_risk.sql'),'utf8');
  assert.match(migration,/create table if not exists public\.security_events/i);
  assert.match(migration,/paxinbot_record_security_event/i);
  assert.match(migration,/when 'integrity_failure' then 90/i);
  assert.match(migration,/risk_reauthentication_required/i);
  assert.match(migration,/paxinbot_owner_reset_security_risk/i);
  assert.doesNotMatch(migration,/update public\.device_identities set banned_at/i);
  assert.doesNotMatch(migration,/grant (select|insert|update|delete) on table public\.security_/i);
});

test('owner panel exposes sanitized risk review without raw device identifiers',()=>{
  const page=fs.readFileSync(path.join(__dirname,'..','api','admin','_assets','page.txt'),'utf8');
  const client=fs.readFileSync(path.join(__dirname,'..','api','admin','_assets','client.txt'),'utf8');
  assert.match(page,/data-admin-view="security"/); assert.match(page,/id="admin-risk-list"/);
  assert.match(client,/paxinbot_owner_reset_security_risk|riskReset|data-risk-reset/);
  assert.doesNotMatch(page,/fingerprint_hash|device_key_hash|public_key/i);
});
