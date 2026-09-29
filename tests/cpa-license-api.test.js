'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');

process.env.NODE_ENV='test';

const helperPath=require.resolve('../api/_paxinbot');
const publicPath=require.resolve('../api/licenses');
const adminModulePath=require.resolve('../server/cpa-licensing-admin');

function response(){return{headers:{},statusCode:0,setHeader(n,v){this.headers[n.toLowerCase()]=v;},end(v){this.body=JSON.parse(v);}};}
function request(method,query,body={}){return{method,query,body,headers:{},socket:{remoteAddress:'127.0.0.1'}};}
function load(file,overrides={}){
  delete require.cache[file];
  delete require.cache[adminModulePath];
  require.cache[helperPath]={id:helperPath,filename:helperPath,loaded:true,exports:{
    json:(res,status,payload)=>{res.statusCode=status;res.end(JSON.stringify(payload));},requireTrustedHost:()=>true,
    readBodyResult:async req=>({ok:true,body:req.body}),serviceUpstream:async()=>({response:{ok:true},payload:true}),
    requestRateLimit:async()=>true,serviceRateLimit:async()=>true,clientAddress:()=> '127.0.0.1',sha256:v=>crypto.createHash('sha256').update(String(v)).digest('hex'),isUuid:v=>/^[0-9a-f-]{36}$/i.test(v),
    browserSession:async()=>({user:{id:crypto.randomUUID()},access:'browser'}),upstream:async()=>({response:{ok:true},payload:true}),sameOriginRequest:()=>true,...overrides
  }};
  return require(file);
}

test('challenge validates action/hash and never returns server material',async()=>{
  const calls=[]; const handler=load(publicPath,{serviceUpstream:async(url,options)=>{calls.push({url,body:options.body});return{response:{ok:true},payload:{}};}});
  const res=response();await handler(request('POST',{action:'challenge'},{action:'activate',payloadHash:'a'.repeat(64)}),res);
  assert.equal(res.statusCode,201);assert.match(res.body.challengeId,/^[0-9a-f-]{36}$/);assert.match(res.body.nonce,/^[A-Za-z0-9_-]{43}$/);assert.equal(calls[0].url.endsWith('/cpa_license_create_challenge'),true);
  assert.deepEqual(Object.keys(res.body).sort(),['challengeId','expiresIn','nonce','ok']);
});

test('challenge limiter returns the canonical protocol code',async()=>{
  const handler=load(publicPath,{serviceRateLimit:async()=>false});const res=response();
  await handler(request('POST',{action:'challenge'},{action:'activate',payloadHash:'a'.repeat(64)}),res);
  assert.equal(res.statusCode,429);assert.deepEqual(res.body,{ok:false,code:'rate_limited'});
});

test('public endpoint consumes a challenge before it validates proof',async()=>{
  const calls=[];const handler=load(publicPath,{serviceUpstream:async(url)=>{calls.push(url);if(url.endsWith('/cpa_license_consume_challenge'))return{response:{ok:true},payload:{status:'ready',action:'refresh',nonce:'n'.repeat(43),payloadHash:'a'.repeat(64)}};return{response:{ok:true},payload:true};}});
  const res=response();await handler(request('POST',{action:'refresh'},{challengeId:crypto.randomUUID(),payload:'e30',signature:'x'}),res);
  assert.equal(calls[0].endsWith('/cpa_license_consume_challenge'),true);assert.equal(res.body.code,'invalid_proof');
});

test('valid signed activation crosses the public handler and returns a verifiable lease',async()=>{
  const serverPair=crypto.generateKeyPairSync('ed25519');const clientPair=crypto.generateKeyPairSync('ed25519');
  process.env.CPA_LICENSE_HMAC_PEPPERS=JSON.stringify({v1:'api-test-pepper-with-more-than-thirty-two-bytes'});process.env.CPA_LICENSE_HMAC_CURRENT_VERSION='v1';
  process.env.CPA_LICENSE_SIGNING_KEYS=JSON.stringify({test:serverPair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64url')});process.env.CPA_LICENSE_SIGNING_CURRENT_KID='test';
  process.env.CPA_RELEASE_KEYS=JSON.stringify({'cash-hunters-1.6.0-test':crypto.randomBytes(32).toString('base64url')});
  const challengeId=crypto.randomUUID(),nonce=crypto.randomBytes(32).toString('base64url'),licenseId=crypto.randomUUID();
  const payloadObject={requestNonce:crypto.randomBytes(32).toString('base64url'),hwid:'a'.repeat(64),publicKey:clientPair.publicKey.export({format:'der',type:'spki'}).toString('base64url'),releaseId:'cash-hunters-1.6.0-test',licenseKey:crypto.randomBytes(32).toString('base64url')};
  const payload=Buffer.from(JSON.stringify(payloadObject)).toString('base64url'),payloadHash=crypto.createHash('sha256').update(Buffer.from(payload,'base64url')).digest('hex');
  const signature=crypto.sign(null,Buffer.from(`PAXINCPA/1\n${challengeId}\n${nonce}\nactivate\n${payloadHash}`),clientPair.privateKey).toString('base64url');
  const calls=[];const handler=load(publicPath,{serviceUpstream:async(url,options)=>{calls.push({url,body:options.body});if(url.endsWith('/cpa_license_consume_challenge'))return{response:{ok:true,status:200},payload:{status:'ready',action:'activate',nonce,payloadHash}};if(url.endsWith('/cpa_license_register_proof'))return{response:{ok:true,status:200},payload:true};if(url.endsWith('/cpa_license_activate'))return{response:{ok:true,status:200},payload:{licenseId,serverTime:new Date().toISOString(),expiresIn:120,licenseExpiresAt:null}};return{response:{ok:true,status:200},payload:true};}});
  const res=response();await handler(request('POST',{action:'activate'},{challengeId,payload,signature}),res);
  assert.equal(res.statusCode,200);assert.equal(res.body.kid,'test');assert.deepEqual(calls.filter(call=>call.url.includes('/cpa_license_')).map(call=>call.url.split('/').pop()),['cpa_license_consume_challenge','cpa_license_register_proof','cpa_license_activate']);
  assert.equal(crypto.verify(null,Buffer.from(`PAXINCPA/1.response\n${res.body.payload}`),serverPair.publicKey,Buffer.from(res.body.signature,'base64url')),true);
  const lease=JSON.parse(Buffer.from(res.body.payload,'base64url'));assert.equal(lease.licenseId,licenseId);assert.equal(lease.requestNonce,payloadObject.requestNonce);assert.match(lease.sessionToken,/^[A-Za-z0-9_-]{43}$/);assert.equal(lease.releaseKey,undefined);
});

test('admin endpoint requires existing owner session, CSRF and valid duration',async()=>{
  let upstreamCalls=0;const handler=load(publicPath,{upstream:async()=>{upstreamCalls++;return{response:{ok:true},payload:true};},sameOriginRequest:()=>false});
  const denied=response();await handler(request('POST',{channel:'admin'}, {action:'create',duration:{unit:'days',value:1},activationPolicy:'first'}),denied);
  assert.equal(denied.statusCode,403);assert.equal(upstreamCalls,1);
  const valid=load(publicPath);const bad=response();await valid(request('POST',{channel:'admin'}, {action:'create',duration:{unit:'days',value:0},activationPolicy:'first'}),bad);assert.equal(bad.statusCode,400);
});

test('admin list is capped at 200 and supports pending state',async()=>{
  const calls=[];const handler=load(publicPath,{upstream:async(url,options)=>{calls.push({url,body:options.body});return{response:{ok:true},payload:url.endsWith('/paxinbot_is_owner')?true:[]};}});
  const res=response();await handler(request('GET',{channel:'admin',action:'list',status:'pending',q:'abc'}),res);
  assert.equal(res.statusCode,200);assert.equal(calls[1].body.p_limit,200);assert.equal(calls[1].body.p_status,'pending');
});
