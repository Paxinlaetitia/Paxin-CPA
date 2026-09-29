'use strict';

// Local-only cross-language fixture. It runs the real API handler against the
// real PostgreSQL migration in PGlite and writes secrets only to the requested
// fixture directory. It is excluded from the public build by build-public.cjs.
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const { PGlite }=require('@electric-sql/pglite');
const licensing=require('../server/cpa-licensing');

function argument(name){const index=process.argv.indexOf(name);return index>=0?process.argv[index+1]:'';}
const configDir=path.resolve(argument('--config-dir')||'');
const releaseKeyPath=path.resolve(argument('--release-key')||'');
if(!configDir||!releaseKeyPath||!fs.existsSync(configDir)||!fs.existsSync(releaseKeyPath)){
  process.stderr.write('Usage: node tests/cpa-fixture-server.cjs --config-dir <fixture-dir> --release-key <server-release-key.json>\n');process.exit(2);
}

function jsonFile(file){return JSON.parse(fs.readFileSync(file,'utf8'));}
function releaseSecret(file,releaseId){
  const raw=jsonFile(file);const value=String(raw[releaseId]||raw.releaseKey||raw.release_key||raw.key||'');
  if(!/^[A-Za-z0-9_-]{43}$/.test(value))throw new Error('Test release key must be a base64url 32-byte value.');
  return value;
}
async function body(req){const chunks=[];for await(const chunk of req)chunks.push(chunk);return JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}');}
function reply(res,status,value,headers={}){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers});res.end(JSON.stringify(value));}

(async()=>{
  const config=jsonFile(path.join(configDir,'test-config.json'));
  const signing=jsonFile(path.join(configDir,'test-signing.json'));
  const releaseId=String(config.release_id||'');
  const releaseKey=releaseSecret(releaseKeyPath,releaseId);
  const pepper=crypto.randomBytes(48).toString('base64url');
  process.env.CPA_LICENSE_HMAC_PEPPERS=JSON.stringify({test:pepper});
  process.env.CPA_LICENSE_HMAC_CURRENT_VERSION='test';
  process.env.CPA_LICENSE_SIGNING_KEYS=JSON.stringify({[signing.kid]:signing.privateKey});
  process.env.CPA_LICENSE_SIGNING_CURRENT_KID=signing.kid;
  process.env.CPA_RELEASE_KEYS=JSON.stringify({[releaseId]:releaseKey});

  const db=new PGlite();
  await db.exec(`
    create role anon; create role authenticated; create role service_role;
    create schema auth; create schema extensions;
    create function extensions.gen_random_uuid() returns uuid language sql volatile as $$select gen_random_uuid()$$;
    create table auth.users(id uuid primary key default extensions.gen_random_uuid(),email text unique);
    create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
    create function auth.role() returns text language sql stable as $$select nullif(current_setting('request.jwt.claim.role',true),'')$$;
    create function public.paxinbot_is_owner() returns boolean language sql stable as $$select current_setting('request.jwt.claim.owner',true)='true'$$;
  `);
  await db.exec(fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260929_cpa_licenses.sql'),'utf8'));
  const owner=crypto.randomUUID();await db.query(`insert into auth.users(id,email) values($1,'fixture-owner@example.test')`,[owner]);
  await db.query(`select set_config('request.jwt.claim.sub',$1,false)`,[owner]);await db.query(`select set_config('request.jwt.claim.owner','true',false)`);
  const seeded=[];
  for(const definition of [{name:'lifetime',unit:'lifetime',value:null},{name:'timed',unit:'hours',value:2}]){
    const key=licensing.generateLicense();
    const result=await db.query(`select public.cpa_owner_create_license($1,$2,$3,$4,$5,$6,null,'first',null) data`,[key.keyId,key.keyPrefix,key.keyHash,key.pepperVersion,definition.unit,definition.value]);
    seeded.push({name:definition.name,licenseKey:key.licenseKey,licenseId:result.rows[0].data.id,keyId:key.keyId});
  }
  await db.query(`select set_config('request.jwt.claim.role','service_role',false)`);

  const helperPath=require.resolve('../api/_paxinbot');
  async function serviceUpstream(url,options={}){
    const name=String(url).split('/').pop();const entries=Object.entries(options.body||{});
    try{
      const args=entries.map(([key],index)=>`${key}=>$${index+1}`).join(',');
      const values=entries.map(([,value])=>value&&typeof value==='object'?JSON.stringify(value):value);
      const result=await db.query(`select public.${name}(${args}) data`,values);
      return{response:{ok:true,status:200},payload:result.rows[0]?.data};
    }catch(error){return{response:{ok:false,status:400},payload:{message:String(error.message).split('\n')[0]}};}
  }
  require.cache[helperPath]={id:helperPath,filename:helperPath,loaded:true,exports:{
    json:reply,requireTrustedHost:()=>true,clientAddress:req=>req.socket.remoteAddress||'loopback',
    sha256:value=>crypto.createHash('sha256').update(String(value)).digest('hex'),
    isUuid:value=>/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value||'')),
    serviceRateLimit:async()=>true,requestRateLimit:async()=>true,serviceUpstream,
    readBodyResult:async(req,res)=>{try{return{ok:true,body:await body(req)}}catch{return reply(res,400,{ok:false,code:'invalid_request'}),{ok:false};}}
  }};
  const handler=require('../api/licenses');
  const fixtureAdminSecret=crypto.randomBytes(32).toString('base64url');
  const receipt={apiUrl:config.api_url,releaseId,signingKid:signing.kid,licenseKey:seeded[0].licenseKey,fixtureAdminSecret,licenses:seeded,createdAt:new Date().toISOString()};
  const receiptPath=path.join(configDir,'server-receipt.json');fs.writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{encoding:'utf8',mode:0o600});
  const server=http.createServer(async(req,res)=>{
    const url=new URL(req.url,'http://127.0.0.1:18797');
    if(url.pathname==='/__fixture/admin'&&req.method==='POST'){
      if(req.headers['x-cpa-fixture-secret']!==fixtureAdminSecret)return reply(res,404,{ok:false});
      try{
        const command=await body(req);const operation=String(command.operation||'');const licenseId=String(command.licenseId||seeded[0].licenseId);
        if(!['activate','deactivate','suspend','revoke','ban','unban','reset_device','terminate_sessions'].includes(operation))return reply(res,400,{ok:false,code:'invalid_request'});
        await db.query(`select set_config('request.jwt.claim.role','authenticated',false)`);await db.query(`select set_config('request.jwt.claim.owner','true',false)`);
        const result=await db.query(`select public.cpa_owner_update_license($1,$2) data`,[licenseId,operation]);
        await db.query(`select set_config('request.jwt.claim.role','service_role',false)`);await db.query(`select set_config('request.jwt.claim.owner','',false)`);
        return reply(res,200,{ok:true,data:result.rows[0].data});
      }catch{return reply(res,400,{ok:false,code:'invalid_request'});}
    }
    if(url.pathname!=='/api/licenses')return reply(res,404,{ok:false,code:'invalid_request'});req.query=Object.fromEntries(url.searchParams);handler(req,res);
  });
  server.listen(18797,'127.0.0.1',()=>process.stdout.write(`CPA fixture ready on loopback; receipt=${receiptPath}\n`));
  async function stop(){server.close(async()=>{await db.close();process.exit(0);});}process.on('SIGINT',stop);process.on('SIGTERM',stop);
})().catch(error=>{process.stderr.write(`Fixture failed: ${error.message}\n`);process.exit(1);});
