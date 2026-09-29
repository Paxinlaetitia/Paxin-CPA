'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const { PGlite }=require('@electric-sql/pglite');
const licensing=require('../server/cpa-licensing');

const migration=fs.readFileSync(path.join(__dirname,'..','supabase/migrations/20260929_cpa_licenses.sql'),'utf8');

async function database(){
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
  await db.exec(migration);
  return db;
}

test('real PostgreSQL executes migration and enforces activation, refresh and immediate revocation',async()=>{
  const db=await database();
  try{
    const owner=crypto.randomUUID();
    await db.query(`insert into auth.users(id,email) values($1,'owner@example.test')`,[owner]);
    await db.query(`select set_config('request.jwt.claim.sub',$1,false)`,[owner]);
    await db.query(`select set_config('request.jwt.claim.owner','true',false)`);
    const env={CPA_LICENSE_HMAC_PEPPERS:JSON.stringify({v1:'pglite-test-pepper-longer-than-thirty-two-bytes'}),CPA_LICENSE_HMAC_CURRENT_VERSION:'v1'};
    const key=licensing.generateLicense(env);
    const created=await db.query(`select public.cpa_owner_create_license($1,$2,$3,$4,'hours',1,null,'first',null) data`,[key.keyId,key.keyPrefix,key.keyHash,key.pepperVersion]);
    const licenseId=created.rows[0].data.id; assert.equal(created.rows[0].data.status,'pending');
    await db.query(`select set_config('request.jwt.claim.role','service_role',false)`);
    const hwid='a'.repeat(64),publicKey='A'.repeat(64),publicKeyHash='b'.repeat(64),tokenHash='c'.repeat(64);
    const activated=await db.query(`select public.cpa_license_activate($1::jsonb,$2,$3,$4,'cash-hunters-1.6.0-test',$5) data`,[JSON.stringify([{version:'v1',hash:key.keyHash}]),hwid,publicKey,publicKeyHash,tokenHash]);
    assert.equal(activated.rows[0].data.licenseId,licenseId); assert.ok(activated.rows[0].data.expiresIn<=120);
    const refreshed=await db.query(`select public.cpa_license_refresh($1,$2,$3,$4,'cash-hunters-1.6.0-test') data`,[tokenHash,'d'.repeat(64),hwid,publicKeyHash]);
    assert.ok(refreshed.rows[0].data.expiresIn<=120);
    await db.query(`select set_config('request.jwt.claim.role','',false)`);
    await db.query(`select set_config('request.jwt.claim.owner','true',false)`);
    await db.query(`select public.cpa_owner_update_license($1,'suspend')`,[licenseId]);
    await db.query(`select set_config('request.jwt.claim.role','service_role',false)`);
    await assert.rejects(db.query(`select public.cpa_license_refresh($1,$2,$3,$4,'cash-hunters-1.6.0-test')`,['d'.repeat(64),'e'.repeat(64),hwid,publicKeyHash]),/session_expired|suspended/);
  }finally{await db.close();}
});

test('first-use license cannot reactivate after an explicit admin deactivation',async()=>{
  const db=await database();
  try{
    const owner=crypto.randomUUID();await db.query(`insert into auth.users(id,email) values($1,'owner2@example.test')`,[owner]);
    await db.query(`select set_config('request.jwt.claim.sub',$1,false)`,[owner]);
    await db.query(`select set_config('request.jwt.claim.owner','true',false)`);
    const env={CPA_LICENSE_HMAC_PEPPERS:JSON.stringify({v1:'another-pglite-test-pepper-thirty-two-bytes'}),CPA_LICENSE_HMAC_CURRENT_VERSION:'v1'};const key=licensing.generateLicense(env);
    const made=await db.query(`select public.cpa_owner_create_license($1,$2,$3,$4,'days',1,null,'first',null) data`,[key.keyId,key.keyPrefix,key.keyHash,key.pepperVersion]);
    await db.query(`select public.cpa_owner_update_license($1,'deactivate')`,[made.rows[0].data.id]);
    await db.query(`select set_config('request.jwt.claim.role','service_role',false)`);
    await assert.rejects(db.query(`select public.cpa_license_activate($1::jsonb,$2,$3,$4,$5,$6)`,[JSON.stringify([{version:'v1',hash:key.keyHash}]),'a'.repeat(64),'A'.repeat(64),'b'.repeat(64),'cash-hunters-1.6.0-test','c'.repeat(64)]),/invalid_key/);
  }finally{await db.close();}
});
