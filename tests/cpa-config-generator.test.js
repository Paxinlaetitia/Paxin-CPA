'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const { spawnSync }=require('node:child_process');
const { generate }=require('../scripts/cpa-generate-config.cjs');

function temporary(){return fs.mkdtempSync(path.join(os.tmpdir(),'paxincpa-config-test-'));}

test('offline generator creates matching Ed25519 material and stable public contract',()=>{
  const directory=temporary();
  try{
    const result=generate(directory,'cash-hunters-1.6.0-test');
    const secrets=JSON.parse(fs.readFileSync(result.secretFile,'utf8'));
    const publicConfig=JSON.parse(fs.readFileSync(result.publicFile,'utf8'));
    assert.deepEqual(Object.keys(secrets).sort(),['CPA_LICENSE_HMAC_CURRENT_VERSION','CPA_LICENSE_HMAC_PEPPERS','CPA_LICENSE_SIGNING_CURRENT_KID','CPA_LICENSE_SIGNING_KEYS']);
    assert.deepEqual(Object.keys(publicConfig).sort(),['api_url','build_mode','public_keys','release_id']);
    assert.equal(publicConfig.api_url,'https://www.paxincpa.store/api/licenses');
    assert.equal(publicConfig.release_id,'cash-hunters-1.6.0-test');assert.equal(publicConfig.build_mode,'production');
    const kid=secrets.CPA_LICENSE_SIGNING_CURRENT_KID;assert.equal(Object.keys(publicConfig.public_keys)[0],kid);
    const privateKey=crypto.createPrivateKey({key:Buffer.from(JSON.parse(secrets.CPA_LICENSE_SIGNING_KEYS)[kid],'base64url'),format:'der',type:'pkcs8'});
    const derived=crypto.createPublicKey(privateKey).export({format:'der',type:'spki'}).toString('base64url');
    assert.equal(derived,publicConfig.public_keys[kid]);
    assert.doesNotMatch(JSON.stringify(publicConfig),/PRIVATE|PEPPER|SIGNING_KEYS|HMAC/i);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('generator refuses repository destinations, invalid releases and overwrite',()=>{
  assert.throws(()=>generate(path.join(__dirname,'generated'),'cash-hunters-1.6.0-test'),/outside the site repository/);
  const directory=temporary();
  try{
    assert.throws(()=>generate(directory,'bad release'),/Invalid release ID/);
    generate(directory,'cash-hunters-1.6.0-test');
    assert.throws(()=>generate(directory,'cash-hunters-1.6.0-test'),/Refusing to replace/);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('CLI discloses no generated secrets on stdout',()=>{
  const directory=temporary();
  try{
    const result=spawnSync(process.execPath,[path.join(__dirname,'../scripts/cpa-generate-config.cjs'),directory,'cash-hunters-1.6.0-test'],{encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');
    assert.equal(result.stdout.trim(),'Configuration written. Import server secrets securely; only public config goes to the build.');
    const secrets=JSON.parse(fs.readFileSync(path.join(directory,'cpa-server-secrets.json'),'utf8'));
    for(const value of Object.values(secrets))assert.equal(result.stdout.includes(String(value)),false);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
