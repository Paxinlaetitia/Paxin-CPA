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
process.env.PUBLIC_SITE_URL='https://www.paxincpa.store';

const helpers=require('../api/_paxinbot');
const root=path.join(__dirname,'..');

function req(host) { return { headers:{ host },socket:{} }; }
function res() { return { statusCode:0,headers:{},setHeader(name,value){this.headers[name.toLowerCase()]=value;},end(value){this.body=JSON.parse(value);} }; }

test('production APIs accept only the official custom domain',()=>{
  const previous={ node:process.env.NODE_ENV,vercel:process.env.VERCEL_ENV,url:process.env.VERCEL_URL };
  try {
    process.env.NODE_ENV='production'; process.env.VERCEL_ENV='production'; process.env.VERCEL_URL='paxinbot-random.vercel.app';
    assert.equal(helpers.trustedRequestHost(req('www.paxincpa.store')),true);
    assert.equal(helpers.trustedRequestHost(req('paxincpa.store')),true);
    assert.equal(helpers.trustedRequestHost(req('paxinbot-random.vercel.app')),false);
    assert.equal(helpers.trustedRequestHost(req('attacker.invalid')),false);
    const response=res(); assert.equal(helpers.requireTrustedHost(req('paxinbot-random.vercel.app'),response),false);
    assert.equal(response.statusCode,404); assert.equal(response.body.code,'not_found');
  } finally {
    process.env.NODE_ENV=previous.node;
    if(previous.vercel===undefined) delete process.env.VERCEL_ENV; else process.env.VERCEL_ENV=previous.vercel;
    if(previous.url===undefined) delete process.env.VERCEL_URL; else process.env.VERCEL_URL=previous.url;
  }
});

test('preview accepts only its exact Vercel host in addition to the official domain',()=>{
  const previous={ node:process.env.NODE_ENV,vercel:process.env.VERCEL_ENV,url:process.env.VERCEL_URL };
  try {
    process.env.NODE_ENV='production'; process.env.VERCEL_ENV='preview'; process.env.VERCEL_URL='paxinbot-git-staging-owner.vercel.app';
    assert.equal(helpers.trustedRequestHost(req('paxinbot-git-staging-owner.vercel.app')),true);
    assert.equal(helpers.trustedRequestHost(req('other-preview.vercel.app')),false);
    assert.equal(helpers.publicOrigin(req('paxinbot-git-staging-owner.vercel.app')),'https://paxinbot-git-staging-owner.vercel.app');
  } finally {
    process.env.NODE_ENV=previous.node;
    if(previous.vercel===undefined) delete process.env.VERCEL_ENV; else process.env.VERCEL_ENV=previous.vercel;
    if(previous.url===undefined) delete process.env.VERCEL_URL; else process.env.VERCEL_URL=previous.url;
  }
});

test('production origin is strict HTTPS without paths or credentials',()=>{
  const original=process.env.PUBLIC_SITE_URL;
  try {
    process.env.PUBLIC_SITE_URL='http://www.paxincpa.store'; assert.throws(()=>helpers.configuredSiteOrigin(true),/inválida/);
    process.env.PUBLIC_SITE_URL='https://user:pass@www.paxincpa.store'; assert.throws(()=>helpers.configuredSiteOrigin(true),/inválida/);
    process.env.PUBLIC_SITE_URL='https://www.paxincpa.store/path'; assert.throws(()=>helpers.configuredSiteOrigin(true),/inválida/);
    process.env.PUBLIC_SITE_URL='https://www.paxincpa.store'; assert.equal(helpers.configuredSiteOrigin(true),'https://www.paxincpa.store');
  } finally { process.env.PUBLIC_SITE_URL=original; }
});

test('every deployed API handler rejects an untrusted origin host first',()=>{
  const files=[];
  (function walk(directory){ for(const entry of fs.readdirSync(directory,{withFileTypes:true})) { const item=path.join(directory,entry.name); if(entry.isDirectory()) walk(item); else if(entry.name.endsWith('.js')&&!item.endsWith('_paxinbot.js')) files.push(item); } })(path.join(root,'api'));
  assert.equal(files.length,11);
  for(const file of files) assert.match(fs.readFileSync(file,'utf8'),/requireTrustedHost\(req, res\)/,path.relative(root,file));
});

test('deployment excludes internal development material and contains no inline scripts',()=>{
  const ignore=fs.readFileSync(path.join(root,'.vercelignore'),'utf8');
  for(const name of ['tests','docs','supabase','.env.example','AUTH_SETUP.md']) assert.match(ignore,new RegExp(`^${name.replace('.','\\.')}\\s*$`,'m'));
  const htmlFiles=fs.readdirSync(root).filter(name=>name.endsWith('.html'));
  for(const name of htmlFiles) {
    const html=fs.readFileSync(path.join(root,name),'utf8');
    assert.doesNotMatch(html,/<script(?![^>]*\bsrc=)[^>]*>\s*\S/i,name);
  }
  const guide=fs.readFileSync(path.join(root,'docs','security','cloudflare-activation-guide.md'),'utf8');
  assert.match(guide,/Full \(strict\)/); assert.match(guide,/Bypass cache/); assert.match(guide,/Bot Fight Mode.*desativado/is); assert.match(guide,/HSTS gradual/);
});
