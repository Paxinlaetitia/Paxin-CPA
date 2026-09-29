'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const docs=path.join(__dirname,'..','docs');
const preflight=fs.readFileSync(path.join(docs,'cpa-licensing-preflight.sql'),'utf8');
const postcheck=fs.readFileSync(path.join(docs,'cpa-licensing-postcheck.sql'),'utf8');
const statements=value=>value.replace(/^\s*--.*$/gm,'');

test('CPA preflight reads prerequisites and collisions without customer data',()=>{
  for(const prerequisite of ['auth.users','paxinbot_is_owner','paxinbot_service_rate_limit(text,text,integer,integer)','extensions.gen_random_uuid'])assert.ok(preflight.includes(prerequisite));
  assert.doesNotMatch(preflight,/paxinbot_service_rate_limit_v2/);
  assert.match(preflight,/begin transaction read only;/i);assert.match(preflight,/commit;/i);
  for(const table of ['cpa_licenses','cpa_devices','cpa_device_bans','cpa_sessions','cpa_challenges','cpa_audit'])assert.ok(preflight.includes(`('${table}')`));
  assert.doesNotMatch(statements(preflight),/^\s*(?:insert\s+into|update\s+public\.|delete\s+from|alter\s+table|create\s+table|drop\s+table|truncate\s+)/im);
});

test('CPA postcheck covers RLS and exact RPC grants without customer rows',()=>{
  for(const table of ['cpa_licenses','cpa_devices','cpa_device_bans','cpa_sessions','cpa_challenges','cpa_audit'])assert.ok(postcheck.includes(`('${table}')`));
  for(const rpc of ['cpa_license_activate','cpa_license_refresh','cpa_license_authorize','cpa_owner_create_license','cpa_owner_update_license','cpa_owner_set_device_ban'])assert.ok(postcheck.includes(rpc));
  assert.match(postcheck,/relrowsecurity/);assert.match(postcheck,/has_table_privilege/);assert.match(postcheck,/has_function_privilege/);
  assert.match(postcheck,/auth\.role\(\) is not null/);assert.match(postcheck,/paxinbot_is_owner\(\) is true/);
  assert.match(postcheck,/begin transaction read only;/i);assert.match(postcheck,/commit;/i);
  assert.doesNotMatch(postcheck,/select\s+\*\s+from\s+public\.cpa_/i);
  assert.doesNotMatch(statements(postcheck),/^\s*(?:insert\s+into|update\s+public\.|delete\s+from|alter\s+table|create\s+table|drop\s+table|truncate\s+)/im);
});
