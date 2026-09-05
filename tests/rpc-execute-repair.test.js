'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const migration = read('supabase/remediation/20260904_repair_rpc_execute_privileges.sql');
const audit = read('supabase/diagnostics/rpc_execute_audit.sql');
const baseline = read('supabase/migrations/20260831_database_least_privilege.sql');
function matrix(sql) {
  return [...sql.matchAll(/\('(public\.paxinbot_\w+\([^']*\))', (true|false), (true|false), (true|false), (true|false)\)/g)]
    .map(m => ({ signature: m[1], anon: m[2] === 'true', authenticated: m[3] === 'true', service: m[4] === 'true', required: m[5] === 'true' }));
}
const rules = matrix(migration);

test('repair and read-only audit share the exact reviewed signature matrix', () => {
  assert.equal(fs.existsSync(path.join(root, 'supabase/migrations/20260904_repair_rpc_execute_privileges.sql')), false);
  assert.equal(rules.length, 67);
  assert.equal(new Set(rules.map(r => r.signature)).size, rules.length);
  assert.deepEqual(matrix(audit), rules);
  assert.doesNotMatch(audit.replace(/--[^\n]*/g, ''), /\b(?:grant|revoke|insert|update|delete|create|alter|drop|call|do)\s/i);
});

test('anonymous access is only the exact public catalog signature', () => {
  assert.deepEqual(rules.filter(r => r.anon).map(r => r.signature), ['public.paxinbot_list_active_products()']);
  assert.ok(rules.filter(r => r.service).every(r => !r.anon && !r.authenticated));
  const payment = rules.find(r => r.signature.startsWith('public.paxinbot_finalize_mercadopago_payment('));
  assert.ok(payment.service && payment.required && !payment.authenticated);
});

test('existing browser/server allowlists and all dynamic route RPCs are retained', () => {
  const expectedNames = new Set([...baseline.matchAll(/'(paxinbot_\w+)'/g)].map(m => m[1]));
  const actualNames = new Set(rules.map(r => r.signature.match(/^public\.(\w+)\(/)[1]));
  assert.deepEqual(actualNames, expectedNames);
  for (const file of ['api/account/index.js', 'api/admin/index.js', 'api/checkout/index.js']) {
    for (const match of read(file).matchAll(/['`](paxinbot_[a-z0-9_]+)['`]/g)) {
      assert.ok(actualNames.has(match[1]), `${file}: ${match[1]}`);
    }
  }
});

test('internal and legacy helpers are not reopened to API roles', () => {
  for (const name of ['handle_new_auth_user', 'paxinbot_require_owner', 'paxinbot_prepare_checkout', 'paxinbot_cancel_checkout', 'paxinbot_pause_desktop_usage', 'paxinbot_desktop_session_v2']) {
    assert.equal(rules.some(r => r.signature.startsWith(`public.${name}(`)), false);
  }
});

test('repair is atomic, scoped to app functions, with required-function and effective ACL checks', () => {
  assert.match(migration, /\nbegin;/);
  assert.match(migration, /\ncommit;\s*$/);
  assert.match(migration, /current_user <> 'postgres'/);
  assert.match(migration, /where required and to_regprocedure\(signature\) is null/);
  assert.match(migration, /set local lock_timeout = '5s'/);
  assert.match(migration, /left\(p.proname, 9\) = 'paxinbot_'/);
  assert.match(migration, /from public, anon, authenticated, service_role/);
  for (const role of ['anon', 'authenticated', 'service_role']) {
    assert.match(migration, new RegExp(`has_function_privilege\\('${role}'`));
  }
  assert.match(migration, /acl.grantee = 0/);
  assert.doesNotMatch(migration, /on all functions|alter table|create policy|disable row level security|create or replace function|\bdelete from\b|\btruncate\b|\bexecute[^;]*cascade/i);
});
