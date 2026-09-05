'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const sql = fs.readFileSync(path.join(root, 'supabase/remediation/20260904_restore_missing_rpcs.sql'), 'utf8');
const diagnostic = fs.readFileSync(path.join(root, 'supabase/diagnostics/missing_rpc_dependencies.sql'), 'utf8');
const expected = [
  'paxinbot_get_usage_runtime_state','paxinbot_owner_approve_order','paxinbot_owner_kick_user',
  'paxinbot_owner_list_orders','paxinbot_owner_list_site_security_events','paxinbot_owner_refund_order',
  'paxinbot_owner_reset_user_devices','paxinbot_owner_set_user_ban','paxinbot_record_site_security_event',
  'paxinbot_service_rate_limit_v2'
];
const functions = [...sql.matchAll(/^create function public\.(\w+)\([\s\S]*?\$\$;/gm)];

test('supplement creates exactly the ten missing functions without replacing existing ones', () => {
  assert.deepEqual(functions.map(m => m[1]).sort(), expected.sort());
  assert.doesNotMatch(sql, /create or replace function|drop function|drop table/i);
  assert.match(sql, /where to_regprocedure\(signature\) is not null/);
  assert.match(sql, /ja existem/);
});

test('every new definer fixes search_path and checks authorization inside the function', () => {
  for (const [body, name] of functions) {
    assert.match(body, /security definer/);
    assert.match(body, /set search_path = pg_catalog, public, auth, pg_temp/);
    if (name.startsWith('paxinbot_owner_')) {
      assert.match(body, /if auth.uid\(\) is null then raise exception 'not_authenticated'/);
      assert.match(body, /perform public.paxinbot_require_owner\(\)/);
    } else assert.match(body, /auth.role\(\) is distinct from 'service_role'/);
  }
  assert.match(sql, /if p_banned is null then raise exception 'invalid_ban_state'/);
});

test('new RPC privileges are granted explicitly in the same transaction and verified', () => {
  assert.match(sql, /\nbegin;/);
  assert.match(sql, /\ncommit;\s*$/);
  assert.equal((sql.match(/^revoke all on function /gm) || []).length, 10);
  assert.equal((sql.match(/^grant execute on function /gm) || []).length, 10);
  assert.doesNotMatch(sql, /^grant execute.*to (?:public|anon);/m);
  assert.match(sql, /has_function_privilege\('authenticated'/);
  assert.match(sql, /acl.grantee = 0/);
});

test('read-only diagnostic and executable preflight check the same 58 columns', () => {
  const columns = text => [...text.matchAll(/\('((?:public|auth)\.\w+)', '(\w+)', '(\w+)'\)/g)].map(m => m.slice(1));
  assert.equal(columns(sql).length, 58);
  assert.deepEqual(columns(sql), columns(diagnostic));
  assert.doesNotMatch(diagnostic.replace(/--[^\n]*/g,''), /\b(?:create|alter|drop|insert|update|delete|grant|revoke|do)\s/i);
  assert.match(sql, /i.indnkeyatts = 2/);
  assert.match(sql, /i.indnkeyatts = 1/);
  assert.match(sql, /Estrutura incompativel/);
});

test('device reset invalidates approved requests before revoking sessions and preserves identities', () => {
  const [body] = functions.find(m => m[1] === 'paxinbot_owner_reset_user_devices');
  assert.match(body, /if p_user_id is null then raise exception 'invalid_user'/);
  assert.match(body, /update public.device_authorizations set denied_at = now\(\)\s+where approved_user_id = p_user_id and consumed_at is null and denied_at is null/);
  assert.match(body, /update public.desktop_sessions set revoked_at = now\(\) where user_id = p_user_id and revoked_at is null/);
  assert.ok(body.indexOf('update public.device_authorizations') < body.indexOf('update public.desktop_sessions'));
  assert.match(body, /'owner.user_devices_reset'/);
  assert.doesNotMatch(body, /\bdelete\b|\btruncate\b|update public\.(?:device_identities|promotion_claims|usage_grants|profiles)/i);
  assert.doesNotMatch(diagnostic, /device_account_bindings/);
});

test('only the event table may be created and direct access is closed without permissive policies', () => {
  assert.deepEqual([...sql.matchAll(/^create table if not exists public\.(\w+)/gm)].map(m => m[1]), ['site_security_events']);
  assert.match(sql, /alter table public.site_security_events enable row level security/);
  assert.match(sql, /revoke all on table public.site_security_events from public, anon, authenticated, service_role/);
  assert.doesNotMatch(sql, /create policy|disable row level security/i);
});
