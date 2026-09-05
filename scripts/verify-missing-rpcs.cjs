'use strict';
// Runs only in an ephemeral, in-memory PostgreSQL (PGlite); never connects to Supabase.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
if (!process.env.PAXINBOT_SQL_TEST_RUNTIME) throw new Error('Set PAXINBOT_SQL_TEST_RUNTIME to the installed PGlite module path.');
const { PGlite } = require(process.env.PAXINBOT_SQL_TEST_RUNTIME);
const root = path.resolve(__dirname, '..');
const read = f => fs.readFileSync(path.join(root, f), 'utf8');
const supplement = read('supabase/remediation/20260904_restore_missing_rpcs.sql');
const repair = read('supabase/remediation/20260904_repair_rpc_execute_privileges.sql');
const audit = read('supabase/diagnostics/rpc_execute_audit.sql');
const deps = read('supabase/diagnostics/missing_rpc_dependencies.sql');
const owner = '11111111-1111-4111-8111-111111111111';
const user = '22222222-2222-4222-8222-222222222222';
const other = '33333333-3333-4333-8333-333333333333';
const order = '44444444-4444-4444-8444-444444444444';
const product = '55555555-5555-4555-8555-555555555555';
const grant = '66666666-6666-4666-8666-666666666666';
const event = '77777777-7777-4777-8777-777777777777';
const signatures = [...supplement.matchAll(/^  \('(public\.[^']+)', (true|false)\)/gm)].map(m => ({ signature: m[1], service: m[2] === 'true' }));
assert.equal(signatures.length, 10);
const fixture = `
create role anon; create role authenticated; create role service_role;
create schema auth;
grant usage on schema public, auth to anon, authenticated, service_role;
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
create function auth.role() returns text language sql stable as $$ select nullif(current_setting('request.jwt.claim.role',true),'') $$;
create function public.paxinbot_require_owner() returns void language plpgsql security definer as $$
begin if auth.uid() is distinct from '${owner}'::uuid then raise exception 'not_owner'; end if; end $$;
create table auth.users(id uuid primary key, email text);
create table public.orders(id uuid primary key, user_id uuid, product_id uuid, entitlement_id uuid,
 status text, currency text, payment_provider text, provider_status text,
 paid_at timestamptz, updated_at timestamptz, created_at timestamptz,
 subtotal_cents integer, discount_cents integer, amount_cents integer);
create table public.products(id uuid primary key, name text, access_kind text, duration_minutes integer);
create table public.entitlements(id uuid primary key default gen_random_uuid(), user_id uuid,
 kind text, status text default 'active', source text, expires_at timestamptz, revoked_at timestamptz);
create table public.profiles(id uuid primary key, disabled_at timestamptz);
create table public.audit_events(user_id uuid, event_type text, metadata jsonb);
create table public.desktop_sessions(user_id uuid, usage_grant_id uuid, revoked_at timestamptz, usage_paused_at timestamptz, last_seen_at timestamptz);
create table public.usage_grants(user_id uuid, status text, revoked_at timestamptz);
create table public.device_authorizations(id integer primary key, approved_user_id uuid, consumed_at timestamptz, denied_at timestamptz);
create table public.device_identities(id uuid primary key, public_key text, banned_at timestamptz, ban_reason text);
create table public.promotion_claims(user_id uuid, device_fingerprint_hash text);
create table public.api_rate_limits(scope text, subject_hash text, window_started_at timestamptz, hits integer, primary key(scope,subject_hash));
insert into auth.users values ('${owner}','owner@example.invalid'),('${user}','client@example.invalid'),('${other}','other@example.invalid');
insert into public.profiles(id) values ('${user}'),('${other}');
insert into public.products values('${product}','Test only','lifetime',60);
insert into public.orders values('${order}','${user}','${product}',null,'pending','BRL','test',null,null,now(),now(),1000,0,1000);
insert into public.desktop_sessions values('${user}','${grant}',null,null,now()),('${other}',null,null,null,now());
insert into public.usage_grants values('${user}','available',null),('${other}','available',null);
insert into public.device_authorizations values
 (1,'${user}',null,null), (2,'${other}',null,null), (3,null,null,null),
 (4,'${user}','2026-01-01Z',null), (5,'${user}',null,'2026-01-01Z');
insert into public.desktop_sessions values('${user}',null,'2026-01-01Z',null,now());
insert into public.device_identities values('${event}','fixture-only-public-key','2026-01-01Z','fixture ban');
insert into public.promotion_claims values('${user}','fixture-fingerprint');
`;
async function snapshot(db, table) {
  // Table names are fixed test literals, never user input.
  return (await db.query(`select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb) as rows from public.${table} t`)).rows[0].rows;
}
async function database() { const db = new PGlite(); await db.exec(fixture); return db; }
async function role(db, name, sub, work, claim = name) {
  await db.exec(`begin; set local role ${name};`);
  await db.query("select set_config('request.jwt.claim.role',$1,true), set_config('request.jwt.claim.sub',$2,true)", [claim, sub || '']);
  try { return await work(); } finally { await db.exec('rollback;'); }
}
const calls = {
  paxinbot_owner_approve_order: `select public.paxinbot_owner_approve_order('${order}')`,
  paxinbot_owner_refund_order: `select public.paxinbot_owner_refund_order('${order}')`,
  paxinbot_owner_list_orders: "select public.paxinbot_owner_list_orders('')",
  paxinbot_owner_kick_user: `select public.paxinbot_owner_kick_user('${user}')`,
  paxinbot_owner_set_user_ban: `select public.paxinbot_owner_set_user_ban('${user}',true,'test')`,
  paxinbot_owner_reset_user_devices: `select public.paxinbot_owner_reset_user_devices('${user}')`,
  paxinbot_owner_list_site_security_events: 'select public.paxinbot_owner_list_site_security_events(20)',
  paxinbot_get_usage_runtime_state: `select public.paxinbot_get_usage_runtime_state('${user}','${grant}') as result`,
  paxinbot_service_rate_limit_v2: `select public.paxinbot_service_rate_limit_v2('test_scope','${'a'.repeat(64)}',2,60,1) as result`,
  paxinbot_record_site_security_event: `select public.paxinbot_record_site_security_event('${event}','${event}','auth.login_rejected',10::smallint,'/api/auth/login',null,null,null,'{"outcome":"rejected"}'::jsonb) as result`
};
async function main() {
  let checks = 0;
  const db = await database();
  try {
    const before = await db.query(deps);
    assert.ok(before.rows.every(r => ['OK','WILL_CREATE'].includes(r.status)));
    const untouched = ['device_authorizations', 'desktop_sessions', 'device_identities', 'promotion_claims', 'usage_grants', 'profiles'];
    const original = Object.fromEntries(await Promise.all(untouched.map(async t => [t, await snapshot(db, t)])));
    await db.exec(supplement); checks++;
    for (const table of untouched) assert.deepEqual(await snapshot(db, table), original[table]);
    checks++;
    assert.ok((await db.query(deps)).rows.every(r => r.status === 'OK'));
    assert.equal((await db.query('select count(*)::integer as n from public.audit_events')).rows[0].n, 0);
    assert.equal((await db.query('select status from public.orders')).rows[0].status, 'pending'); checks++;
    for (const { signature, service } of signatures) {
      const name = signature.match(/public\.(\w+)\(/)[1];
      await assert.rejects(role(db, 'anon', '', () => db.query(calls[name])), /permission denied/);
      if (!service) await assert.rejects(role(db, 'authenticated', user, () => db.query(calls[name])), /not_owner/);
      else {
        await assert.rejects(role(db, 'authenticated', user, () => db.query(calls[name])), /permission denied/);
        await assert.rejects(role(db, 'service_role', '', () => db.query(calls[name]), ''), /service_role_required/);
      }
      checks++;
    }
    for (const name of Object.keys(calls).filter(n => n.startsWith('paxinbot_owner_'))) {
      await role(db, 'authenticated', owner, () => db.query(calls[name])); checks++;
    }
    await assert.rejects(role(db, 'authenticated', owner, () => db.query('select public.paxinbot_owner_reset_user_devices(null)')), /invalid_user/); checks++;
    await assert.rejects(role(db, 'authenticated', '', () => db.query(calls.paxinbot_owner_reset_user_devices)), /not_authenticated/); checks++;
    await role(db, 'authenticated', owner, async () => {
      assert.equal((await db.query(calls.paxinbot_owner_reset_user_devices)).rows[0].paxinbot_owner_reset_user_devices.ok, true);
      await db.exec('reset role;');
      const requests = (await db.query('select id, denied_at is not null as denied from public.device_authorizations order by id')).rows;
      assert.deepEqual(requests, [
        { id: 1, denied: true }, { id: 2, denied: false }, { id: 3, denied: false },
        { id: 4, denied: false }, { id: 5, denied: true }
      ]);
      for (const row of (await snapshot(db, 'device_authorizations')).filter(r => r.id !== 1)) {
        assert.deepEqual(row, original.device_authorizations.find(r => r.id === row.id));
      }
      checks++;
      assert.equal((await db.query('select count(*)::integer as n from public.desktop_sessions where user_id=$1 and revoked_at is null', [user])).rows[0].n, 0);
      const sessions = await snapshot(db, 'desktop_sessions');
      for (const row of original.desktop_sessions.filter(r => r.user_id === other || r.revoked_at !== null)) {
        assert.ok(sessions.some(s => JSON.stringify(s) === JSON.stringify(row)));
      }
      for (const table of ['device_identities', 'promotion_claims', 'usage_grants', 'profiles']) {
        assert.deepEqual(await snapshot(db, table), original[table]);
      }
      assert.deepEqual((await db.query('select * from public.audit_events')).rows, [
        { user_id: owner, event_type: 'owner.user_devices_reset', metadata: { targetUserId: user } }
      ]);
      checks++;
      const afterRequests = await snapshot(db, 'device_authorizations');
      await db.exec('set local role authenticated;');
      await db.query(calls.paxinbot_owner_reset_user_devices);
      await db.exec('reset role;');
      assert.deepEqual(await snapshot(db, 'device_authorizations'), afterRequests);
      assert.deepEqual(await snapshot(db, 'desktop_sessions'), sessions);
      checks++;
    });
    await role(db, 'service_role', '', async () => {
      assert.equal((await db.query(calls.paxinbot_get_usage_runtime_state)).rows[0].result.running, true);
      assert.equal((await db.query(calls.paxinbot_service_rate_limit_v2)).rows[0].result.allowed, true);
      await db.query(calls.paxinbot_service_rate_limit_v2);
      assert.equal((await db.query(calls.paxinbot_service_rate_limit_v2)).rows[0].result.allowed, false);
      assert.equal((await db.query(calls.paxinbot_record_site_security_event)).rows[0].result, true);
      await db.query(calls.paxinbot_record_site_security_event);
      await db.exec('reset role;');
      assert.equal((await db.query('select count(*)::integer as n from public.site_security_events')).rows[0].n, 1);
    }); checks++;
    await assert.rejects(role(db, 'authenticated', owner, () => db.query(`select public.paxinbot_owner_set_user_ban('${user}',null,null)`)), /invalid_ban_state/); checks++;
    await assert.rejects(db.exec(supplement), /ja existem/);
    await db.exec('rollback;'); checks++;
    // Other RPC bodies are inert fixtures: this checks ACL repair, not business logic.
    const rules = [...repair.matchAll(/\('(public\.paxinbot_\w+\([^']*\))', (?:true|false), (?:true|false), (?:true|false), (?:true|false)\)/g)].map(m => m[1]);
    for (const signature of rules) {
      if ((await db.query('select to_regprocedure($1)::text as f', [signature])).rows[0].f === null) {
        await db.exec(`create function ${signature} returns jsonb language sql security definer as $$ select '{}'::jsonb $$;`);
      }
    }
    await db.exec(repair);
    assert.ok((await db.query(audit)).rows.every(r => ['OK','OPTIONAL_ABSENT'].includes(r.status)));
    await role(db, 'authenticated', owner, () => db.query(calls.paxinbot_owner_list_orders));
    checks++;
  } finally { await db.close(); }
  const invalid = await database();
  try {
    await invalid.exec('alter table public.device_authorizations drop column denied_at;');
    assert.ok((await invalid.query(deps)).rows.some(r => r.status === 'MISSING_COLUMN'));
    await assert.rejects(invalid.exec(supplement), /Estrutura incompativel/);
    await invalid.exec('rollback;');
    assert.equal((await invalid.query("select to_regprocedure('public.paxinbot_owner_kick_user(uuid)')::text as f")).rows[0].f, null);
    assert.equal((await invalid.query("select to_regclass('public.site_security_events')::text as t")).rows[0].t, null); checks++;
  } finally { await invalid.close(); }
  const inherited = await database();
  try {
    await inherited.exec('create role inherited_execute; grant inherited_execute to anon; alter default privileges grant execute on functions to inherited_execute;');
    await assert.rejects(inherited.exec(supplement), /ACL inesperada/);
    await inherited.exec('rollback;');
    assert.equal((await inherited.query("select to_regprocedure('public.paxinbot_owner_kick_user(uuid)')::text as f")).rows[0].f, null); checks++;
  } finally { await inherited.close(); }
  console.log(JSON.stringify({ engine: 'PGlite (PostgreSQL in memory)', checksPassed: checks, liveDatabaseTouched: false }));
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
