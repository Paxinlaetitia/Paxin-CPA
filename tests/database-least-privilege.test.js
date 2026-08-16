'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const migrationPath = path.join(root, 'supabase/migrations/20260831_database_least_privilege.sql');
const migration = fs.readFileSync(migrationPath, 'utf8');
const migrations = fs.readdirSync(path.join(root, 'supabase/migrations'))
  .filter(name => name.endsWith('.sql')).sort()
  .map(name => fs.readFileSync(path.join(root, 'supabase/migrations', name), 'utf8')).join('\n');

test('Data API objects become private by default', () => {
  assert.match(migration, /revoke create on schema public from public, anon, authenticated, service_role/i);
  assert.match(migration, /alter default privileges for role postgres[\s\S]*revoke all on tables from public, anon, authenticated, service_role/i);
  assert.match(migration, /revoke execute on functions from public, anon, authenticated, service_role/i);
  assert.match(migration, /revoke usage, select on sequences from public, anon, authenticated, service_role/i);
  assert.match(migration, /revoke all privileges on all tables in schema public from public, anon, authenticated, service_role/i);
  assert.match(migration, /revoke execute on all functions in schema public from public, anon, authenticated, service_role/i);
});

test('only current v3 desktop RPCs are reopened to the service role', () => {
  const serviceSection = migration.split('-- RPCs exclusivos da Vercel')[1];
  for (const name of [
    'paxinbot_service_rate_limit_v2','paxinbot_device_start_v3',
    'paxinbot_device_approve_v3','paxinbot_device_poll_v3',
    'paxinbot_desktop_session_v3','paxinbot_pause_desktop_usage_v3',
    'paxinbot_record_security_event','paxinbot_authorize_protected_release',
    'paxinbot_finalize_mercadopago_payment','paxinbot_record_site_security_event',
    'paxinbot_get_usage_runtime_state'
  ]) assert.match(serviceSection, new RegExp(`'${name}'`));
  assert.doesNotMatch(serviceSection, /'paxinbot_(?:device_start|device_approve|device_poll|desktop_session)_v2'/);
});

test('public catalog has the only anonymous RPC grant', () => {
  const anonSection = migration.split('-- Reabra somente os RPCs chamados sem sessão.')[1]
    .split('-- RPCs do navegador autenticado.')[0];
  assert.match(anonSection, /'paxinbot_list_active_products'/);
  assert.equal((anonSection.match(/'paxinbot_[a-z0-9_]+'/g) || []).length, 1);
});

test('every RPC selected dynamically by an API handler is present in the grant allowlist', () => {
  const handlers = ['api/account/index.js', 'api/admin/index.js', 'api/checkout/index.js'];
  const selected = new Set(handlers.flatMap(file =>
    [...fs.readFileSync(path.join(root, file), 'utf8').matchAll(/['`](paxinbot_[a-z0-9_]+)['`]/g)]
      .map(match => match[1])
  ));
  assert.ok(selected.size >= 35);
  for (const rpc of selected) assert.match(migration, new RegExp(`'${rpc}'`), `${rpc} must be granted explicitly`);
});

test('all tables created by repository migrations explicitly enable RLS', () => {
  const tables = [...migrations.matchAll(/^create table(?: if not exists)?\s+public\.([a-z0-9_]+)/gim)]
    .map(match => match[1]);
  assert.ok(tables.length >= 10);
  for (const table of tables) {
    assert.match(migrations, new RegExp(`alter table public\\.${table} enable row level security`, 'i'), `${table} must enable RLS`);
  }
});

test('runtime status no longer queries a private table through REST', () => {
  const auth = fs.readFileSync(path.join(root, 'api/auth/[action].js'), 'utf8');
  assert.doesNotMatch(auth, /rest\/v1\/desktop_sessions/);
  assert.match(auth, /rest\/v1\/rpc\/paxinbot_get_usage_runtime_state/);
  assert.match(migration, /auth\.role\(\) <> 'service_role'/);
});

test('Cloudflare guide does not pretend the WAF protects Supabase grants', () => {
  const guide = fs.readFileSync(path.join(root, 'docs/security/cloudflare-activation-guide.md'), 'utf8');
  assert.match(guide, /WAF da Cloudflare protege `paxincpa\.store`, mas não substitui RLS ou grants/);
  assert.match(guide, /não existe registro `db`, `postgres`,\s+`pooler` ou `supabase`/s);
  assert.match(guide, /SUPABASE_SECRET_KEY/);
});
