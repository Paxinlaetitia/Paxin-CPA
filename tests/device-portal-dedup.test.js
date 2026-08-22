'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('customer device list groups desktop sessions by verified hardware identity', () => {
  const migration = read('supabase/migrations/20260902_device_portal_identity_dedup.sql');

  assert.match(migration, /coalesce\(d\.fingerprint_hash,\s*'legacy:'\s*\|\|\s*s\.id::text\)/i);
  assert.match(migration, /group by\s+coalesce\(s\.fingerprint_hash/i);
  assert.match(migration, /bool_or\(s\.revoked_at is null and s\.expires_at > now\(\)\)/i);
  assert.doesNotMatch(migration, /select\s+s\.id,\s*s\.device_name/i);
});

test('revoking a displayed computer revokes every session with the same HWID', () => {
  const migration = read('supabase/migrations/20260902_device_portal_identity_dedup.sql');

  assert.match(migration, /create or replace function public\.paxinbot_revoke_my_device\(p_session_id uuid\)/i);
  assert.match(migration, /fingerprint_hash\s*=\s*v_fingerprint_hash/i);
  assert.match(migration, /s\.user_id\s*=\s*auth\.uid\(\)/i);
  assert.match(migration, /'deviceIdentityId'/i);
});

test('portal sends the stable device identity instead of treating it as a session', () => {
  const client = read('auth-client.js');
  const account = read('api/account/index.js');

  assert.match(client, /action:'revokeDevice',\s*deviceIdentityId:button\.dataset\.revokeDevice/);
  assert.match(account, /p_session_id:\s*String\(body\.deviceIdentityId\s*\|\|\s*''\)/);
  assert.match(account, /action === 'revokeDevice'[\s\S]*?Dispositivo inválido/);
});

test('authorized computers omit revoked and expired legacy sessions', () => {
  const migration = read('supabase/migrations/20260903_authorized_devices_active_only.sql');

  assert.match(migration, /where s\.user_id=auth\.uid\(\)[\s\S]*?s\.revoked_at is null[\s\S]*?s\.expires_at > now\(\)/i);
  assert.match(migration, /group by\s+coalesce\(s\.fingerprint_hash,\s*'legacy:'\s*\|\|\s*s\.id::text\)/i);
  assert.match(migration, /'status',\s*'active'/i);
  assert.doesNotMatch(migration, /delete\s+from\s+public\.desktop_sessions/i);
});
