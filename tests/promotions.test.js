'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('promotion claims are server-side, verified and idempotent per account', () => {
  const sql = read('supabase/migrations/20260825_promotions.sql');
  assert.match(sql, /unique \(promotion_id,user_id\)/i);
  assert.match(sql, /email_confirmed_at is null/i);
  assert.match(sql, /where id=p_promotion_id for update/i);
  assert.match(sql, /insert into public\.usage_grants/i);
  assert.match(sql, /revoke all on table public\.promotions, public\.promotion_claims from public, anon, authenticated/i);
  assert.match(sql, /'boas-vindas-1h'.*3600,false/s);
});

test('client exposes a controlled welcome benefit without starting its timer', () => {
  const html = read('cliente.html');
  const client = read('auth-client.js');
  assert.match(html, /id="portal-promotion-card"[^>]*hidden/);
  assert.match(html, /id="claim-promotion"/);
  assert.match(client, /action:'claimPromotion'/);
  assert.match(client, /só começa após a ativação/);
  assert.match(client, /setAccountView\('subscription'\)/);
});

test('owner can create, edit and pause promotions independently from coupons', () => {
  const page = read('api/admin/_assets/page.txt');
  const client = read('api/admin/_assets/client.txt');
  const api = read('api/admin/index.js');
  assert.match(page, /data-admin-view="promotions"/);
  assert.match(page, /id="admin-promotion-form"/);
  assert.match(client, /action:'promotion'/);
  assert.match(client, /data-toggle-promotion/);
  assert.match(api, /paxinbot_owner_save_promotion/);
});

test('owner can search, block and unblock protected device identities', () => {
  const page=read('api/admin/_assets/page.txt');
  const client=read('api/admin/_assets/client.txt');
  const api=read('api/admin/index.js');
  assert.match(page,/data-admin-view="devices"/);
  assert.match(page,/id="admin-devices-list"/);
  assert.match(client,/data-device-ban/);
  assert.match(client,/action:'deviceBan'/);
  assert.match(api,/paxinbot_owner_list_device_identities/);
  assert.match(api,/paxinbot_owner_set_device_ban/);
});
