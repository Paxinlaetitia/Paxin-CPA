const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, 'api', 'admin', '_assets', name), 'utf8');

test('Cash Hunters admin section exposes the contract controls', () => {
  const page = read('page.txt');
  for (const value of ['cash-licenses', 'cash-license-create-form', 'hours', 'days', 'weeks', 'months', 'custom', 'lifetime', 'first', 'immediate', 'cash-licenses-list', 'cash-license-audit-list']) {
    assert.match(page, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('Cash license UI uses the dedicated endpoint and the existing CSRF flow', () => {
  const client = read('client.txt');
  assert.match(client, /fetch\(`\/api\/licenses-admin\$\{path\}/);
  assert.match(client, /headers\['x-paxinbot-csrf'\]=await csrf\(\)/);
  assert.match(client, /action:'create'/);
  for (const operation of ['activate', 'deactivate', 'suspend', 'revoke', 'ban', 'unban', 'reset_device', 'replace_device', 'extend', 'set_expiration', 'terminate_sessions']) {
    assert.match(client, new RegExp(operation));
  }
  assert.match(client, /action:'device'/i); // device action remains part of the API contract surface
  assert.doesNotMatch(client, /localStorage/);
});

test('license rows and audit values are inserted with textContent', () => {
  const client = read('client.txt');
  assert.match(client, /function renderCashLicenses\(items\)/);
  assert.match(client, /node\.textContent=text\(value\)/);
  assert.match(client, /function renderCashAudit\(items\)/);
  assert.match(client, /licenseCall\('\?action=audit'\)/);
});

test('license audit accepts category-only events and validates expiration input', () => {
  const client = read('client.txt');
  assert.match(client, /event\.eventType \|\| event\.event \|\| event\.category/);
  assert.match(client, /Number\.isNaN\(parsed\.getTime\(\)\)/);
  assert.match(client, /Informe uma data UTC válida/);
});

test('styles keep the Cash Hunters panel responsive and within admin tokens', () => {
  const style = read('style.txt');
  assert.match(style, /\.admin-cash-license-grid/);
  assert.match(style, /@media \(max-width: 900px\) \{ \.admin-cash-license-grid/);
  assert.match(style, /var\(--line\)/);
});
