'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('client portal starts neutral and reveals exactly one authenticated state', () => {
  const html = read('cliente.html');
  const css = read('client.css');
  const client = read('auth-client.js');

  assert.match(html, /<body class="client-auth-pending"[^>]+aria-busy="true">/);
  assert.match(html, /<div data-site-header><\/div>/);
  assert.match(html, /id="client-auth-loader"[^>]+role="status"/);
  assert.match(css, /\.client-auth-pending \.client-access-section[^}]+display: none !important/);
  assert.match(css, /\.client-auth-pending \.client-dashboard-preview[^}]+display: none !important/);
  assert.match(css, /\.client-guest \.client-dashboard-preview \{ display: none !important; \}/);
  assert.match(css, /\.client-authenticated \.site-header[^}]+display: none !important/);
  assert.match(client, /classList\.toggle\('client-authenticated', Boolean\(user\)\)/);
  assert.match(client, /classList\.toggle\('client-guest', !user\)/);
  assert.match(client, /classList\.remove\('client-auth-pending'\)/);
});

test('every account route uses the gated client document and admin remains server gated', () => {
  const config = JSON.parse(read('vercel.json'));
  const rewrites = config.rewrites || [];
  assert.ok(rewrites.some(rule => rule.source === '/conta' && rule.destination === '/cliente'));
  assert.ok(rewrites.some(rule => rule.source === '/conta/:path*' && rule.destination === '/cliente'));
  assert.ok(rewrites.some(rule => rule.source === '/admin' && rule.destination === '/api/admin?view=hidden'));
  assert.ok(rewrites.some(rule => /^\/gestao\//.test(rule.source) && rule.destination === '/api/admin?view=page'));
});
