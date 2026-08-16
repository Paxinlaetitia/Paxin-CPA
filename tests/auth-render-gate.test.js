'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

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
  assert.ok(config.redirects.some(rule => rule.source === '/admin' && rule.destination === '/' && rule.permanent === false));
  assert.equal(rewrites.some(rule => rule.source === '/admin'), false);
  assert.ok(rewrites.some(rule => /^\/gestao\//.test(rule.source) && rule.destination === '/api/admin?view=page'));
});

test('public and account scripts can share one browser page without lexical collisions', () => {
  assert.doesNotThrow(() => new vm.Script(`${read('script.js')}\n${read('auth-client.js')}`));
});

test('signup uses username, email and one password with accessible animated visibility controls', () => {
  const html = read('cliente.html');
  const shell = read('site-shell.js');
  const publicClient = read('script.js');
  const accountClient = read('auth-client.js');
  const css = read('client.css');
  const api = read('api/auth/[action].js');

  assert.match(html, /id="signup-username" name="username"[^>]+minlength="3"[^>]+maxlength="24"/);
  assert.doesNotMatch(html, /id="signup-password-confirm"/);
  assert.equal((html.match(/data-password-toggle=/g) || []).length, 2);
  assert.match(html, /data-password-toggle="#client-password"[^>]+aria-label="Mostrar senha"[^>]+aria-pressed="false"/);
  assert.match(html, /data-password-toggle="#signup-password"[^>]+aria-label="Mostrar senha"[^>]+aria-pressed="false"/);
  assert.match(shell, /symbol id="i-eye"/);
  assert.match(shell, /symbol id="i-eye-off"/);
  assert.match(publicClient, /querySelectorAll\('\[data-password-toggle\]'\)/);
  assert.match(publicClient, /setAttribute\('aria-pressed', String\(willShow\)\)/);
  assert.match(accountClient, /username:data\.get\('username'\)/);
  assert.match(css, /animation: auth-eye-toggle 160ms ease-out/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(api, /const USERNAME_PATTERN =/);
  assert.match(api, /data: \{ display_name: username \}/);
  assert.match(api, /paxinbot_update_my_profile/);
});
