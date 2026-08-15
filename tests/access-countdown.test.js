'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('client access counter includes seconds and resynchronizes with the server', () => {
  const client = read('auth-client.js');
  const css = read('client.css');
  assert.match(client, /function formatUsageCountdown/);
  assert.match(client, /\$\{pad\(rest\)\}s/);
  assert.match(client, /setInterval\(syncAccessSummary, 10000\)/);
  assert.match(client, /PaxinbotAuth\.request\('\/api\/auth\/me'\)/);
  assert.match(css, /#dashboard-expiry,#subscription-expiry[^}]+tabular-nums/);
});

test('server reports whether the metered application session is running without exposing session secrets', () => {
  const handler = read(path.join('api', 'auth', '[action].js'));
  assert.match(handler, /select: 'last_seen_at,usage_paused_at'/);
  assert.match(handler, /entitlement\.usageRunning/);
  assert.match(handler, /serverNow: new Date\(\)\.toISOString\(\)/);
  assert.doesNotMatch(handler, /select: '[^']*token_hash/);
});
