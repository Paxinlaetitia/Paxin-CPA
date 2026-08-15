'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('device approval is visually compact and has no manual return action', () => {
  const html = read('activate.html');
  const css = read('client.css');
  assert.match(html, /<body class="activation-page"/);
  assert.match(html, /class="auth-card activation-card/);
  assert.doesNotMatch(html, /activate-open-app|Voltar ao Paxinbot|prototype-notice/);
  assert.match(css, /\.activation-page \.client-access-section \{ padding: 104px 0 72px; \}/);
  assert.match(css, /#activate-approve\[hidden\][^{]+\{ display: none !important; \}/);
});

test('approval client locks the action and does not depend on a custom protocol redirect', () => {
  const client = read('auth-client.js');
  assert.match(client, /let approvalPending=false; let approvalComplete=false/);
  assert.match(client, /if \(approvalPending \|\| approvalComplete\) return/);
  assert.match(client, /approvalComplete=true/);
  assert.doesNotMatch(client, /window\.location\.assign\('paxinbot:\/\/auth-complete'\)/);
});
