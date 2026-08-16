'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('security workflow is read-only and never receives production secrets', () => {
  const workflow = read('.github/workflows/security-ci.yml');
  assert.match(workflow, /permissions:\s*\n\s+contents: read/);
  assert.match(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /pull_request_target:/);
  assert.doesNotMatch(workflow, /secrets\.|permissions:\s*write|contents: write|id-token: write/);
  assert.match(workflow, /persist-credentials: false/);
});

test('every external action is pinned to a full immutable commit', () => {
  const workflow = read('.github/workflows/security-ci.yml');
  const references = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)/gm)].map(match => match[1]);
  assert.ok(references.length >= 2);
  for (const reference of references) assert.match(reference, /@[0-9a-f]{40}$/i);
});

test('dependency installation cannot execute package lifecycle scripts', () => {
  const workflow = read('.github/workflows/security-ci.yml');
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm audit --audit-level=high/);
});

test('repository security verifier succeeds without third-party packages', () => {
  const result = spawnSync(process.execPath, ['scripts/security-ci.js'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /Security CI aprovado/);
});
