'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('local release audit approves source but reports external gates pending', () => {
  const result = spawnSync(process.execPath, ['scripts/release-audit.js', '--mode', 'local'], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /AUDITORIA_LOCAL=APROVADA/);
  assert.match(result.stdout, /GATES_EXTERNOS=PENDENTES\(12\)/);
});

test('release audit fails closed without external evidence', () => {
  const result = spawnSync(process.execPath, ['scripts/release-audit.js', '--mode', 'release'], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /evidência obrigatória/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /sb_secret_|APP_USR-|BEGIN PRIVATE KEY/);
});

test('evidence template is safe, incomplete and covers every external gate', () => {
  const gates = JSON.parse(read('docs/security/release-gates.json'));
  const example = JSON.parse(read('docs/security/release-evidence.example.json'));
  assert.equal(gates.externalGates.length, 12);
  assert.deepEqual(Object.keys(example.checks).sort(), gates.externalGates.map(gate => gate.id).sort());
  for (const check of Object.values(example.checks)) {
    assert.equal(check.passed, false);
    assert.equal(check.evidence, '');
  }
  assert.doesNotMatch(JSON.stringify(example), /sb_secret_|APP_USR-|BEGIN PRIVATE KEY/);
});

test('all nine security packages and the explicit production gate are documented', () => {
  for (let packageNumber = 1; packageNumber <= 9; packageNumber += 1) {
    assert.equal(fs.existsSync(path.join(root, `docs/security/site-package-${packageNumber}.md`)), true);
  }
  const checklist = read('docs/security/release-checklist.md');
  assert.match(checklist, /NÃO APROVADO PARA PRODUÇÃO/);
  assert.match(checklist, /Um teste local\s+não comprova/);
  assert.match(checklist, /somente então promover o mesmo commit para produção/);
});
