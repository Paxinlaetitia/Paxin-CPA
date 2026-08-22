'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const failures = [];
const args = process.argv.slice(2);

function option(name, fallback = '') {
  const index = args.indexOf(name);
  return index >= 0 ? String(args[index + 1] || '') : fallback;
}

function fail(message) { failures.push(message); }
function exists(relative) { return fs.existsSync(path.join(root, relative)); }
function read(relative) { return fs.readFileSync(path.join(root, relative), 'utf8'); }
function json(relative) { return JSON.parse(read(relative)); }
function walk(directory) {
  const full = path.join(root, directory);
  if (!fs.existsSync(full)) return [];
  return fs.readdirSync(full, { withFileTypes: true }).flatMap(entry => {
    const relative = path.posix.join(directory.replaceAll('\\', '/'), entry.name);
    return entry.isDirectory() ? walk(relative) : [relative];
  });
}

const mode = option('--mode', 'local');
if (!['local', 'release'].includes(mode)) fail('modo inválido; use local ou release');

for (let packageNumber = 1; packageNumber <= 9; packageNumber += 1) {
  const file = `docs/security/site-package-${packageNumber}.md`;
  if (!exists(file)) fail(`documentação ausente: ${file}`);
}

let gates;
try {
  gates = json('docs/security/release-gates.json');
  if (gates.schemaVersion !== 1 || gates.package !== 9 || gates.environment !== 'preview') {
    fail('release-gates.json possui versão, pacote ou ambiente inválido');
  }
  const ids = (gates.externalGates || []).map(gate => gate.id);
  if (ids.length < 10 || new Set(ids).size !== ids.length) fail('gates externos ausentes ou duplicados');
  if ((gates.externalGates || []).some(gate => !gate.required || !gate.label)) {
    fail('todos os gates externos devem ser obrigatórios e possuir rótulo');
  }
} catch (error) {
  fail(`release-gates.json inválido: ${error.message}`);
  gates = { externalGates: [] };
}

const migrations = walk('supabase/migrations').filter(file => /\/\d{8}_[a-z0-9_]+\.sql$/i.test(file)).sort();
const migrationNames = migrations.map(file => path.posix.basename(file));
if (migrations.length < 17) fail(`migrações esperadas: ao menos 17; encontradas: ${migrations.length}`);
if (new Set(migrationNames).size !== migrationNames.length) fail('nomes de migração duplicados');
const leastPrivilegeName = '20260831_database_least_privilege.sql';
const leastPrivilegeIndex = migrationNames.indexOf(leastPrivilegeName);
if (leastPrivilegeIndex < 0) fail('migração de menor privilégio ausente');
const reviewedRpcReplacements = new Map([
  ['20260902_device_portal_identity_dedup.sql', new Set(['paxinbot_list_my_devices','paxinbot_revoke_my_device'])]
]);
for (const file of migrations.slice(leastPrivilegeIndex + 1)) {
  const source = read(file);
  if (/\b(?:create\s+(?:or\s+replace\s+)?function|create\s+table|alter\s+default\s+privileges|grant\s|revoke\s)/i.test(source)) {
    const allowed = reviewedRpcReplacements.get(path.posix.basename(file));
    const declared = [...source.matchAll(/create\s+or\s+replace\s+function\s+public\.([a-z0-9_]+)\s*\(/gi)].map(match => match[1]);
    const broadening = /\b(?:create\s+table|alter\s+default\s+privileges|grant\s|revoke\s)/i.test(source)
      || !allowed || declared.length !== allowed.size || declared.some(name => !allowed.has(name));
    if (broadening) fail(`migração posterior ao fechamento de privilégios amplia a superfície: ${file}`);
  }
}

try { JSON.parse(read('vercel.json')); }
catch (error) { fail(`vercel.json inválido: ${error.message}`); }

const handlers = walk('api').filter(file => file.endsWith('.js') && file !== 'api/_paxinbot.js');
if (handlers.length > 11) fail(`orçamento conservador da Vercel excedido: ${handlers.length}/11 handlers`);
for (const handler of handlers) {
  if (!read(handler).includes('requireTrustedHost')) fail(`handler sem barreira de origem: ${handler}`);
}

const ignored = read('.vercelignore');
for (const entry of ['tests', 'docs', 'supabase', 'scripts', 'cloudflare', '.github', 'SECURITY.md']) {
  if (!new RegExp(`^${entry.replace('.', '\\.')}\\s*$`, 'm').test(ignored)) fail(`.vercelignore não exclui ${entry}`);
}

const cloudflareGuide = read('docs/security/cloudflare-activation-guide.md');
for (let stage = 0; stage <= 11; stage += 1) {
  if (!cloudflareGuide.includes(`Etapa ${stage}`)) fail(`guia Cloudflare sem Etapa ${stage}`);
}
if (!cloudflareGuide.includes('Registro de ativação')) fail('guia Cloudflare sem registro de ativação');

const workflow = read('.github/workflows/security-ci.yml');
if (!workflow.includes('node scripts/release-audit.js --mode local')) fail('Security CI não executa a auditoria local');
for (const match of workflow.matchAll(/^\s*uses:\s*([^\s#]+)/gm)) {
  if (!/@[0-9a-f]{40}$/i.test(match[1])) fail(`GitHub Action sem SHA imutável: ${match[1]}`);
}

const environmentExample = read('.env.example');
if (!/^PAXINBOT_ORIGIN_GATE_SECRET=\s*$/m.test(environmentExample)) {
  fail('barreira de origem deve permanecer desativada no exemplo');
}

if (mode === 'release') {
  const evidencePath = option('--evidence');
  if (!evidencePath) {
    fail('evidência obrigatória; use --evidence release-evidence.local.json');
  } else {
    const resolvedEvidence = path.resolve(root, evidencePath);
    let evidence;
    try { evidence = JSON.parse(fs.readFileSync(resolvedEvidence, 'utf8')); }
    catch (error) { fail(`arquivo de evidência inválido: ${error.message}`); }

    if (evidence) {
      if (evidence.schemaVersion !== 1 || evidence.environment !== 'preview') fail('evidência deve ser schema 1 e ambiente preview');
      if (!/^.{3,100}$/.test(String(evidence.approvedBy || ''))) fail('responsável pela aprovação ausente');

      let head = '';
      try { head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); }
      catch { fail('não foi possível identificar o commit atual'); }
      if (!/^[0-9a-f]{40}$/i.test(String(evidence.commit || '')) || evidence.commit !== head) {
        fail('evidência não corresponde ao commit atual');
      }

      const verifiedAt = Date.parse(evidence.verifiedAt);
      const age = Date.now() - verifiedAt;
      if (!Number.isFinite(verifiedAt) || age < -5 * 60 * 1000 || age > 72 * 60 * 60 * 1000) {
        fail('evidência deve ter sido verificada nas últimas 72 horas');
      }

      for (const gate of gates.externalGates.filter(item => item.required)) {
        const check = evidence.checks && evidence.checks[gate.id];
        if (!check || check.passed !== true || typeof check.evidence !== 'string' || check.evidence.trim().length < 8) {
          fail(`gate externo sem evidência aprovada: ${gate.id}`);
        }
      }

      try {
        const status = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim();
        if (status) fail('árvore de trabalho não está limpa');
      } catch { fail('não foi possível verificar a árvore de trabalho'); }
    }
  }
}

if (failures.length) {
  for (const message of failures) process.stderr.write(`ERRO: ${message}\n`);
  process.exit(1);
}

if (mode === 'local') {
  process.stdout.write(`AUDITORIA_LOCAL=APROVADA GATES_EXTERNOS=PENDENTES(${gates.externalGates.length})\n`);
} else {
  process.stdout.write(`AUDITORIA_DE_LIBERACAO=APROVADA GATES_EXTERNOS=${gates.externalGates.length}\n`);
}
