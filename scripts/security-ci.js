'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const failures = [];
const note = message => process.stdout.write(`${message}\n`);
const fail = message => failures.push(message);

function trackedFiles() {
  return execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: root })
    .toString('utf8').split('\0').filter(Boolean);
}

function textOf(relative) {
  const value = fs.readFileSync(path.join(root, relative));
  if (value.includes(0)) return null;
  return value.toString('utf8');
}

const files = trackedFiles();

for (const file of files) {
  const normalized = file.replaceAll('\\', '/');
  if (/(^|\/)\.env(?:\.|$)/.test(normalized) && normalized !== '.env.example') {
    fail(`arquivo de ambiente rastreado: ${normalized}`);
  }
}

const secretPatterns = [
  ['chave secreta Supabase', /sb_secret_[A-Za-z0-9_-]{16,}/g],
  ['JWT persistido', /eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g],
  ['token Mercado Pago', /APP_USR-[A-Za-z0-9_-]{20,}/g],
  ['chave Resend', /\bre_[A-Za-z0-9_-]{20,}\b/g],
  ['token GitHub', /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g],
  ['chave privada', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['conexão PostgreSQL com senha', /postgres(?:ql)?:\/\/[^\s/:]+:[^\s@]+@[^\s]+/gi]
];
const documentedPlaceholders = new Set([
  'sb_secret_replace_with_your_server_only_key',
  'sb_secret_unique_backend_credential',
  're_replace_with_your_sending_only_key'
]);

for (const file of files) {
  const full = path.join(root, file);
  if (!fs.existsSync(full) || fs.statSync(full).size > 2_000_000) continue;
  const text = textOf(file); if (text === null) continue;
  for (const [label, pattern] of secretPatterns) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      if (!documentedPlaceholders.has(match[0])) fail(`${label} encontrado em ${file}`);
    }
  }
}

const javascript = files.filter(file => /\.(?:c|m)?js$/.test(file));
for (const file of javascript) {
  const checked = spawnSync(process.execPath, ['--check', file], { cwd: root, encoding: 'utf8' });
  if (checked.status !== 0) fail(`JavaScript inválido em ${file}: ${String(checked.stderr || checked.stdout).trim()}`);
}

const apiHandlers = javascript.filter(file => file.startsWith('api/') && file.endsWith('.js'));
if (apiHandlers.length > 12) fail(`Vercel Hobby aceita 12 funções; foram encontradas ${apiHandlers.length}`);

try { JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8')); }
catch (error) { fail(`vercel.json inválido: ${error.message}`); }

const lockNames = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];
for (const manifest of files.filter(file => path.basename(file) === 'package.json')) {
  const directory = path.posix.dirname(manifest);
  const prefix = directory === '.' ? '' : `${directory}/`;
  if (!lockNames.some(lock => files.includes(`${prefix}${lock}`))) fail(`manifesto sem lockfile: ${manifest}`);
}

for (const workflow of files.filter(file => /^\.github\/workflows\/.*\.ya?ml$/.test(file))) {
  const text = textOf(workflow) || '';
  for (const match of text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)) {
    const reference = match[1];
    if (reference.startsWith('./')) continue;
    if (!/@[0-9a-f]{40}$/i.test(reference)) fail(`action sem SHA imutável em ${workflow}: ${reference}`);
  }
}

if (failures.length) {
  for (const failure of failures) process.stderr.write(`ERRO: ${failure}\n`);
  process.exit(1);
}

note(`Security CI aprovado: ${files.length} arquivos, ${javascript.length} JavaScripts, ${apiHandlers.length}/12 funções Vercel.`);
