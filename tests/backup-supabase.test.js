'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const root = path.join(__dirname, '..');
const script = fs.readFileSync(path.join(root, 'scripts/backup-supabase.ps1'), 'utf8');
const launcher = fs.readFileSync(path.join(root, 'Backup-Supabase.cmd'), 'utf8');

test('backup launcher prefills only the user-supplied connection identifiers', () => {
  assert.match(launcher, /-DatabaseHost "aws-0-us-east-1\.pooler\.supabase\.com"/);
  assert.match(launcher, /-DatabaseUser "postgres\.drkyjgnctbxmupbfarnj"/);
  assert.doesNotMatch(launcher, /PGPASSWORD|postgresql:\/\/|-(?:Database)?Password/i);
  assert.match(launcher, /--certificate/);
  assert.match(launcher, /RootCertificatePath/);
  assert.ok(script.indexOf('Assert-BackupConnection $DatabaseHost $DatabaseUser') < script.indexOf('if ($CheckOnly)'));
  assert.ok(script.indexOf("Ctrl+C cancela.") < script.indexOf("Read-Host 'Senha do BANCO"));
  assert.ok(script.includes("certificates\\supabase-ca.crt"));
  assert.match(script, /Read-PublicRootCertificate/);
});

test('double-click launcher works without PowerShell on PATH and never prompts in check mode', { skip: process.platform !== 'win32' }, () => {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.toLowerCase() === 'path') delete environment[name];
  }
  environment.PATH = path.join(process.env.SystemRoot, 'System32');
  const check = spawnSync(path.join(process.env.SystemRoot, 'System32/cmd.exe'),
    ['/d', '/c', 'Backup-Supabase.cmd', '--check'], {
      cwd: root, env: environment, encoding: 'utf8', windowsHide: true, timeout: 30000
    });
  assert.equal(check.status, 0, check.stderr || check.stdout);
  const result = JSON.parse(check.stdout);
  assert.equal(result.toolsReady, true);
  assert.equal(result.credentialRequested, false);
  assert.equal(result.databaseTouched, false);
  assert.equal(result.certificateReady, true);
  assert.match(result.certificatePath, /supabase-ca\.crt$/i);
});

test('prepare-only does not require a certificate and explicit missing CA fails safely', () => {
  assert.ok(script.indexOf("if ($PrepareToolsOnly)") < script.lastIndexOf('Assert-PublicRootCertificate $RootCertificatePath'));
  assert.match(script, /Certificado CA ausente no caminho configurado/);
  assert.ok(script.includes('PFX/P12 nao sao aceitos'));
});

test('tools and output use the Windows known folder even when LOCALAPPDATA differs', { skip: process.platform !== 'win32' }, () => {
  const check = spawnSync(path.join(process.env.SystemRoot, 'System32/cmd.exe'),
    ['/d', '/c', 'Backup-Supabase.cmd', '--check'], {
      cwd: root, env: { ...process.env, LOCALAPPDATA: path.join(os.tmpdir(), 'not-the-windows-known-folder') },
      encoding: 'utf8', windowsHide: true, timeout: 30000
    });
  assert.equal(check.status, 0, check.stderr || check.stdout);
  const result = JSON.parse(check.stdout);
  assert.equal(result.toolsReady, true);
  assert.equal(result.credentialRequested, false);
  assert.equal(result.databaseTouched, false);
  assert.equal(result.certificateReady, true);
  assert.ok(fs.existsSync(path.join(result.toolsDirectory, 'pg_dump.exe')));
  assert.ok(!result.outputRoot.includes('not-the-windows-known-folder'));
  assert.ok(!result.toolsDirectory.includes('not-the-windows-known-folder'));
});

test('launcher keeps early failures visible and preserves their exit code without asking for credentials', { skip: process.platform !== 'win32' }, () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'paxin launcher missing script '));
  const fixtureLauncher = path.join(fixture, 'Backup-Supabase.cmd');
  // Only a generated copy of the launcher: the referenced .ps1 intentionally does not exist.
  fs.copyFileSync(path.join(root, 'Backup-Supabase.cmd'), fixtureLauncher);
  const cmd = path.join(process.env.SystemRoot, 'System32/cmd.exe');
  try {
    const interactive = spawnSync(cmd, ['/d', '/c', 'Backup-Supabase.cmd'], {
      cwd: fixture, input: '\r\n', encoding: 'utf8', windowsHide: true, timeout: 15000
    });
    assert.equal(interactive.error, undefined);
    assert.notEqual(interactive.status, 0);
    assert.match(interactive.stdout, /Falha no backup ou na inicializacao/);
    assert.match(interactive.stdout, /A janela ficara aberta/);
    assert.doesNotMatch(interactive.stdout, /Senha do BANCO|Conferindo conexao TLS|Exportacao concluida/);
    const check = spawnSync(cmd, ['/d', '/c', 'Backup-Supabase.cmd', '--check'], {
      cwd: fixture, encoding: 'utf8', windowsHide: true, timeout: 15000
    });
    assert.equal(check.error, undefined);
    assert.equal(check.status, interactive.status);
    assert.doesNotMatch(check.stdout, /A janela ficara aberta/);
  } finally {
    fs.unlinkSync(fixtureLauncher);
    fs.rmdirSync(fixture); // Only this empty test directory; no recursive deletion.
  }
});

test('backup uses explicit TLS, restricted local output and no credential command arguments', () => {
  assert.match(script, /PGSSLMODE = 'verify-full'/);
  assert.match(script, /PGGSSENCMODE = 'disable'/);
  assert.match(script, /PGOPTIONS = '-c default_transaction_read_only=on'/);
  assert.match(script, /-AsSecureString/);
  assert.match(script, /\$info\.ArgumentList\.Add/);
  assert.match(script, /SetAccessRuleProtection\(\$true, \$false\)/);
  assert.match(script, /PAXINBOT\\DatabaseBackups/);
  assert.match(script, /Assert-PublicRootCertificate \$RootCertificatePath/);
  assert.match(script, /certificateReady = \$true/);
  assert.doesNotMatch(script, /--clean|--no-privileges|--enable-row-security|sslmode=require|Start-Transcript/i);
});

test('missing tool preparation pins the official package and runs before the password prompt', () => {
  assert.match(script, /https:\/\/sbp\.enterprisedb\.com\/getfile\.jsp\?fileid=1260488/);
  assert.match(script, /59F8CE701C63C2ED623C665A5E51B3EF6F2E37CCF837B68FFEED0742D0AE6ABD/);
  assert.match(script, /\$missingTools.Count -gt 0 -and -not \$CheckOnly/);
  assert.ok(script.indexOf('Install-BackupTools -ToolsDirectory $toolsDirectory') < script.indexOf("Read-Host 'Senha do BANCO"));
  assert.match(script, /ExtractToFile\(\$item.Entry, \$item.Path, \$false\)/);
  assert.doesNotMatch(script, /SkipCertificateCheck|Set-MpPreference|Add-MpPreference|ExecutionPolicy Bypass/);
});

test('fresh portable preparation validates hashes, runs clients and refuses overwrite', { skip: process.platform !== 'win32' }, t => {
  const check = spawnSync('pwsh.exe', ['-NoProfile', '-File', path.join(__dirname, 'backup-tools-install-checks.ps1')],
    { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  assert.equal(check.status, 0, check.stderr || check.stdout);
  const result = JSON.parse(check.stdout);
  if (result.skipped) return t.skip(result.reason);
  assert.equal(result.checksPassed, 5);
  assert.equal(result.liveDatabaseTouched, false);
  assert.equal(result.downloaded, false);
});

test('backup validates archive offline and discloses limits without modifying production', () => {
  assert.match(script, /'--roles-only', '--no-role-passwords'/);
  assert.match(script, /@\('--file=NUL', \$archive\)/);
  assert.match(script, /restoreTested = \$false/);
  assert.match(script, /INCOMPLETE\.json/);
  assert.match(script, /Get-FileHash.*SHA256/);
  assert.match(script, /if \(\$started -and -not \$process.HasExited\)/);
  assert.match(script, /exit \$backupExitCode/);
  assert.ok(script.indexOf("@('--file=NUL'") < script.indexOf("'BACKUP-MANIFEST.json'"));
});

test('PowerShell backup helpers pass local security checks', { skip: process.platform !== 'win32' }, () => {
  const check = spawnSync('pwsh.exe', ['-NoProfile', '-File', path.join(__dirname, 'backup-supabase-checks.ps1')],
    { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  assert.equal(check.status, 0, check.stderr);
  const result = JSON.parse(check.stdout);
  assert.equal(result.checksPassed, 15);
  assert.equal(result.liveDatabaseTouched, false);
});
