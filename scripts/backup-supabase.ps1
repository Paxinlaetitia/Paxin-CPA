#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$DefinitionsOnly,
    [switch]$PrepareToolsOnly,
    [string]$DatabaseHost = '',
    [string]$DatabaseUser = '',
    [string]$RootCertificatePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-BackupConnection {
    param([string]$DatabaseHost, [string]$DatabaseUser)
    # Accept only Supabase session-pooler hosts, never a URL containing a password.
    if ($DatabaseHost -cnotmatch '^aws-[0-9]+-[a-z0-9-]+\.pooler\.supabase\.com$') {
        throw 'Copie somente o Host de Connect > Session pooler, sem URL ou senha.'
    }
    if ($DatabaseUser -cnotmatch '^postgres\.[a-z]{20}$') {
        throw 'Copie o User de Connect > Session pooler (postgres.referencia-do-projeto).'
    }
}

function Assert-NoReparsePoint {
    param([string]$TargetPath)
    $cursor = [IO.Path]::GetFullPath($TargetPath)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Pasta com link/junction nao permitida para o backup.'
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function New-PrivateBackupDirectory {
    param([string]$DirectoryPath)
    Assert-NoReparsePoint $DirectoryPath
    if (Test-Path -LiteralPath $DirectoryPath) { throw 'Pasta ja existe; nenhum backup sera sobrescrito.' }
    $directory = [IO.Directory]::CreateDirectory($DirectoryPath)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $directory.FullName -AclObject $acl
    $actualAcl = Get-Acl -LiteralPath $directory.FullName
    if (-not $actualAcl.AreAccessRulesProtected) { throw 'Falha ao restringir acesso ao backup.' }
    $allowed = @($sid.Value, 'S-1-5-18')
    foreach ($rule in $actualAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) {
            throw 'Permissao inesperada na pasta do backup.'
        }
    }
    return $directory.FullName
}

function Export-TrustedRoots {
    param([string]$Destination, [string]$AdditionalCertificatePath = '')
    # Public CA certificates only: never exports a private key or a user certificate.
    $certificates = @(Get-ChildItem Cert:\CurrentUser\Root, Cert:\LocalMachine\Root |
        Sort-Object Thumbprint -Unique)
    if ($AdditionalCertificatePath) {
        Assert-NoReparsePoint $AdditionalCertificatePath
        $certificateText = [IO.File]::ReadAllText($AdditionalCertificatePath)
        if ($certificateText -match 'PRIVATE KEY') { throw 'Informe somente o certificado publico da CA.' }
        $additionalCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($certificateText)
        try {
            $constraints = @($additionalCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
            if ($constraints.Count -ne 1 -or -not $constraints[0].CertificateAuthority -or
                $additionalCertificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
                $additionalCertificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
                throw 'Certificado CA invalido ou fora da validade. Baixe o certificado atual no Supabase.'
            }
            $certificates += [Security.Cryptography.X509Certificates.X509Certificate2]::new($additionalCertificate.RawData)
        } finally { $additionalCertificate.Dispose() }
    }
    if ($certificates.Count -eq 0) { throw 'Nenhuma autoridade certificadora confiavel encontrada.' }
    $pem = foreach ($certificate in $certificates) {
        "-----BEGIN CERTIFICATE-----`n" +
            [Convert]::ToBase64String($certificate.RawData, [Base64FormattingOptions]::InsertLineBreaks) +
            "`n-----END CERTIFICATE-----`n"
    }
    [IO.File]::WriteAllText($Destination, ($pem -join "`n"), [Text.UTF8Encoding]::new($false))
}

function Install-BackupTools {
    param([string]$ToolsDirectory, [string]$ArchivePath = '')
    $expectedArchiveHash = '59F8CE701C63C2ED623C665A5E51B3EF6F2E37CCF837B68FFEED0742D0AE6ABD'
    $downloadUrl = 'https://sbp.enterprisedb.com/getfile.jsp?fileid=1260488'
    if (-not [IO.Path]::IsPathFullyQualified($ToolsDirectory)) { throw 'Destino de ferramentas invalido.' }
    $destination = [IO.Path]::GetFullPath($ToolsDirectory)
    Assert-NoReparsePoint $destination
    if (-not $ArchivePath) {
        $packageRoot = [IO.Path]::GetDirectoryName($destination)
        Assert-NoReparsePoint $packageRoot
        if (-not (Test-Path -LiteralPath $packageRoot)) { [void](New-PrivateBackupDirectory $packageRoot) }
        $ArchivePath = Join-Path $packageRoot 'postgresql-binaries.zip'
        Assert-NoReparsePoint $ArchivePath
        if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
            # A unique download is preserved on failure; no existing package is overwritten.
            $partial = Join-Path $packageRoot ('download-' + [Guid]::NewGuid().ToString('N') + '.partial')
            Write-Host 'Baixando ferramentas PostgreSQL 18.6 da EDB (aproximadamente 344 MB)...'
            Invoke-WebRequest -Uri $downloadUrl -OutFile $partial -TimeoutSec 600 -MaximumRedirection 5
            if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $expectedArchiveHash) {
                throw 'Integridade do download incorreta. Nada sera extraido ou executado; preserve o arquivo parcial.'
            }
            # Both exact paths are in the checked package directory; Move refuses overwrite.
            [IO.File]::Move($partial, $ArchivePath)
        }
    }
    Assert-NoReparsePoint $ArchivePath
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash -ne $expectedArchiveHash) {
        throw 'Pacote PostgreSQL incompativel. Nenhum arquivo existente sera substituido.'
    }
    Write-Host 'Pacote conferido. Preparando somente os clientes e suas bibliotecas...'
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entries = @($zip.Entries | Where-Object {
            $_.FullName -cmatch '^pgsql/bin/(?:pg_dump\.exe|pg_dumpall\.exe|pg_restore\.exe|psql\.exe|[A-Za-z0-9_.-]+\.dll)$'
        })
        foreach ($required in @('pg_dump.exe', 'pg_dumpall.exe', 'pg_restore.exe', 'psql.exe')) {
            if (@($entries | Where-Object Name -CEQ $required).Count -ne 1) { throw 'Pacote sem os clientes esperados.' }
        }
        if (@($entries.Name | Select-Object -Unique).Count -ne $entries.Count) { throw 'Pacote com nomes duplicados.' }
        $validated = foreach ($entry in $entries) {
            $target = [IO.Path]::GetFullPath((Join-Path $destination $entry.Name))
            if (-not $target.StartsWith($destination + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Destino de extracao fora da pasta permitida.'
            }
            Assert-NoReparsePoint $target
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
            finally { $stream.Dispose(); $sha.Dispose() }
            if (Test-Path -LiteralPath $target) {
                if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
                    (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $hash) {
                    throw "Arquivo existente incompativel: $($entry.Name). Preservado; nao sera sobrescrito."
                }
            }
            [pscustomobject]@{ Entry = $entry; Path = $target; Hash = $hash }
        }
        # Check every existing file before any extraction, then write only absent files.
        if (-not (Test-Path -LiteralPath $destination)) { [void](New-PrivateBackupDirectory $destination) }
        foreach ($item in $validated) {
            if (-not (Test-Path -LiteralPath $item.Path)) {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($item.Entry, $item.Path, $false)
            }
            if ((Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash -ne $item.Hash) {
                throw 'Falha de integridade apos extracao. Nao execute as ferramentas.'
            }
        }
    } finally { $zip.Dispose() }
    Write-Host 'Ferramentas preparadas e verificadas neste Windows. Nenhum servidor foi instalado.'
}

function Invoke-BackupTool {
    param([string]$Executable, [string[]]$ToolArguments, [hashtable]$ConnectionEnvironment,
        [Security.SecureString]$Password, [int]$TimeoutSeconds = 1800)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $ToolArguments) { $info.ArgumentList.Add($argument) }
    foreach ($key in @($info.Environment.Keys)) {
        if ($key -like 'PG*') { [void]$info.Environment.Remove($key) }
    }
    foreach ($key in $ConnectionEnvironment.Keys) { $info.Environment[$key] = $ConnectionEnvironment[$key] }
    $pointer = [IntPtr]::Zero
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $started = $false
    try {
        if ($null -ne $Password) {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            # Secret exists only in this child process environment; never in CLI arguments/files.
            $info.Environment['PGPASSWORD'] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        }
        [void]$process.Start()
        $started = $true
        [void]$info.Environment.Remove('PGPASSWORD')
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            $pointer = [IntPtr]::Zero
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'Tempo limite excedido; backup NAO concluido.'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            # Never echo raw tool diagnostics, which could contain identifiers or database text.
            $reason = switch -Regex ($stderr) {
                'password authentication failed|no password supplied' { 'Autenticacao recusada. Confira a senha do banco.'; break }
                'certificate|SSL error|TLS' { 'Falha TLS/certificado. Nao desative a verificacao.'; break }
                'permission denied|must be superuser' { 'Permissao insuficiente. Nao libere acesso publico para contornar.'; break }
                'server version mismatch' { 'Cliente PostgreSQL incompativel com a versao do servidor.'; break }
                'could not translate|could not connect|timeout|Tenant or user not found' { 'Confira Host/User do Session pooler e a conexao de rede.'; break }
                default { 'A ferramenta recusou a operacao. Backup NAO concluido.' }
            }
            throw $reason
        }
        return $stdout
    } finally {
        [void]$info.Environment.Remove('PGPASSWORD')
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $process.Dispose()
    }
}

if ($DefinitionsOnly) { return }
if (-not $IsWindows) { throw 'Este procedimento foi preparado para Windows.' }
if ($DatabaseHost -or $DatabaseUser) {
    $DatabaseHost = $DatabaseHost.Trim().ToLowerInvariant()
    $DatabaseUser = $DatabaseUser.Trim()
    Assert-BackupConnection $DatabaseHost $DatabaseUser
}
# Explorer and app-launched shells may inherit different environment variables.
# Resolve the real Windows known folder, not the shell's LOCALAPPDATA value.
$localDataDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrWhiteSpace($localDataDirectory) -or -not [IO.Path]::IsPathFullyQualified($localDataDirectory)) {
    throw 'Nao foi possivel localizar a pasta local do usuario Windows. Nenhum backup foi iniciado.'
}
$toolsDirectory = Join-Path $localDataDirectory 'PAXINBOT\BackupTools\postgresql-18.6\bin'
$backupRoot = Join-Path $localDataDirectory 'PAXINBOT\DatabaseBackups'
if (-not $CheckOnly) { Write-Host "Ferramentas: $toolsDirectory" }
Assert-NoReparsePoint $toolsDirectory
$requiredExecutables = @('pg_dump', 'pg_dumpall', 'pg_restore', 'psql')
$missingTools = @($requiredExecutables | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $toolsDirectory ($_ + '.exe')) -PathType Leaf)
})
if ($missingTools.Count -gt 0 -and -not $CheckOnly) {
    Install-BackupTools -ToolsDirectory $toolsDirectory
}
foreach ($tool in $requiredExecutables) {
    $executable = Join-Path $toolsDirectory ($tool + '.exe')
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Ferramenta ausente: $tool. Caminho verificado: $executable. Nenhuma conexao ao banco foi iniciada."
    }
    $version = Invoke-BackupTool $executable @('--version') @{} $null 15
    if ($version -notmatch 'PostgreSQL\) 18\.6\b') { throw 'Versao inesperada das ferramentas.' }
}
if ($CheckOnly) {
    [pscustomobject]@{ toolsReady = $true; credentialRequested = $false; databaseTouched = $false;
        toolsDirectory = $toolsDirectory; outputRoot = $backupRoot } | ConvertTo-Json
    return
}
if ($PrepareToolsOnly) {
    Write-Host 'PREPARACAO CONCLUIDA. Agora abra o iniciador normalmente para fazer o backup.'
    return
}

if (-not $RootCertificatePath) {
    $RootCertificatePath = Join-Path $localDataDirectory 'PAXINBOT\BackupTools\supabase-ca.crt'
}
Assert-NoReparsePoint $RootCertificatePath
if (-not (Test-Path -LiteralPath $RootCertificatePath -PathType Leaf)) {
    throw 'Certificado CA ausente. Baixe no painel Supabase e configure RootCertificatePath. Nao desative TLS.'
}

$Host.UI.RawUI.WindowTitle = 'PAXINBOT - backup local do Supabase'
Write-Host 'Backup manual gratuito. Nao aplica SQL nem altera os dados do banco.'
Write-Host 'No Supabase abra Connect > Session pooler, porta 5432.'
if (-not $databaseHost -and -not $databaseUser) {
    Write-Host 'Copie os campos Host e User separadamente. NAO cole uma URL com senha.'
    $databaseHost = (Read-Host 'Host').Trim().ToLowerInvariant()
    $databaseUser = (Read-Host 'User (postgres.referencia)').Trim()
}
Assert-BackupConnection $databaseHost $databaseUser
Write-Host "Projeto: $($databaseUser.Substring(9))"
Write-Host "Host: $databaseHost (porta 5432)"
Write-Host 'Confira o projeto antes de digitar a senha. Ctrl+C cancela.'
$databasePassword = Read-Host 'Senha do BANCO (oculta; nao e a senha de login no site)' -AsSecureString
if ($databasePassword.Length -eq 0) { $databasePassword.Dispose(); throw 'Senha vazia. Nada foi iniciado.' }
$runDirectory = $null
$stage = 'preparation'
$backupExitCode = 0
try {
    $runName = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
    $runDirectory = New-PrivateBackupDirectory (Join-Path $backupRoot $runName)
    $caFile = Join-Path $runDirectory 'trusted-roots.pem'
    Export-TrustedRoots $caFile -AdditionalCertificatePath $RootCertificatePath
    $connection = @{
        PGHOST = $databaseHost; PGPORT = '5432'; PGUSER = $databaseUser; PGDATABASE = 'postgres'
        PGSSLMODE = 'verify-full'; PGSSLROOTCERT = $caFile; PGCONNECT_TIMEOUT = '20'; PGGSSENCMODE = 'disable'
        PGAPPNAME = 'paxinbot-manual-backup'; PGCLIENTENCODING = 'UTF8'
        PGOPTIONS = '-c default_transaction_read_only=on'
        PGPASSFILE = (Join-Path $runDirectory 'unused-password-file')
    }
    $stage = 'connection'
    Write-Host 'Conferindo conexao TLS e versao...'
    $serverVersion = (Invoke-BackupTool (Join-Path $toolsDirectory 'psql.exe') @(
        '-X', '-w', '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'show server_version_num'
    ) $connection $databasePassword 40).Trim()
    if ($serverVersion -notmatch '^\d{6}$' -or [int]$serverVersion -ge 190000) { throw 'Versao do servidor nao suportada por estas ferramentas.' }
    $stage = 'database-dump'
    Write-Host 'Exportando estrutura, dados, proprietarios, RLS e permissoes...'
    $archive = Join-Path $runDirectory 'database.dump'
    [void](Invoke-BackupTool (Join-Path $toolsDirectory 'pg_dump.exe') @(
        '--no-password', '--format=custom', '--quote-all-identifiers', '--lock-wait-timeout=10000', '--file', $archive
    ) $connection $databasePassword)
    $stage = 'roles-dump'
    Write-Host 'Exportando roles sem suas senhas...'
    $rolesFile = Join-Path $runDirectory 'roles.sql'
    [void](Invoke-BackupTool (Join-Path $toolsDirectory 'pg_dumpall.exe') @(
        '--no-password', '--roles-only', '--no-role-passwords', '--quote-all-identifiers', '--database=postgres', '--file', $rolesFile
    ) $connection $databasePassword)
    $databasePassword.Dispose()
    $databasePassword = $null
    $stage = 'archive-validation'
    Write-Host 'Verificando o arquivo local, sem restaurar no banco...'
    $toc = Invoke-BackupTool (Join-Path $toolsDirectory 'pg_restore.exe') @('--list', $archive) @{} $null
    if ($toc -notmatch 'TABLE DATA public ' -or $toc -notmatch 'TABLE DATA auth users ') {
        throw 'Conteudo esperado do app/auth ausente no arquivo. Backup NAO validado.'
    }
    [IO.File]::WriteAllText((Join-Path $runDirectory 'archive-contents.txt'), $toc, [Text.UTF8Encoding]::new($false))
    # Decode every archive entry to the Windows null device, never to a database.
    [void](Invoke-BackupTool (Join-Path $toolsDirectory 'pg_restore.exe') @('--file=NUL', $archive) @{} $null)
    foreach ($file in @($archive, $rolesFile)) {
        if ((Get-Item -LiteralPath $file).Length -le 0) { throw 'Arquivo de backup vazio.' }
    }
    $files = foreach ($name in @('database.dump', 'roles.sql', 'archive-contents.txt')) {
        $file = Join-Path $runDirectory $name
        [ordered]@{ name = $name; bytes = (Get-Item -LiteralPath $file).Length; sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash }
    }
    $manifest = [ordered]@{
        status = 'exported-and-archive-checked'; createdAtUtc = [DateTime]::UtcNow.ToString('o')
        projectRef = $databaseUser.Substring(9); serverVersionNum = $serverVersion
        clientVersion = '18.6'; files = @($files); restoreTested = $false
        limitations = @('No Storage/R2 object files', 'No Vercel/Cloudflare environment secrets', 'No Vault root encryption key or platform settings',
            'No role passwords', 'Not an offsite copy', 'Restricted Windows ACL, not file encryption',
            'Roles exported separately from database snapshot', 'Raw dump includes managed schemas: selective restore review required',
            'PostgreSQL 18 dump output may need adaptation for older target majors', 'Restore must be rehearsed in a separate project')
    }
    [IO.File]::WriteAllText((Join-Path $runDirectory 'BACKUP-MANIFEST.json'), ($manifest | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Host "Exportacao concluida e arquivo conferido: $runDirectory" -ForegroundColor Green
    Write-Host 'A restauracao ainda nao foi ensaiada. Nao publique nem compartilhe os arquivos.'
} catch {
    $backupExitCode = 1
    if ($null -ne $runDirectory) {
        $failure = @{ status = 'incomplete'; stage = $stage; createdAtUtc = [DateTime]::UtcNow.ToString('o') }
        [IO.File]::WriteAllText((Join-Path $runDirectory 'INCOMPLETE.json'), ($failure | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    Write-Host 'Backup NAO concluido. Nao execute o SQL de alteracao.' -ForegroundColor Red
    # Only our sanitized messages should be shown; never dump ErrorRecord/stack/env.
    Write-Host "Etapa: $stage. $($_.Exception.Message)"
} finally {
    if ($null -ne $databasePassword) { $databasePassword.Dispose() }
}
# The batch launcher owns the final pause, including failures before this script loads.
exit $backupExitCode
