#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/backup-supabase.ps1') -DefinitionsOnly
$localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$archive = Join-Path $localData 'PAXINBOT\BackupTools\postgresql-18.6\postgresql-binaries.zip'
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    [pscustomobject]@{ skipped = $true; reason = 'No verified offline test package'; liveDatabaseTouched = $false } | ConvertTo-Json -Compress
    return
}
$fixture = New-PrivateBackupDirectory (Join-Path ([IO.Path]::GetTempPath()) ('paxin-tools-install-test-' + [Guid]::NewGuid().ToString('N')))
$bin = Join-Path $fixture 'bin'
$checks = 0
try {
    Install-BackupTools -ToolsDirectory $bin -ArchivePath $archive 6>$null
    foreach ($tool in @('pg_dump', 'pg_dumpall', 'pg_restore', 'psql')) {
        $version = Invoke-BackupTool (Join-Path $bin ($tool + '.exe')) @('--version') @{} $null 15
        if ($version -notmatch 'PostgreSQL\) 18\.6') { throw 'Freshly prepared client did not run.' }
    }
    $checks++
    if (-not (Get-Acl -LiteralPath $bin).AreAccessRulesProtected) { throw 'Expected private tool directory.' }
    $checks++
    $before = @(Get-ChildItem -LiteralPath $bin -File | Sort-Object Name | ForEach-Object {
        $_.Name + ':' + $_.LastWriteTimeUtc.Ticks + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    Install-BackupTools -ToolsDirectory $bin -ArchivePath $archive 6>$null
    $after = @(Get-ChildItem -LiteralPath $bin -File | Sort-Object Name | ForEach-Object {
        $_.Name + ':' + $_.LastWriteTimeUtc.Ticks + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    if (Compare-Object $before $after) { throw 'Existing files were changed.' }
    $checks++
    $invalidArchive = Join-Path $fixture 'invalid-package.zip'
    [IO.File]::WriteAllText($invalidArchive, 'INERT TEST PACKAGE')
    $rejected = $false
    try { Install-BackupTools -ToolsDirectory (Join-Path $fixture 'rejected') -ArchivePath $invalidArchive 6>$null }
    catch { $rejected = $_.Exception.Message -like '*Pacote PostgreSQL incompativel*' }
    if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $fixture 'rejected'))) { throw 'Invalid archive was not refused before extraction.' }
    $checks++
    $testClient = Join-Path $bin 'pg_dump.exe'
    [IO.File]::WriteAllText($testClient, 'INERT TEST FILE: MUST NOT BE OVERWRITTEN')
    $rejected = $false
    try { Install-BackupTools -ToolsDirectory $bin -ArchivePath $archive 6>$null }
    catch { $rejected = $_.Exception.Message -like '*Arquivo existente incompativel*' }
    if (-not $rejected -or [IO.File]::ReadAllText($testClient) -ne 'INERT TEST FILE: MUST NOT BE OVERWRITTEN') {
        throw 'Mismatched existing file was not preserved.'
    }
    $checks++
} finally {
    # Delete only files created in this unique test directory; no recursion or user backups.
    foreach ($directory in @($bin, $fixture)) {
        if (Test-Path -LiteralPath $directory) {
            foreach ($file in Get-ChildItem -LiteralPath $directory -File) {
                if (-not $file.FullName.StartsWith($fixture + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup path.' }
                Remove-Item -LiteralPath $file.FullName
            }
            [IO.Directory]::Delete($directory, $false)
        }
    }
}
[pscustomobject]@{ checksPassed = $checks; liveDatabaseTouched = $false; downloaded = $false } | ConvertTo-Json -Compress
