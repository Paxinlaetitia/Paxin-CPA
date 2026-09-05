#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/backup-supabase.ps1') -DefinitionsOnly
function Assert-Condition([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Test failed: $Label" }
}
$checks = 0
Assert-BackupConnection 'aws-0-us-east-1.pooler.supabase.com' 'postgres.aaaaaaaaaaaaaaaaaaaa'
$checks++
foreach ($invalid in @('https://example.com', 'aws-0-us-east-1.pooler.supabase.com.evil.test',
    'localhost', 'postgresql://example.invalid/postgres')) {
    $rejected = $false
    try { Assert-BackupConnection $invalid 'postgres.aaaaaaaaaaaaaaaaaaaa' } catch { $rejected = $true }
    Assert-Condition $rejected 'reject non-Supabase host/credential URL'
    $checks++
}
$rejected = $false
try { Assert-BackupConnection 'aws-0-us-east-1.pooler.supabase.com' 'postgres;bad' } catch { $rejected = $true }
Assert-Condition $rejected 'reject non-project user'
$checks++
$testDirectory = Join-Path $env:TEMP ('paxin-backup-test-' + [Guid]::NewGuid().ToString('N'))
$privateDirectory = New-PrivateBackupDirectory $testDirectory
Assert-Condition ((Get-Acl -LiteralPath $privateDirectory).AreAccessRulesProtected) 'restricted ACL'
$checks++
$rejected = $false
try { New-PrivateBackupDirectory $testDirectory | Out-Null } catch { $rejected = $true }
Assert-Condition $rejected 'refuse existing directory'
$checks++
$rootCertFile = Join-Path $privateDirectory 'ca.pem'
Export-TrustedRoots $rootCertFile
$pem = [IO.File]::ReadAllText($rootCertFile)
Assert-Condition ($pem.Contains('BEGIN CERTIFICATE') -and -not $pem.Contains('PRIVATE KEY')) 'public certificates only'
$checks++
$testPassword = ConvertTo-SecureString 'FAKE-LOCAL-TEST-ONLY' -AsPlainText -Force
$additionalCaFile = Join-Path $privateDirectory 'additional-ca.pem'
$certificateKey = [Security.Cryptography.RSA]::Create(2048)
try {
    foreach ($scenario in @('valid', 'expired', 'not-ca', 'private-key')) {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Backup Test CA', $certificateKey, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            ($scenario -ne 'not-ca'), $false, 0, $true))
        $expiry = if ($scenario -eq 'expired') { [DateTimeOffset]::UtcNow.AddDays(-1) } else { [DateTimeOffset]::UtcNow.AddDays(1) }
        $fixtureCertificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-2), $expiry)
        try {
            $fixturePem = $fixtureCertificate.ExportCertificatePem()
            if ($scenario -eq 'private-key') { $fixturePem += "`n-----BEGIN " + 'PRIVATE KEY-----' }
            [IO.File]::WriteAllText($additionalCaFile, $fixturePem)
            $rejected = $false
            try { Export-TrustedRoots $rootCertFile -AdditionalCertificatePath $additionalCaFile } catch { $rejected = $true }
            Assert-Condition ($rejected -eq ($scenario -ne 'valid')) "additional CA validation: $scenario"
            if ($scenario -eq 'valid') {
                Assert-Condition ([IO.File]::ReadAllText($rootCertFile).Contains(
                    [Convert]::ToBase64String($fixtureCertificate.RawData, [Base64FormattingOptions]::InsertLineBreaks))) 'include explicit CA in bundle'
            }
            $checks++
        } finally { $fixtureCertificate.Dispose() }
    }
} finally {
    $certificateKey.Dispose()
    Remove-Item -LiteralPath $additionalCaFile
}
$powershell = (Get-Process -Id $PID).Path
$priorPgService = $env:PGSERVICE
$env:PGSERVICE = 'must-not-be-inherited'
try {
    $result = Invoke-BackupTool $powershell @('-NoProfile', '-Command',
        'if ($env:PGPASSWORD -ne "FAKE-LOCAL-TEST-ONLY" -or $env:PGSERVICE -or $env:PGSSLMODE -ne "verify-full") { exit 9 }; Write-Output "SAFE"') @{
            PGSSLMODE = 'verify-full'
        } $testPassword 15
    Assert-Condition ($result.Trim() -eq 'SAFE') 'child-only password and isolated PG environment'
    Assert-Condition ($env:PGSERVICE -eq 'must-not-be-inherited') 'parent PG environment unchanged'
    $checks++
    $failureMessage = ''
    try {
        Invoke-BackupTool $powershell @('-NoProfile', '-Command',
            '[Console]::Error.WriteLine("password authentication failed FAKE-LOCAL-TEST-ONLY"); exit 9') @{} $testPassword 15 | Out-Null
    } catch { $failureMessage = $_.Exception.Message }
    Assert-Condition ($failureMessage -match 'Autenticacao recusada' -and $failureMessage -notmatch 'FAKE-LOCAL') 'redact raw errors'
    $checks++
} finally {
    $env:PGSERVICE = $priorPgService
    $testPassword.Dispose()
    # Exact files created by this test only; no recursive deletion or existing backup paths.
    Remove-Item -LiteralPath $rootCertFile
    [IO.Directory]::Delete($privateDirectory, $false)
}
[pscustomobject]@{ checksPassed = $checks; liveDatabaseTouched = $false } | ConvertTo-Json -Compress
