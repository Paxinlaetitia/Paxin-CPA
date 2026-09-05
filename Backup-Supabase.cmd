@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "BACKUP_PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
if exist "%BACKUP_PWSH%" goto run
set "BACKUP_PWSH=%LOCALAPPDATA%\Programs\PowerShell\7\pwsh.exe"
if exist "%BACKUP_PWSH%" goto run
set "BACKUP_PWSH=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
if exist "%BACKUP_PWSH%" goto run
echo PowerShell 7 nao encontrado nos locais conhecidos. Nenhum backup foi iniciado.
if /i not "%~1"=="--check" pause
exit /b 1

:run
set "BACKUP_CHECK="
if /i "%~1"=="--check" set "BACKUP_CHECK=-CheckOnly"
if /i "%~1"=="--prepare" set "BACKUP_CHECK=-PrepareToolsOnly"
"%BACKUP_PWSH%" -NoLogo -NoProfile -File "%~dp0scripts\backup-supabase.ps1" -DatabaseHost "aws-0-us-east-1.pooler.supabase.com" -DatabaseUser "postgres.drkyjgnctbxmupbfarnj" %BACKUP_CHECK%
set "BACKUP_EXIT_CODE=%errorlevel%"
if /i "%~1"=="--check" exit /b %BACKUP_EXIT_CODE%
if not "%BACKUP_EXIT_CODE%"=="0" echo Falha no backup ou na inicializacao. Codigo: %BACKUP_EXIT_CODE%. Nao execute o SQL de alteracao.
echo A janela ficara aberta para conferir o resultado. Nao compartilhe senhas ou arquivos do banco.
pause
exit /b %BACKUP_EXIT_CODE%
