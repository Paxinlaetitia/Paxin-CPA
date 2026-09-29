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
set "BACKUP_CERTIFICATE="
set "BACKUP_CERTIFICATE_REQUESTED=0"
:parse_args
if /i "%~1"=="--check" (
  set "BACKUP_CHECK=-CheckOnly"
  shift
  goto parse_args
)
if /i "%~1"=="--prepare" (
  set "BACKUP_CHECK=-PrepareToolsOnly"
  shift
  goto parse_args
)
if /i "%~1"=="--certificate" (
  set "BACKUP_CERTIFICATE_REQUESTED=1"
  set "BACKUP_CERTIFICATE=%~2"
  shift
  shift
  goto parse_args
)
if "%BACKUP_CERTIFICATE_REQUESTED%"=="1" if not defined BACKUP_CERTIFICATE (
  echo --certificate exige um caminho de arquivo publico CA. Nenhum backup foi iniciado.
  exit /b 2
)
set "BACKUP_CERT_ARG="
if defined BACKUP_CERTIFICATE set "BACKUP_CERT_ARG=-RootCertificatePath "%BACKUP_CERTIFICATE%""
"%BACKUP_PWSH%" -NoLogo -NoProfile -File "%~dp0scripts\backup-supabase.ps1" -DatabaseHost "aws-0-us-east-1.pooler.supabase.com" -DatabaseUser "postgres.drkyjgnctbxmupbfarnj" %BACKUP_CHECK% %BACKUP_CERT_ARG%
set "BACKUP_EXIT_CODE=%errorlevel%"
if "%BACKUP_CHECK%"=="-CheckOnly" exit /b %BACKUP_EXIT_CODE%
if not "%BACKUP_EXIT_CODE%"=="0" echo Falha no backup ou na inicializacao. Codigo: %BACKUP_EXIT_CODE%. Nao execute o SQL de alteracao.
echo A janela ficara aberta para conferir o resultado. Nao compartilhe senhas ou arquivos do banco.
pause
exit /b %BACKUP_EXIT_CODE%
