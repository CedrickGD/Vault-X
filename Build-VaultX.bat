@echo off
title VaultX Builder
echo.
echo  VaultX Builder
echo  ===============
echo.

:: Find PowerShell - prefer pwsh (PS7), fall back to powershell (PS5)
where pwsh >nul 2>&1
if %errorlevel%==0 (
    set "PS=pwsh"
) else (
    set "PS=powershell"
)

%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-VaultX.ps1"
