@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   VaultX Installer
echo ============================================
echo.

:: Locate VaultX.exe next to this batch file
set "SCRIPT_DIR=%~dp0"
set "SOURCE_EXE=%SCRIPT_DIR%VaultX.exe"

if not exist "%SOURCE_EXE%" (
    echo ERROR: VaultX.exe not found next to this installer.
    echo Place VaultX.exe in the same folder as Install-VaultX.bat
    echo and run again.
    echo.
    pause
    exit /b 1
)

:: Install directory
set "INSTALL_DIR=%LOCALAPPDATA%\VaultX"

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Copying VaultX.exe to %INSTALL_DIR%...
copy /y "%SOURCE_EXE%" "%INSTALL_DIR%\VaultX.exe" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy VaultX.exe.
    pause
    exit /b 1
)
echo Done.
echo.

:: Create main Start Menu shortcut
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs"
set "TARGET_EXE=%INSTALL_DIR%\VaultX.exe"

echo Creating Start Menu shortcut...
call :CreateShortcut "%START_MENU%\VaultX.lnk" "%TARGET_EXE%"
echo Done. You can now find "VaultX" in Windows Search.
echo.

:: Ask for alias names
echo Want to find VaultX by other names in Windows Search?
set /p "ALIASES=Enter additional names (comma-separated, or press Enter to skip): "

if "%ALIASES%"=="" goto :Finish

:: Parse comma-separated aliases and create shortcuts
for %%A in (%ALIASES%) do (
    set "ALIAS=%%~A"
    :: Trim leading/trailing spaces
    for /f "tokens=* delims= " %%T in ("!ALIAS!") do set "ALIAS=%%T"
    if not "!ALIAS!"=="" (
        echo Creating alias shortcut: !ALIAS!
        call :CreateShortcut "%START_MENU%\!ALIAS!.lnk" "%TARGET_EXE%"
    )
)

:Finish
echo.
echo ============================================
echo   Installation complete!
echo   Location: %INSTALL_DIR%\VaultX.exe
echo ============================================
echo.
pause
exit /b 0

:: -----------------------------------------------
:: Function: CreateShortcut
::   %1 = shortcut path (.lnk)
::   %2 = target exe path
:: Uses inline VBScript via cscript.
:: -----------------------------------------------
:CreateShortcut
set "LNK_PATH=%~1"
set "LNK_TARGET=%~2"
set "LNK_WORKDIR=%INSTALL_DIR%"

:: Write a temporary VBScript to create the shortcut
set "VBS_TEMP=%TEMP%\vaultx_shortcut_%RANDOM%.vbs"
(
    echo Set ws = CreateObject("WScript.Shell"^)
    echo Set sc = ws.CreateShortcut("%LNK_PATH%"^)
    echo sc.TargetPath = "%LNK_TARGET%"
    echo sc.WorkingDirectory = "%LNK_WORKDIR%"
    echo sc.Description = "VaultX Password Manager"
    echo sc.Save
) > "%VBS_TEMP%"

cscript //nologo "%VBS_TEMP%"
del "%VBS_TEMP%" >nul 2>&1
exit /b 0
