<#
.SYNOPSIS
    Builds VaultX.ps1 into a portable VaultX.exe using ps2exe.
.DESCRIPTION
    Compiles the VaultX PowerShell script into a standalone executable
    that can be distributed and launched with a double-click.
.EXAMPLE
    .\Build-VaultX.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$sourceFile = Join-Path $scriptDir "VaultX.ps1"
$distDir = Join-Path $scriptDir "dist"
$outputFile = Join-Path $distDir "VaultX.exe"

if (-not (Test-Path $sourceFile)) {
    Write-Error "VaultX.ps1 not found in $scriptDir"
    return
}

$versionMatch = Select-String -Path $sourceFile -Pattern '^\$script:AppVersion\s*=\s*"([^"]+)"' | Select-Object -First 1
$version = if ($null -ne $versionMatch) { $versionMatch.Matches[0].Groups[1].Value } else { "0.0.0" }

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Installing ps2exe module..." -ForegroundColor Yellow
    if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
        Install-PSResource ps2exe -Scope CurrentUser -TrustRepository
    } else {
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
    }
}

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host "Building VaultX v$version..." -ForegroundColor Cyan

$iconFile = Join-Path $scriptDir "assets" "VaultX.ico"
$ps2exeArgs = @{
    InputFile  = $sourceFile
    OutputFile = $outputFile
    NoConsole  = $false
    Title      = "VaultX"
    Product    = "VaultX"
    Version    = $version
    Copyright  = "VaultX"
    Description = "VaultX Password Manager"
}
if (Test-Path $iconFile) {
    $ps2exeArgs.IconFile = $iconFile
}

Invoke-PS2EXE @ps2exeArgs

if (-not (Test-Path $outputFile)) {
    Write-Error "Build failed. Output file was not created."
    return
}

Write-Host "Build complete: $outputFile" -ForegroundColor Green

# Install to local app data and create Start Menu shortcut
$installDir = Join-Path $env:LOCALAPPDATA "VaultX"
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$targetExe = Join-Path $installDir "VaultX.exe"

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

Copy-Item -Path $outputFile -Destination $targetExe -Force
Write-Host "Installed to: $targetExe" -ForegroundColor Green

$shell = New-Object -ComObject WScript.Shell
$mainLnk = $shell.CreateShortcut((Join-Path $startMenu "VaultX.lnk"))
$mainLnk.TargetPath = $targetExe
$mainLnk.WorkingDirectory = $installDir
$mainLnk.Description = "VaultX Password Manager"
$mainLnk.Save()
Write-Host "Start Menu shortcut created. VaultX is now searchable." -ForegroundColor Green
