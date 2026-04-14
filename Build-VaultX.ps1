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
    Install-Module -Name ps2exe -Scope CurrentUser -Force
}

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host "Building VaultX v$version..." -ForegroundColor Cyan

$iconFile = Join-Path $scriptDir "VaultX.ico"
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

if (Test-Path $outputFile) {
    Write-Host "Build complete: $outputFile" -ForegroundColor Green
} else {
    Write-Error "Build failed. Output file was not created."
}
