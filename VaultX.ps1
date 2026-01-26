<# 
VaultX - simple local password manager (single-user, local encryption)
#>

[CmdletBinding()]
param(
    [switch]$Close,
    [switch]$Help,
    [switch]$OpenData
)

$ErrorActionPreference = "Stop"

$script:AppName = "VaultX"
$script:AppVersion = "1.0.3"
$script:UpdateConfigUrl = "https://raw.githubusercontent.com/CedrickGD/Vault-X/main/version.yml"
$script:UpdateCheckEnabled = ($env:VAULTX_UPDATE_CHECK -ne "0")
$script:SkipShellOnQuit = $false
$script:MenuNormalColor = [ConsoleColor]::Gray
$script:MenuHighlightColor = [ConsoleColor]::Cyan
$script:MenuDisabledColor = [ConsoleColor]::DarkGray
$script:MenuSeparatorColor = [ConsoleColor]::DarkGray
$script:MenuPromptColor = [ConsoleColor]::Gray
$script:MenuBannerColor = [ConsoleColor]::Cyan
$script:MenuPointerSymbol = ">"
$script:WaitOnExit = ($env:VAULTX_WAIT_ON_EXIT -eq "1")
$script:DefaultMenuNormalColor = $script:MenuNormalColor
$script:DefaultMenuPromptColor = $script:MenuPromptColor
$script:DefaultMenuBannerColor = $script:MenuBannerColor
$script:DefaultHostForegroundColor = $null
try {
    if ($Host -and $Host.UI -and $Host.UI.RawUI) {
        $script:DefaultHostForegroundColor = $Host.UI.RawUI.ForegroundColor
    }
} catch {
}

function Convert-SecureStringToPlain {
    param([Security.SecureString]$Secure)
    if ($null -eq $Secure) { return "" }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Read-SecurePlain {
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    return Convert-SecureStringToPlain $secure
}

function Test-PathSafe {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        return (Test-Path -LiteralPath $Path)
    } catch {
        return $false
    }
}

function New-RandomBytes {
    param([int]$Length)
    $bytes = New-Object byte[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return $bytes
}

function Get-AppDir {
    $root = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($root)) {
        $root = $env:TEMP
    }
    if ([string]::IsNullOrWhiteSpace($root)) {
        return $null
    }
    return (Join-Path $root $script:AppName)
}

function Open-AppDataFolder {
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) {
        Show-Message "Data folder unavailable." ([ConsoleColor]::Red)
        return $false
    }
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    try {
        Start-Process -FilePath $dir -ErrorAction Stop | Out-Null
        Show-Message ("Data folder: " + $dir) ([ConsoleColor]::Green)
        return $true
    } catch {
        Write-Log ("Open data folder failed: {0}" -f $_.Exception.Message)
        Show-Message "Unable to open data folder." ([ConsoleColor]::Red)
        return $false
    }
}

function Get-LogPath {
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) {
        $fallback = $env:TEMP
        if ([string]::IsNullOrWhiteSpace($fallback)) {
            $fallback = $PWD.Path
        }
        $dir = $fallback
    }
    return (Join-Path $dir "vaultx.log")
}

function Write-Log {
    param([string]$Message)
    try {
        $path = Get-LogPath
        if ([string]::IsNullOrWhiteSpace($path)) { return }
        $dir = Split-Path -Parent $path
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
        }
        $stamp = (Get-Date).ToString("s")
        Add-Content -Path $path -Value ("[{0}] {1}" -f $stamp, $Message) -Encoding UTF8
    } catch {
    }
}

function Wait-ForExit {
    param([string]$Prompt = "Press Enter to close VaultX.")
    try {
        [void](Read-Host $Prompt)
    } catch {
    }
}

function Convert-UpdateConfigText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $result = [ordered]@{
        Version = $null
        Url = $null
        Changelog = $null
        Mandatory = $false
        Args = $null
    }
    $trimmed = $Text.TrimStart()
    if ($trimmed.StartsWith("<")) {
        try {
            [xml]$xml = $Text
            $item = $xml.item
            if ($null -eq $item) { return $null }
            $result.Version = $item.version
            $result.Url = $item.url
            $result.Changelog = $item.changelog
            $result.Mandatory = (($item.mandatory -as [string]) -match "^(true|yes|1)$")
            $result.Args = $item.args
            return $result
        } catch {
            return $null
        }
    }
    $lines = $Text -split "`r?`n"
    foreach ($line in $lines) {
        $clean = $line.Trim()
        if ($clean -eq "" -or $clean.StartsWith("#")) { continue }
        $parts = $clean -split ":", 2
        if ($parts.Count -lt 2) { continue }
        $key = $parts[0].Trim().ToLowerInvariant()
        $value = $parts[1].Trim()
        if ($value.StartsWith('"') -and $value.EndsWith('"')) { $value = $value.Trim('"') }
        if ($value.StartsWith("'") -and $value.EndsWith("'")) { $value = $value.Trim("'") }
        switch ($key) {
            "version" { $result.Version = $value }
            "url" { $result.Url = $value }
            "changelog" { $result.Changelog = $value }
            "mandatory" { $result.Mandatory = ($value -match "^(true|yes|1)$") }
            "args" { $result.Args = $value }
        }
    }
    return $result
}

function ConvertTo-VersionString {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $clean = $Value.Trim()
    if ($clean.StartsWith("v", [StringComparison]::OrdinalIgnoreCase)) {
        $clean = $clean.Substring(1)
    }
    $clean = ($clean -replace "[^0-9\.].*$", "")
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    return $clean
}

function Normalize-VersionString {
    param([string]$Value)
    $clean = ConvertTo-VersionString -Value $Value
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    $parts = $clean -split "\."
    $numbers = @()
    foreach ($part in $parts) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $num = 0
        if (-not [int]::TryParse($part, [ref]$num)) {
            return $clean
        }
        $numbers += $num
    }
    if ($numbers.Count -eq 0) { return $clean }
    while ($numbers.Count -gt 1 -and $numbers[-1] -eq 0) {
        $numbers = $numbers[0..($numbers.Count - 2)]
    }
    return ($numbers -join ".")
}

function Resolve-UpdateTemplate {
    param([string]$Value, [string]$Version)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $Value }
    return ($Value -replace "\{version\}", $Version)
}

function Test-IsDevelopmentCopy {
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { return $false }
    $root = Split-Path -Parent $scriptPath
    if ([string]::IsNullOrWhiteSpace($root)) { return $false }
    return (Test-Path (Join-Path $root ".git"))
}

function Test-UpdateDownloadUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) { return $true }
    } catch {
        $status = $null
        try { $status = $_.Exception.Response.StatusCode } catch { }
        if ($status) {
            Write-Log ("Update download check failed: HTTP {0}" -f [int]$status)
        } else {
            Write-Log ("Update download check failed: {0}" -f $_.Exception.Message)
        }
        return $false
    }
    return $false
}

function Compare-VersionString {
    param([string]$Current, [string]$Latest)
    $currentClean = Normalize-VersionString -Value $Current
    $latestClean = Normalize-VersionString -Value $Latest
    if ([string]::IsNullOrWhiteSpace($currentClean) -or [string]::IsNullOrWhiteSpace($latestClean)) {
        return 0
    }
    $currentVersion = $null
    $latestVersion = $null
    if ([Version]::TryParse($currentClean, [ref]$currentVersion) -and [Version]::TryParse($latestClean, [ref]$latestVersion)) {
        return $currentVersion.CompareTo($latestVersion)
    }
    return [string]::Compare($currentClean, $latestClean, $true)
}

function Install-Update {
    param(
        [string]$DownloadUrl,
        [string]$LatestVersion
    )
    if ([string]::IsNullOrWhiteSpace($DownloadUrl)) { return $null }
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        Show-Message "Update failed: script path unavailable." ([ConsoleColor]::Red)
        return $null
    }
    $tempFile = [IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
        $firstLine = (Get-Content -Path $tempFile -TotalCount 1 -ErrorAction SilentlyContinue)
        if ([string]::IsNullOrWhiteSpace($firstLine) -or $firstLine -match "<!DOCTYPE html|Not Found") {
            Show-Message "Update download failed." ([ConsoleColor]::Red)
            Write-Log "Update download returned invalid content."
            return $null
        }
        $backupPath = "$scriptPath.bak"
        Copy-Item -Path $scriptPath -Destination $backupPath -Force
        Move-Item -Path $tempFile -Destination $scriptPath -Force
        Show-Message ("Updated to version " + $LatestVersion + ". Restarting VaultX...") ([ConsoleColor]::Green)
        return $scriptPath
    } catch {
        Write-Log ("Update install failed: {0}" -f $_.Exception.Message)
        Show-Message "Update failed." ([ConsoleColor]::Red)
        return $null
    } finally {
        if (Test-Path $tempFile) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Start-UpdatedScript {
    param([string]$ScriptPath)
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { return }
    if (-not (Test-Path $ScriptPath)) { return }
    try {
        if ($script:LaunchedFromFile -and $Host.Name -eq "ConsoleHost") {
            Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$ScriptPath`"") | Out-Null
        } else {
            & $ScriptPath
        }
    } catch {
    }
}

function Invoke-UpdateCheck {
    param([string]$CurrentVersion)
    if (-not $script:UpdateCheckEnabled) { return $false }
    if ([string]::IsNullOrWhiteSpace($script:UpdateConfigUrl)) { return $false }
    if (Test-IsDevelopmentCopy) { return $false }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch {
    }
    $content = $null
    try {
        $response = Invoke-WebRequest -Uri $script:UpdateConfigUrl -UseBasicParsing -ErrorAction Stop
        $content = $response.Content
    } catch {
        Write-Log ("Update check failed: {0}" -f $_.Exception.Message)
        return $false
    }
    $info = Convert-UpdateConfigText -Text $content
    if ($null -eq $info) { return $false }
    if ([string]::IsNullOrWhiteSpace($info.Version)) { return $false }
    $latestVersion = $info.Version
    $currentDisplay = ConvertTo-VersionString -Value $CurrentVersion
    $latestDisplay = ConvertTo-VersionString -Value $latestVersion
    if ([string]::IsNullOrWhiteSpace($currentDisplay) -or [string]::IsNullOrWhiteSpace($latestDisplay)) { return $false }
    if (Compare-VersionString -Current $currentDisplay -Latest $latestDisplay -ge 0) { return $false }
    $downloadUrl = Resolve-UpdateTemplate -Value $info.Url -Version $latestDisplay
    if ([string]::IsNullOrWhiteSpace($downloadUrl)) { return $false }
    if (-not (Test-UpdateDownloadUrl -Url $downloadUrl)) { return $false }
    $subtitle = ("Current: {0}  Latest: {1}" -f $currentDisplay, $latestDisplay)
    $updateNow = $info.Mandatory
    if (-not $updateNow) {
        $choice = Show-ActionMenu -Title "Update available" -Options @("Update now", "Skip") -Subtitle $subtitle
        if ($choice -ne "Update now") { return $false }
    }
    $updatedPath = Install-Update -DownloadUrl $downloadUrl -LatestVersion $latestDisplay
    if ($updatedPath) {
        $script:SkipShellOnQuit = $true
        Start-UpdatedScript -ScriptPath $updatedPath
        Stop-VaultX -Message "$script:AppName updated."
        return $true
    }
    return $false
}

function Get-AccountsPath {
    return (Join-Path (Get-AppDir) "accounts.json")
}

function Get-VaultPath {
    param([string]$FileName)
    return (Join-Path (Get-AppDir) $FileName)
}

function Get-AccountFileName {
    param([string]$AccountName)
    $safe = ($AccountName.Trim()) -replace '[\\/:*?"<>|]', '_'
    $safe = $safe -replace '\s+', '_'
    if ([string]::IsNullOrEmpty($safe)) { $safe = "account" }
    if ($safe.Length -gt 32) { $safe = $safe.Substring(0, 32) }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($AccountName)
        $hashBytes = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    $hash = ([BitConverter]::ToString($hashBytes)).Replace("-", "")
    $short = $hash.Substring(0, 8)
    return ("vault_{0}_{1}.json" -f $safe, $short)
}

function Get-Accounts {
    $path = Get-AccountsPath
    if (-not (Test-Path $path)) { return @() }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = $raw | ConvertFrom-Json
        if ($null -eq $data) { return @() }
        return @($data)
    } catch {
        Show-Message "Vault list file is corrupted. Starting with empty list." ([ConsoleColor]::Red)
        return @()
    }
}

function Save-Accounts {
    param([array]$Accounts)
    $path = Get-AccountsPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $json = $Accounts | ConvertTo-Json -Depth 4
    Set-Content -Path $path -Value $json -Encoding UTF8
}

function Get-UniqueAccountName {
    param([array]$Accounts, [string]$BaseName)
    $base = if ([string]::IsNullOrWhiteSpace($BaseName)) { "Imported vault" } else { $BaseName.Trim() }
    if (-not ($Accounts | Where-Object { $_.Name -ieq $base })) { return $base }
    $index = 2
    while ($true) {
        $candidate = "$base ($index)"
        if (-not ($Accounts | Where-Object { $_.Name -ieq $candidate })) { return $candidate }
        $index++
    }
}

function Get-AccountNameFromFile {
    param([string]$FileName)
    $base = [IO.Path]::GetFileNameWithoutExtension($FileName)
    if ($base -match "^vault_(.+)_[0-9A-Fa-f]{8}$") {
        return ($Matches[1] -replace "_", " ")
    }
    return $base
}

function Get-VaultFilesStamp {
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path $dir)) { return "0" }
    $files = Get-ChildItem -Path $dir -Filter "vault_*.json" -File -ErrorAction SilentlyContinue
    if ($null -eq $files -or $files.Count -eq 0) { return "0" }
    $latest = ($files | Measure-Object -Property LastWriteTimeUtc -Maximum).Maximum
    $ticks = if ($latest) { $latest.Ticks } else { 0 }
    return ("{0}:{1}" -f $files.Count, $ticks)
}

function New-VaultFolderWatcher {
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) { return $null }
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $dir
    $watcher.Filter = "vault_*.json"
    $watcher.IncludeSubdirectories = $false
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $watcher.EnableRaisingEvents = $true
    return $watcher
}

function Close-VaultFolderWatcher {
    param($Watcher)
    if ($null -eq $Watcher) { return }
    try { $Watcher.EnableRaisingEvents = $false } catch { }
    try { $Watcher.Dispose() } catch { }
}

function Sync-AccountsWithVaultFiles {
    param([array]$Accounts)
    if ($null -eq $Accounts) { $Accounts = @() }
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path $dir)) { return $Accounts }
    $vaultFiles = Get-ChildItem -Path $dir -Filter "vault_*.json" -File -ErrorAction SilentlyContinue
    if ($null -eq $vaultFiles -or $vaultFiles.Count -eq 0) { return $Accounts }

    $fileIndex = @{}
    foreach ($account in $Accounts) {
        if ($account.File) { $fileIndex[$account.File.ToLowerInvariant()] = $true }
    }

    $updated = @($Accounts)
    $added = $false
    foreach ($file in $vaultFiles) {
        $key = $file.Name.ToLowerInvariant()
        if ($fileIndex.ContainsKey($key)) { continue }
        $meta = $null
        try {
            $meta = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }
        if (-not (Test-VaultMeta -Meta $meta)) { continue }
        $name = $meta.AccountName
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = Get-AccountNameFromFile -FileName $file.Name
        }
        $name = Get-UniqueAccountName -Accounts $updated -BaseName $name
        $updated += [ordered]@{
            Name = $name
            File = $file.Name
            CreatedAt = (Get-Date).ToString("s")
        }
        $fileIndex[$key] = $true
        $added = $true
    }

    if ($added) {
        Save-Accounts -Accounts $updated
    }
    return $updated
}

function Remove-BrokenVaultFiles {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir) -or -not (Test-Path $Dir)) { return 0 }
    $files = Get-ChildItem -Path $Dir -Filter "vault_*.json" -File -ErrorAction SilentlyContinue
    if ($null -eq $files -or $files.Count -eq 0) { return 0 }
    $removed = 0
    foreach ($file in $files) {
        $meta = $null
        try {
            $meta = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        } catch {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $file.FullName)) { $removed++ }
            continue
        }
        if (-not (Test-VaultMeta -Meta $meta)) {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $file.FullName)) { $removed++ }
        }
    }
    return $removed
}

function Wipe-VaultCache {
    param([switch]$Force, [switch]$Silent)
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) {
        Show-Message "Data folder unavailable." ([ConsoleColor]::Red)
        return $false
    }
    if (-not $Force) {
        if (-not (Confirm-Action "Wipe cache and remove broken vault files?")) { return $false }
    }
    $cachePath = Get-AccountsPath
    if (Test-Path $cachePath) {
        Remove-Item -Path $cachePath -Force -ErrorAction SilentlyContinue
    }
    $removed = Remove-BrokenVaultFiles -Dir $dir
    if (-not $Silent) {
        if ($removed -gt 0) {
            Show-Message ("Cache cleared. Removed {0} broken vault file(s)." -f $removed) ([ConsoleColor]::Green)
        } else {
            Show-Message "Cache cleared." ([ConsoleColor]::Green)
        }
    }
    return $true
}

function Read-AccountName {
    param([array]$Accounts)
    while ($true) {
        Clear-Host
        Write-Header "Create vault"
        $name = Read-Host "Vault name (required, Enter to abort)"
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        $exists = $Accounts | Where-Object { $_.Name -ieq $name }
        if ($exists) {
            Show-Message "Vault already exists." ([ConsoleColor]::Red)
            continue
        }
        return $name.Trim()
    }
}

function New-Account {
    param([array]$Accounts)
    $name = Read-AccountName -Accounts $Accounts
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    $fileName = Get-AccountFileName -AccountName $name
    $vaultPath = Get-VaultPath -FileName $fileName
    $vault = Open-Vault -VaultPath $vaultPath -AccountName $name -CreateIfMissing
    if ($null -eq $vault) { return $null }
    $account = [ordered]@{
        Name = $name
        File = $fileName
        CreatedAt = (Get-Date).ToString("s")
    }
    $Accounts += $account
    Save-Accounts -Accounts $Accounts
    return @{
        Accounts = $Accounts
        Account = $account
        Vault = $vault
    }
}

function Remove-Account {
    param([array]$Accounts, [int]$Selected)
    if ($Accounts.Count -eq 0) { return $Accounts }
    $account = $Accounts[$Selected]
    $vaultPath = Get-VaultPath -FileName $account.File
    if (-not (Confirm-AccountPassword -VaultPath $vaultPath -AccountName $account.Name)) {
        return $Accounts
    }
    if (-not (Confirm-Action "Delete vault '$($account.Name)' and its data?")) {
        return $Accounts
    }
    if (Test-Path $vaultPath) {
        Remove-Item -Path $vaultPath -Force
    }
    $updated = @($Accounts | Where-Object { $_.Name -ne $account.Name })
    Save-Accounts -Accounts $updated
    return $updated
}

function Export-VaultData {
    param(
        [string]$AccountName,
        $VaultData
    )
    Clear-Host
    Write-Header "Export vault"
    $destination = Read-Host "Export file path (Enter to abort)"
    if ([string]::IsNullOrWhiteSpace($destination)) { return $false }
    $destination = $destination.Trim()
    $extension = [IO.Path]::GetExtension($destination)
    if ([string]::IsNullOrWhiteSpace($extension)) {
        $destination = "$destination.json"
    }
    $destinationDir = Split-Path -Parent $destination
    if ([string]::IsNullOrWhiteSpace($destinationDir)) {
        $destinationDir = $PWD.Path
    }
    if (-not (Test-PathSafe -Path $destinationDir)) {
        Show-Message "Export path is invalid." ([ConsoleColor]::Red)
        return $false
    }
    $exportPassword = Read-ConfirmedSecret -Title "Export vault" -Prompt "Create export password" -ConfirmPrompt "Confirm export password"
    if ([string]::IsNullOrEmpty($exportPassword)) { return $false }
    $salt = New-RandomBytes 16
    $iterations = 100000
    $key = Get-KeyFromPassword -Password $exportPassword -Salt $salt -Iterations $iterations
    $meta = [ordered]@{
        Version = 1
        AccountName = $AccountName
        Salt = [Convert]::ToBase64String($salt)
        Iterations = $iterations
        IV = ""
        Data = ""
    }
    Save-Vault -VaultPath $destination -Key $key -Meta $meta -Data $VaultData
    Show-Message "Vault exported." ([ConsoleColor]::Green)
    return $true
}

function Import-VaultData {
    param([array]$Accounts)
    $accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
    Clear-Host
    Write-Header "Import data"
    $choice = Show-ActionMenu -Title "Import data" -Options @("Open data folder", "Enter file path", "Back") -Subtitle "Copy an exported vault file into the data folder or select its path."
    if ($null -eq $choice -or $choice -eq "Back") {
        return @{ Accounts = $accounts; Imported = $false }
    }
    if ($choice -eq "Open data folder") {
        Open-AppDataFolder | Out-Null
        $choice = Show-ActionMenu -Title "Import data" -Options @("Enter file path", "Back") -Subtitle "When ready, enter the exported vault file path."
        if ($null -eq $choice -or $choice -eq "Back") {
            return @{ Accounts = $accounts; Imported = $false }
        }
    }
    $path = Read-Host "Path to exported vault (Enter to abort)"
    if ([string]::IsNullOrWhiteSpace($path)) { return @{ Accounts = $accounts; Imported = $false } }
    $path = $path.Trim()
    if (-not (Test-PathSafe -Path $path)) {
        Show-Message "Import file path is invalid or not found." ([ConsoleColor]::Red)
        return @{ Accounts = $accounts; Imported = $false }
    }
    try {
        $meta = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } catch {
        Show-Message "Import file is corrupted or unreadable." ([ConsoleColor]::Red)
        return @{ Accounts = $accounts; Imported = $false }
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-Message "Import file is not a valid vault." ([ConsoleColor]::Red)
        return @{ Accounts = $accounts; Imported = $false }
    }
    $baseName = $meta.AccountName
    if ([string]::IsNullOrWhiteSpace($baseName)) {
        $baseName = Get-AccountNameFromFile -FileName ([IO.Path]::GetFileName($path))
    }
    $name = Get-UniqueAccountName -Accounts $accounts -BaseName $baseName
    $fileName = Get-AccountFileName -AccountName $name
    $destination = Get-VaultPath -FileName $fileName
    if (Test-Path $destination) {
        Show-Message "Vault already exists. Import aborted." ([ConsoleColor]::Red)
        return @{ Accounts = $accounts; Imported = $false }
    }
    $meta.AccountName = $name
    $json = $meta | ConvertTo-Json -Depth 6
    $dir = Split-Path -Parent $destination
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    Set-Content -Path $destination -Value $json -Encoding UTF8
    $accounts += [ordered]@{
        Name = $name
        File = $fileName
        CreatedAt = (Get-Date).ToString("s")
    }
    Save-Accounts -Accounts $accounts
    Show-Message ("Imported vault '{0}'." -f $name) ([ConsoleColor]::Green)
    return @{ Accounts = $accounts; Imported = $true }
}

function Get-CsvRowValue {
    param(
        $Row,
        [string[]]$Names
    )
    if ($null -eq $Row -or $null -eq $Names) { return "" }
    foreach ($name in $Names) {
        foreach ($prop in $Row.PSObject.Properties) {
            if ($prop.Name -ieq $name) {
                $value = [string]$prop.Value
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value.Trim()
                }
            }
        }
    }
    return ""
}

function Convert-BrowserCsvRowToEntry {
    param($Row)
    $title = Get-CsvRowValue -Row $Row -Names @("name", "title", "site", "site_name", "hostname", "host", "url", "website", "origin")
    $url = Get-CsvRowValue -Row $Row -Names @("url", "website", "origin", "site", "hostname", "host", "formActionOrigin", "form_action_origin")
    $username = Get-CsvRowValue -Row $Row -Names @("username", "user", "user_name", "login", "login_username", "email", "username_value")
    $password = Get-CsvRowValue -Row $Row -Names @("password", "pass", "password_value", "login_password")
    $notes = Get-CsvRowValue -Row $Row -Names @("note", "notes", "comment", "description")
    $other = Get-CsvRowValue -Row $Row -Names @("httpRealm", "realm")

    if ([string]::IsNullOrWhiteSpace($title)) { $title = $url }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = $username }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = "Imported entry" }

    if ([string]::IsNullOrWhiteSpace($url) -and [string]::IsNullOrWhiteSpace($username) -and [string]::IsNullOrWhiteSpace($password) -and [string]::IsNullOrWhiteSpace($notes) -and [string]::IsNullOrWhiteSpace($other)) {
        return $null
    }

    $importTag = "Imported from browser CSV"
    if ([string]::IsNullOrWhiteSpace($other)) {
        $other = $importTag
    } else {
        $other = "$other`n$importTag"
    }

    return [ordered]@{
        Id = [guid]::NewGuid().ToString()
        Title = $title
        Url = $url
        Username = $username
        Password = $password
        Phone = ""
        Email = ""
        Notes = $notes
        Other = $other
        UpdatedAt = (Get-Date).ToString("s")
    }
}

function Import-BrowserPasswords {
    param(
        [string]$VaultPath,
        $Meta,
        $Data,
        $Key,
        [string]$AccountName
    )
    if ($null -eq $Data.Entries) {
        $Data | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    Clear-Host
    Write-Header "Import browser passwords"
    $choice = Show-ActionMenu -Title "Import browser passwords" -Options @("Open data folder", "Enter file path", "Back") -Subtitle "Use a browser CSV export to add entries to this vault."
    if ($null -eq $choice -or $choice -eq "Back") { return $false }
    if ($choice -eq "Open data folder") {
        Open-AppDataFolder | Out-Null
        $choice = Show-ActionMenu -Title "Import browser passwords" -Options @("Enter file path", "Back") -Subtitle "When ready, enter the browser CSV file path."
        if ($null -eq $choice -or $choice -eq "Back") { return $false }
    }
    $path = Read-Host "Path to browser CSV (Enter to abort)"
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $path = $path.Trim()
    if (-not (Test-PathSafe -Path $path)) {
        Show-Message "CSV path is invalid or not found." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $rows = Import-Csv -LiteralPath $path
    } catch {
        Show-Message "CSV file is unreadable or invalid." ([ConsoleColor]::Red)
        return $false
    }
    if ($null -eq $rows -or $rows.Count -eq 0) {
        Show-Message "No rows found in CSV." ([ConsoleColor]::Yellow)
        return $false
    }
    $added = 0
    $skipped = 0
    foreach ($row in $rows) {
        $entry = Convert-BrowserCsvRowToEntry -Row $row
        if ($null -eq $entry) {
            $skipped++
            continue
        }
        $Data.Entries += $entry
        $added++
    }
    if ($added -gt 0) {
        Save-Vault -VaultPath $VaultPath -Key $Key -Meta $Meta -Data $Data
    }
    $message = if ($skipped -gt 0) {
        "Imported $added entries. Skipped $skipped row(s)."
    } else {
        "Imported $added entries."
    }
    Show-Message $message ([ConsoleColor]::Green)
    return ($added -gt 0)
}

function Confirm-AccountPassword {
    param([string]$VaultPath, [string]$AccountName)
    if (-not (Test-Path $VaultPath)) {
        Show-Message "Vault file missing. Delete aborted." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $meta = Get-Content -Path $VaultPath -Raw | ConvertFrom-Json
    } catch {
        Show-Message "Vault file is corrupted or unreadable." ([ConsoleColor]::Red)
        return $false
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-Message "Vault file is invalid." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Vault encryption salt is invalid." ([ConsoleColor]::Red)
        return $false
    }
    $iterations = [int]$meta.Iterations
    $recoveryAvailable = Test-RecoveryMeta -Meta $meta
    while ($true) {
        Clear-Host
        Write-Header "Confirm deletion"
        if ($AccountName) {
            Write-Host ("Vault: " + $AccountName) -ForegroundColor DarkGray
            Write-Host ""
        }
        $password = Read-SecurePlain "Master password (Enter to abort)"
        if ([string]::IsNullOrEmpty($password)) { return $false }
        $key = Get-KeyFromPassword -Password $password -Salt $salt -Iterations $iterations
        try {
            $null = Get-DataFromMeta -Meta $meta -Key $key
            $password = $null
            return $true
        } catch {
            Show-Message "Invalid password." ([ConsoleColor]::Red)
            if ($recoveryAvailable) {
                $choice = Show-ActionMenu -Title "Password check failed" -Options @("Try again", "Use recovery password", "Abort") -Subtitle "A recovery password is configured for this vault."
                if ($choice -eq "Use recovery password") {
                    $recoveryPassword = Read-SecurePlain "Recovery password (Enter to abort)"
                    if ([string]::IsNullOrEmpty($recoveryPassword)) { return $false }
                    $masterKey = Get-MasterKeyFromRecovery -Meta $meta -RecoveryPassword $recoveryPassword
                    $recoveryPassword = $null
                    if ($null -eq $masterKey) {
                        Show-Message "Invalid recovery password." ([ConsoleColor]::Red)
                        continue
                    }
                    try {
                        $null = Get-DataFromMeta -Meta $meta -Key $masterKey
                        return $true
                    } catch {
                        Show-Message "Invalid recovery password." ([ConsoleColor]::Red)
                    }
                } elseif ($null -eq $choice -or $choice -eq "Abort") {
                    return $false
                }
            }
        } finally {
            $password = $null
        }
    }
}

function Get-KeyFromPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "Password is used to derive an encryption key and cleared from memory.")]
    param(
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations
    )
    $derive = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, $Iterations)
    try {
        return $derive.GetBytes(32)
    } finally {
        $derive.Dispose()
    }
}

function Protect-Bytes {
    param(
        [byte[]]$PlainBytes,
        [byte[]]$Key
    )
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Key = $Key
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $iv = $aes.IV
        $encryptor = $aes.CreateEncryptor()
        $ms = New-Object IO.MemoryStream
        $cs = New-Object Security.Cryptography.CryptoStream($ms, $encryptor, [Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($PlainBytes, 0, $PlainBytes.Length)
        $cs.FlushFinalBlock()
        $cipher = $ms.ToArray()
        $cs.Dispose()
        $ms.Dispose()
        $encryptor.Dispose()
        return @{
            IV = [Convert]::ToBase64String($iv)
            Data = [Convert]::ToBase64String($cipher)
        }
    } finally {
        $aes.Dispose()
    }
}

function Unprotect-Bytes {
    param(
        [byte[]]$CipherBytes,
        [byte[]]$Key,
        [byte[]]$IV
    )
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Key = $Key
        $aes.IV = $IV
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        $ms = New-Object IO.MemoryStream
        $cs = New-Object Security.Cryptography.CryptoStream($ms, $decryptor, [Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($CipherBytes, 0, $CipherBytes.Length)
        $cs.FlushFinalBlock()
        $plain = $ms.ToArray()
        $cs.Dispose()
        $ms.Dispose()
        $decryptor.Dispose()
        return $plain
    } finally {
        $aes.Dispose()
    }
}

function Save-Vault {
    param(
        [string]$VaultPath,
        [byte[]]$Key,
        $Meta,
        $Data
    )
    if ($null -eq $Data.Entries) {
        $Data | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $json = $Data | ConvertTo-Json -Depth 6
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($json)
    $encrypted = Protect-Bytes -PlainBytes $plainBytes -Key $Key
    $Meta.IV = $encrypted.IV
    $Meta.Data = $encrypted.Data
    $metaJson = $Meta | ConvertTo-Json -Depth 4
    $dir = Split-Path -Parent $VaultPath
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    Set-Content -Path $VaultPath -Value $metaJson -Encoding UTF8
}

function Get-DataFromMeta {
    param(
        $Meta,
        [byte[]]$Key
    )
    if ([string]::IsNullOrEmpty($Meta.Data)) {
        return [ordered]@{ Entries = @() }
    }
    $iv = [Convert]::FromBase64String($Meta.IV)
    $cipher = [Convert]::FromBase64String($Meta.Data)
    $plainBytes = Unprotect-Bytes -CipherBytes $cipher -Key $Key -IV $iv
    $json = [Text.Encoding]::UTF8.GetString($plainBytes)
    try {
        $data = $json | ConvertFrom-Json -Depth 6
    } catch {
        $data = $json | ConvertFrom-Json
    }
    if ($null -eq $data.Entries) {
        $data | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $data.Entries = @($data.Entries)
    return $data
}

function Test-VaultMeta {
    param($Meta)
    if ($null -eq $Meta) { return $false }
    if ([string]::IsNullOrWhiteSpace($Meta.Salt)) { return $false }
    if ($null -eq $Meta.Iterations) { return $false }
    $iterValue = 0
    if (-not [int]::TryParse($Meta.Iterations.ToString(), [ref]$iterValue)) { return $false }
    if ($iterValue -le 0) { return $false }
    return $true
}

function Write-Banner {
    $banner = @'
____   _________   ____ ___.____  ___________           ____  ___
\   \ /   /  _  \ |    |   \    | \__    ___/           \   \/  /
 \   Y   /  /_\  \|    |   /    |   |    |      ______   \     / 
  \     /    |    \    |  /|    |___|    |     /_____/   /     \ 
   \___/\____|__  /______/ |_______ \____|              /___/\  \
                \/                 \/                         \_/
'@
    try {
        $lines = $banner -split "\r?\n"
        foreach ($line in $lines) {
            if ($line -ne "") {
                Write-Host $line -ForegroundColor $script:MenuBannerColor
            }
        }
    } catch {
        Write-Log ("Banner render failed: {0}" -f $_.Exception.Message)
    }
}

function Write-Header {
    param(
        [string]$Subtitle,
        [switch]$ShowBanner
    )
    $hour = (Get-Date).Hour
    $salutation = if ($hour -lt 12) { "Good morning" } elseif ($hour -lt 18) { "Good afternoon" } else { "Good evening" }
    $greeting = "{0}, {1}." -f $salutation, $env:USERNAME
    $hostLine = "Host: {0}" -f $env:COMPUTERNAME
    $titleLine = if ([string]::IsNullOrWhiteSpace($script:AppVersion)) {
        $script:AppName
    } else {
        "{0} v{1}" -f $script:AppName, $script:AppVersion
    }
    Write-Host $greeting -ForegroundColor DarkGray
    Write-Host $hostLine -ForegroundColor DarkGray
    if ($ShowBanner) {
        Write-Banner
        Write-Host $titleLine -ForegroundColor DarkGray
    } else {
        Write-Host $titleLine -ForegroundColor Cyan
    }
    if ($Subtitle) {
        Write-Host $Subtitle -ForegroundColor Gray
    }
    Write-Host ""
}

function Show-Usage {
    Write-Host ("{0} v{1}" -f $script:AppName, $script:AppVersion) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Gray
    Write-Host "  VaultX.ps1             # Launch the app" -ForegroundColor Gray
    Write-Host "  VaultX.ps1 -Close       # Close the app session" -ForegroundColor Gray
    Write-Host "  VaultX.ps1 -OpenData    # Open data folder" -ForegroundColor Gray
    Write-Host "  VaultX.ps1 -Help        # Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Session shortcuts (after first run):" -ForegroundColor Gray
    Write-Host "  VaultX                 # Launch again in the same session" -ForegroundColor Gray
    Write-Host "  Close-VaultX           # Close the app session" -ForegroundColor Gray
}

function Show-Message {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Yellow)
    Write-Host $Message -ForegroundColor $Color
    Start-Sleep -Milliseconds 900
}

function Read-MenuKey {
    param([string]$Prompt)
    $raw = $null
    try {
        $raw = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        if ($raw.PSObject.Properties.Match("KeyDown").Count -gt 0 -and -not $raw.KeyDown) {
            $raw = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } catch {
        $raw = $null
    }
    if ($null -eq $raw) {
        try {
            $raw = [Console]::ReadKey($true)
        } catch {
            $raw = $null
        }
    }
    if ($null -eq $raw) {
        return [pscustomobject]@{ Key = "Escape"; Modifiers = [ConsoleModifiers]0 }
    }
    $mods = [ConsoleModifiers]0
    if ($raw.PSObject.Properties.Match("Modifiers").Count -gt 0) {
        $mods = $raw.Modifiers
    } elseif ($raw.PSObject.Properties.Match("ControlKeyState").Count -gt 0) {
        $state = $raw.ControlKeyState.ToString()
        if ($state -match "AltPressed") { $mods = $mods -bor [ConsoleModifiers]::Alt }
        if ($state -match "CtrlPressed") { $mods = $mods -bor [ConsoleModifiers]::Control }
    }
    $keyValue = $null
    if ($raw.PSObject.Properties.Match("Key").Count -gt 0) {
        $keyValue = $raw.Key
    } elseif ($raw.PSObject.Properties.Match("VirtualKeyCode").Count -gt 0) {
        try {
            $keyValue = [ConsoleKey]$raw.VirtualKeyCode
        } catch {
            $keyValue = $null
        }
    } elseif ($raw.PSObject.Properties.Match("Character").Count -gt 0) {
        if ($raw.Character -ne [char]0) {
            $keyValue = $raw.Character.ToString().ToUpperInvariant()
        }
    }
    $keyText = if ($null -eq $keyValue -or [string]::IsNullOrEmpty($keyValue.ToString())) { "Unknown" } else { $keyValue.ToString() }
    return [pscustomobject]@{
        Key = $keyText
        Modifiers = $mods
    }
}

function Test-MenuKeyAvailable {
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            return $Host.UI.RawUI.KeyAvailable
        }
    } catch {
    }
    try {
        return [Console]::KeyAvailable
    } catch {
        return $false
    }
}

function Read-MenuKeyWithRefresh {
    param(
        [int]$RefreshIntervalMs = 700,
        [scriptblock]$OnRefresh,
        [System.IO.FileSystemWatcher]$Watcher,
        [int]$ChangePollMs = 100,
        [scriptblock]$OnChange
    )
    $hasRefresh = ($RefreshIntervalMs -gt 0 -and $null -ne $OnRefresh)
    $hasChange = ($null -ne $Watcher -and $null -ne $OnChange)
    if (-not $hasRefresh -and -not $hasChange) { return Read-MenuKey }
    $lastRefresh = Get-Date
    while ($true) {
        if (Test-MenuKeyAvailable) {
            return Read-MenuKey
        }
        $changeDetected = $false
        if ($hasChange) {
            try {
                $timeout = [Math]::Max(10, $ChangePollMs)
                $result = $Watcher.WaitForChanged([IO.WatcherChangeTypes]::All, $timeout)
                if (-not $result.TimedOut) { $changeDetected = $true }
            } catch {
                $changeDetected = $false
            }
        } else {
            Start-Sleep -Milliseconds 50
        }
        if ($changeDetected) {
            $didRefresh = & $OnChange
            if ($didRefresh) { return $null }
        }
        if ($hasRefresh) {
            $now = Get-Date
            if (($now - $lastRefresh).TotalMilliseconds -ge $RefreshIntervalMs) {
                $lastRefresh = $now
                $didRefresh = & $OnRefresh
                if ($didRefresh) { return $null }
            }
        }
    }
}

function Get-CursorVisible {
    try {
        return [Console]::CursorVisible
    } catch {
        return $null
    }
}

function Set-CursorVisible {
    param([bool]$Visible)
    try {
        [Console]::CursorVisible = $Visible
    } catch {
    }
}

function Set-ClipboardSafe {
    param([string]$Value)
    $cmd = Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return $false }
    try {
        Set-Clipboard -Value $Value
        return $true
    } catch {
        return $false
    }
}

function ConvertTo-WebUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $trimmed = $Url.Trim()
    if ($trimmed -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $trimmed = "https://$trimmed"
    }
    $uri = $null
    if ([Uri]::TryCreate($trimmed, [UriKind]::Absolute, [ref]$uri)) {
        if ($uri.Scheme -in @("http", "https")) {
            return $uri.AbsoluteUri
        }
    }
    return $null
}

function Open-WebUrl {
    param([string]$Url)
    $normalized = ConvertTo-WebUrl -Url $Url
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        Show-Message "URL is empty or invalid." ([ConsoleColor]::Yellow)
        return
    }
    try {
        Start-Process -FilePath $normalized | Out-Null
        Show-Message "Opening URL..." ([ConsoleColor]::Green)
    } catch {
        Show-Message "Unable to open URL on this system." ([ConsoleColor]::Red)
    }
}

function Open-BrowserExportLinks {
    $options = @(
        @{ Label = "Google Chrome (chrome://password-manager/passwords)"; Url = "chrome://password-manager/passwords" }
        @{ Label = "Microsoft Edge (edge://settings/passwords)"; Url = "edge://settings/passwords" }
        @{ Label = "Mozilla Firefox (about:logins)"; Url = "about:logins" }
        @{ Label = "Brave (brave://settings/passwords)"; Url = "brave://settings/passwords" }
        @{ Label = "Opera (opera://settings/passwords)"; Url = "opera://settings/passwords" }
    )
    $labels = @($options | ForEach-Object { $_.Label }) + @("Back")
    while ($true) {
        $choice = Show-ActionMenu -Title "Browser export links" -Options $labels -Subtitle "Open your browser’s password export page."
        if ($null -eq $choice -or $choice -eq "Back") { return }
        $selected = $options | Where-Object { $_.Label -eq $choice } | Select-Object -First 1
        if ($null -eq $selected) { return }
        try {
            Start-Process -FilePath $selected.Url | Out-Null
            Show-Message "Opening browser export page..." ([ConsoleColor]::Green)
            return
        } catch {
            Show-Message "Unable to open the browser export page." ([ConsoleColor]::Red)
            return
        }
    }
}

function Clear-VaultSession {
    $script:VaultMeta = $null
    $script:VaultData = $null
    $script:VaultKey = $null
}

function Get-ConsoleWidth {
    try {
        return [Console]::WindowWidth
    } catch {
        return 120
    }
}

function Get-ConsoleHeight {
    try {
        return [Console]::WindowHeight
    } catch {
        return 40
    }
}

function Write-MenuPrompt {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    Write-Host ("? " + $Text) -ForegroundColor $script:MenuPromptColor
    Write-Host ""
}

function Write-MenuSeparator {
    param([int]$Indent = 2)
    $width = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent * 2))
    $pattern = "- "
    $line = ""
    while ($line.Length -lt $width) {
        $line += $pattern
    }
    if ($line.Length -gt $width) {
        $line = $line.Substring(0, $width)
    }
    if ($Indent -gt 0) { Write-Host (" " * $Indent) -NoNewline }
    Write-Host $line -ForegroundColor $script:MenuSeparatorColor
}

function Write-MenuHelpHint {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    Write-Host $Text -ForegroundColor DarkGray
}

function Show-MenuHelp {
    param(
        [string]$Title,
        [string[]]$Lines
    )
    Clear-Host
    Write-Header $Title
    foreach ($line in $Lines) {
        Write-Host $line -ForegroundColor $script:MenuNormalColor
    }
    Write-Host ""
    Write-Host "Press any key to return." -ForegroundColor DarkGray
    [void](Read-MenuKey)
}

function Get-ConsoleColorPalette {
    return @(
        @{ Name = "Black"; Color = [ConsoleColor]::Black; R = 0; G = 0; B = 0 }
        @{ Name = "DarkBlue"; Color = [ConsoleColor]::DarkBlue; R = 0; G = 0; B = 139 }
        @{ Name = "DarkGreen"; Color = [ConsoleColor]::DarkGreen; R = 0; G = 100; B = 0 }
        @{ Name = "DarkCyan"; Color = [ConsoleColor]::DarkCyan; R = 0; G = 139; B = 139 }
        @{ Name = "DarkRed"; Color = [ConsoleColor]::DarkRed; R = 139; G = 0; B = 0 }
        @{ Name = "DarkMagenta"; Color = [ConsoleColor]::DarkMagenta; R = 139; G = 0; B = 139 }
        @{ Name = "DarkYellow"; Color = [ConsoleColor]::DarkYellow; R = 184; G = 134; B = 11 }
        @{ Name = "Gray"; Color = [ConsoleColor]::Gray; R = 190; G = 190; B = 190 }
        @{ Name = "DarkGray"; Color = [ConsoleColor]::DarkGray; R = 105; G = 105; B = 105 }
        @{ Name = "Blue"; Color = [ConsoleColor]::Blue; R = 0; G = 0; B = 255 }
        @{ Name = "Green"; Color = [ConsoleColor]::Green; R = 0; G = 255; B = 0 }
        @{ Name = "Cyan"; Color = [ConsoleColor]::Cyan; R = 0; G = 255; B = 255 }
        @{ Name = "Red"; Color = [ConsoleColor]::Red; R = 255; G = 0; B = 0 }
        @{ Name = "Magenta"; Color = [ConsoleColor]::Magenta; R = 255; G = 0; B = 255 }
        @{ Name = "Yellow"; Color = [ConsoleColor]::Yellow; R = 255; G = 255; B = 0 }
        @{ Name = "White"; Color = [ConsoleColor]::White; R = 255; G = 255; B = 255 }
    )
}

function Resolve-ConsoleColor {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    if ($trimmed -match "^(?i)#?[0-9a-f]{6}$") {
        $hex = $trimmed.TrimStart("#")
        $r = [Convert]::ToInt32($hex.Substring(0, 2), 16)
        $g = [Convert]::ToInt32($hex.Substring(2, 2), 16)
        $b = [Convert]::ToInt32($hex.Substring(4, 2), 16)
        $palette = Get-ConsoleColorPalette
        $closest = $palette | Sort-Object { ($_.R - $r) * ($_.R - $r) + ($_.G - $g) * ($_.G - $g) + ($_.B - $b) * ($_.B - $b) } | Select-Object -First 1
        return $closest.Color
    }
    if ($trimmed -match "^\d+$") {
        $num = 0
        if ([int]::TryParse($trimmed, [ref]$num)) {
            if ($num -ge 0 -and $num -le 15) {
                return ([ConsoleColor]$num)
            }
        }
    }
    try {
        return [ConsoleColor]([Enum]::Parse([ConsoleColor], $trimmed, $true))
    } catch {
        return $null
    }
}

function Set-FontColor {
    param([ConsoleColor]$Color)
    $script:MenuNormalColor = $Color
    $script:MenuPromptColor = $Color
    $script:MenuBannerColor = $Color
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            $Host.UI.RawUI.ForegroundColor = $Color
        }
    } catch {
    }
}

function Reset-CustomizationDefaults {
    $script:MenuNormalColor = $script:DefaultMenuNormalColor
    $script:MenuPromptColor = $script:DefaultMenuPromptColor
    $script:MenuBannerColor = $script:DefaultMenuBannerColor
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI -and $null -ne $script:DefaultHostForegroundColor) {
            $Host.UI.RawUI.ForegroundColor = $script:DefaultHostForegroundColor
        }
    } catch {
    }
}

function Invoke-FontColorPrompt {
    Clear-Host
    Write-Header "Customize Script"
    Write-Host "Enter a color name (e.g., Cyan), number (0-15), or hex (#RRGGBB)." -ForegroundColor DarkGray
    $names = [Enum]::GetNames([ConsoleColor]) -join ", "
    Write-Host ("Available colors: " + $names) -ForegroundColor DarkGray
    Write-Host ""
    $input = Read-Host "Font color"
    $color = Resolve-ConsoleColor -Value $input
    if ($null -eq $color) {
        Show-Message "Invalid color value." ([ConsoleColor]::Red)
        return $false
    }
    Set-FontColor -Color $color
    Show-Message ("Font color set to " + $color + ".") ([ConsoleColor]::Green)
    return $true
}

function Format-MenuText {
    param([string]$Text, [int]$Max)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($Max -le 0) { return "" }
    if ($Text.Length -le $Max) { return $Text }
    if ($Max -le 3) { return $Text.Substring(0, $Max) }
    return ($Text.Substring(0, $Max - 3) + "...")
}

function Get-MenuBlockWidth {
    param(
        [string[]]$Items,
        [int]$MinWidth = 10,
        [int]$MaxWidth = 60
    )
    if ($null -eq $Items -or $Items.Count -eq 0) { return $MinWidth }
    $maxLen = ($Items | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $width = [Math]::Max($MinWidth, [Math]::Min($MaxWidth, $maxLen + 2))
    return $width
}

function Start-MenuFrame {
    param([ref]$IsFirstRender)
    if ($IsFirstRender.Value) {
        Clear-Host
        $IsFirstRender.Value = $false
        return
    }
    try {
        [Console]::SetCursorPosition(0, 0)
    } catch {
        Clear-Host
    }
}

function Write-MenuItem {
    param(
        [string]$Text,
        [bool]$IsSelected,
        [bool]$IsActive = $true,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [int]$Indent = 2,
        [ValidateSet("Left", "Center")]
        [string]$Align = "Left",
        [int]$BlockWidth = 0
    )
    $maxWidth = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent + 4))
    $safeText = Format-MenuText -Text $Text -Max $maxWidth
    $pointerColor = if ($IsActive) { $script:MenuHighlightColor } else { $script:MenuHighlightColor }
    if ($Align -eq "Center") {
        $prefix = if ($IsSelected) { "$script:MenuPointerSymbol " } else { "  " }
        $line = $prefix + $safeText
        $width = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent * 2))
        $padding = [Math]::Max(0, [Math]::Floor(($width - $line.Length) / 2))
        if ($Indent -gt 0) { Write-Host (" " * $Indent) -NoNewline }
        Write-Host ((" " * $padding) + $line) -ForegroundColor $Color
        return
    }
    if ($BlockWidth -gt 0) {
        $prefix = if ($IsSelected) { "$script:MenuPointerSymbol " } else { "  " }
        $line = $prefix + $safeText
        $width = [Math]::Max($BlockWidth, $line.Length)
        $screenWidth = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent * 2))
        $padding = [Math]::Max(0, [Math]::Floor(($screenWidth - $width) / 2))
        if ($Indent -gt 0) { Write-Host (" " * $Indent) -NoNewline }
        Write-Host ((" " * $padding) + $line) -ForegroundColor $Color
        return
    }
    if ($IsSelected) {
        if ($Indent -gt 0) { Write-Host (" " * $Indent) -NoNewline }
        Write-Host $script:MenuPointerSymbol -ForegroundColor $pointerColor -NoNewline
        Write-Host " " -NoNewline
        Write-Host $safeText -ForegroundColor $Color
    } else {
        $padding = " " * ($Indent + 2)
        Write-Host ($padding + $safeText) -ForegroundColor $Color
    }
}

function Show-ActionMenu {
    param(
        [string]$Title,
        [string[]]$Options,
        [string]$Subtitle,
        [int]$Selected = 0
    )
    if ($null -eq $Options -or $Options.Count -eq 0) { return $null }
    if ($Selected -lt 0) { $Selected = 0 }
    if ($Selected -ge $Options.Count) { $Selected = $Options.Count - 1 }
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header $Title
            if ($Subtitle) {
                Write-Host $Subtitle -ForegroundColor DarkGray
                Write-Host ""
            }
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $line = $Options[$i]
                $isSelected = ($i -eq $Selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $line -IsSelected $isSelected -Color $color -Align "Center"
            }
            Write-Host ""
            Write-Host "Use Up/Down to move, Enter to select, Esc to go back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    if ($Options.Count -gt 0) {
                        if ($Selected -gt 0) { $Selected-- } else { $Selected = $Options.Count - 1 }
                    }
                }
                "DownArrow" {
                    if ($Options.Count -gt 0) {
                        if ($Selected -lt ($Options.Count - 1)) { $Selected++ } else { $Selected = 0 }
                    }
                }
                "Enter" { return $Options[$Selected] }
                "Escape" { return $null }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Read-NewMasterPassword {
    param([string]$AccountName)
    while ($true) {
        Clear-Host
        $title = "Set master password"
        if ($AccountName) { $title = "Set master password for vault $AccountName" }
        Write-Header $title
        $pw1 = Read-SecurePlain "Create master password (Enter to abort)"
        if ([string]::IsNullOrEmpty($pw1)) { return $null }
        $pw2 = Read-SecurePlain "Confirm master password (Enter to abort)"
        if ([string]::IsNullOrEmpty($pw2)) { return $null }
        if ($pw1 -ne $pw2) {
            Show-Message "Passwords do not match." ([ConsoleColor]::Red)
            $pw1 = $null
            $pw2 = $null
            continue
        }
        return $pw1
    }
}

function Read-ConfirmedSecret {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$ConfirmPrompt
    )
    while ($true) {
        Clear-Host
        Write-Header $Title
        $pw1 = Read-SecurePlain "$Prompt (Enter to abort)"
        if ([string]::IsNullOrEmpty($pw1)) { return $null }
        $pw2 = Read-SecurePlain "$ConfirmPrompt (Enter to abort)"
        if ([string]::IsNullOrEmpty($pw2)) { return $null }
        if ($pw1 -ne $pw2) {
            Show-Message "Passwords do not match." ([ConsoleColor]::Red)
            $pw1 = $null
            $pw2 = $null
            continue
        }
        return $pw1
    }
}

function Test-RecoveryMeta {
    param($Meta)
    if ($null -eq $Meta) { return $false }
    if ([string]::IsNullOrWhiteSpace($Meta.RecoverySalt)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Meta.RecoveryKeyIV)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Meta.RecoveryKeyData)) { return $false }
    if ($null -eq $Meta.RecoveryIterations) { return $false }
    $iterValue = 0
    if (-not [int]::TryParse($Meta.RecoveryIterations.ToString(), [ref]$iterValue)) { return $false }
    if ($iterValue -le 0) { return $false }
    try { [Convert]::FromBase64String($Meta.RecoverySalt) | Out-Null } catch { return $false }
    try { [Convert]::FromBase64String($Meta.RecoveryKeyIV) | Out-Null } catch { return $false }
    try { [Convert]::FromBase64String($Meta.RecoveryKeyData) | Out-Null } catch { return $false }
    return $true
}

function Get-MasterKeyFromRecovery {
    param(
        $Meta,
        [string]$RecoveryPassword
    )
    if (-not (Test-RecoveryMeta -Meta $Meta)) { return $null }
    try {
        $salt = [Convert]::FromBase64String($Meta.RecoverySalt)
        $iterations = [int]$Meta.RecoveryIterations
        $recoveryKey = Get-KeyFromPassword -Password $RecoveryPassword -Salt $salt -Iterations $iterations
        $iv = [Convert]::FromBase64String($Meta.RecoveryKeyIV)
        $cipher = [Convert]::FromBase64String($Meta.RecoveryKeyData)
        $masterKey = Unprotect-Bytes -CipherBytes $cipher -Key $recoveryKey -IV $iv
        return $masterKey
    } catch {
        return $null
    }
}

function Remove-RecoveryFields {
    param($Meta)
    if ($null -eq $Meta) { return }
    if ($Meta -is [System.Collections.IDictionary]) {
        $Meta.Remove("RecoverySalt") | Out-Null
        $Meta.Remove("RecoveryIterations") | Out-Null
        $Meta.Remove("RecoveryKeyIV") | Out-Null
        $Meta.Remove("RecoveryKeyData") | Out-Null
        return
    }
    $Meta.PSObject.Properties.Remove("RecoverySalt")
    $Meta.PSObject.Properties.Remove("RecoveryIterations")
    $Meta.PSObject.Properties.Remove("RecoveryKeyIV")
    $Meta.PSObject.Properties.Remove("RecoveryKeyData")
}

function Open-Vault {
    param(
        [string]$VaultPath,
        [string]$AccountName,
        [switch]$CreateIfMissing
    )
    if (-not (Test-Path $VaultPath)) {
        if (-not $CreateIfMissing) {
            Show-Message "Vault not found." ([ConsoleColor]::Red)
            return $null
        }
        $password = Read-NewMasterPassword -AccountName $AccountName
        if ([string]::IsNullOrEmpty($password)) { return $null }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $key = Get-KeyFromPassword -Password $password -Salt $salt -Iterations $iterations
        $data = [ordered]@{ Entries = @() }
        $meta = [ordered]@{
            Version = 1
            AccountName = $AccountName
            Salt = [Convert]::ToBase64String($salt)
            Iterations = $iterations
            IV = ""
            Data = ""
        }
        Save-Vault -VaultPath $VaultPath -Key $key -Meta $meta -Data $data
        $password = $null
        return @{
            Meta = $meta
            Data = $data
            Key  = $key
        }
    }

    try {
        $meta = Get-Content -Path $VaultPath -Raw | ConvertFrom-Json
    } catch {
        Show-Message "Vault file is corrupted or unreadable." ([ConsoleColor]::Red)
        return $null
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-Message "Vault file is invalid." ([ConsoleColor]::Red)
        return $null
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Vault encryption salt is invalid." ([ConsoleColor]::Red)
        return $null
    }
    $iterations = [int]$meta.Iterations
    $recoveryAvailable = Test-RecoveryMeta -Meta $meta
    while ($true) {
        Clear-Host
        $title = "Unlock vault"
        if ($meta.AccountName) { $title = "Unlock vault $($meta.AccountName)" }
        Write-Header $title
        $password = Read-SecurePlain "Master password (Enter to abort)"
        if ([string]::IsNullOrEmpty($password)) { return $null }
        $key = Get-KeyFromPassword -Password $password -Salt $salt -Iterations $iterations
        try {
            $data = Get-DataFromMeta -Meta $meta -Key $key
            $password = $null
            return @{
                Meta = $meta
                Data = $data
                Key  = $key
            }
        } catch {
            Show-Message "Invalid password." ([ConsoleColor]::Red)
            if ($recoveryAvailable) {
                $choice = Show-ActionMenu -Title "Unlock failed" -Options @("Try again", "Use recovery password", "Abort") -Subtitle "A recovery password is configured for this vault."
                if ($choice -eq "Use recovery password") {
                    $recoveryPassword = Read-SecurePlain "Recovery password (Enter to abort)"
                    if ([string]::IsNullOrEmpty($recoveryPassword)) { return $null }
                    $masterKey = Get-MasterKeyFromRecovery -Meta $meta -RecoveryPassword $recoveryPassword
                    $recoveryPassword = $null
                    if ($null -eq $masterKey) {
                        Show-Message "Invalid recovery password." ([ConsoleColor]::Red)
                        continue
                    }
                    try {
                        $data = Get-DataFromMeta -Meta $meta -Key $masterKey
                        return @{
                            Meta = $meta
                            Data = $data
                            Key  = $masterKey
                        }
                    } catch {
                        Show-Message "Invalid recovery password." ([ConsoleColor]::Red)
                    }
                } elseif ($null -eq $choice -or $choice -eq "Abort") {
                    return $null
                }
            }
        } finally {
            $password = $null
        }
    }
}

function Invoke-RecoveryOptions {
    param(
        [string]$VaultPath,
        [string]$AccountName,
        $Meta,
        $Data,
        [byte[]]$Key
    )
    if ($null -eq $Key -or $Key.Length -ne 32) {
        Show-Message "Recovery options unavailable for this vault session." ([ConsoleColor]::Red)
        return $false
    }
    while ($true) {
        $hasRecovery = Test-RecoveryMeta -Meta $Meta
        $options = if ($hasRecovery) {
            @("Update recovery password", "Remove recovery password", "Back")
        } else {
            @("Set recovery password", "Back")
        }
        $subtitle = "Recovery passwords let you unlock this vault if the master password is lost."
        $choice = Show-ActionMenu -Title "Recovery options" -Options $options -Subtitle $subtitle
        if ($null -eq $choice -or $choice -eq "Back") { return $false }
        if ($choice -eq "Remove recovery password") {
            if (-not (Confirm-Action "Remove recovery password for this vault?")) { return $false }
            Remove-RecoveryFields -Meta $Meta
            Save-Vault -VaultPath $VaultPath -Key $Key -Meta $Meta -Data $Data
            Show-Message "Recovery password removed." ([ConsoleColor]::Green)
            return $true
        }
        $title = if ($AccountName) { "Set recovery password for vault $AccountName" } else { "Set recovery password" }
        $recoveryPassword = Read-ConfirmedSecret -Title $title -Prompt "Create recovery password" -ConfirmPrompt "Confirm recovery password"
        if ([string]::IsNullOrEmpty($recoveryPassword)) { return $false }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $recoveryKey = Get-KeyFromPassword -Password $recoveryPassword -Salt $salt -Iterations $iterations
        $wrapped = Protect-Bytes -PlainBytes $Key -Key $recoveryKey
        $Meta.RecoverySalt = [Convert]::ToBase64String($salt)
        $Meta.RecoveryIterations = $iterations
        $Meta.RecoveryKeyIV = $wrapped.IV
        $Meta.RecoveryKeyData = $wrapped.Data
        Save-Vault -VaultPath $VaultPath -Key $Key -Meta $Meta -Data $Data
        $recoveryPassword = $null
        Show-Message "Recovery password saved." ([ConsoleColor]::Green)
        return $true
    }
}

function Format-DisplayValue {
    param([string]$Value, [int]$Max = 60)
    if ([string]::IsNullOrEmpty($Value)) { return "(empty)" }
    $text = $Value -replace "(\r\n|\r|\n)", " "
    if ($text.Length -le $Max) { return $text }
    return $text.Substring(0, $Max - 3) + "..."
}

function Get-EntryFields {
    param($Entry)
    $mask = ""
    if ($Entry.Password) {
        $mask = "*" * [Math]::Min($Entry.Password.Length, 16)
    }
    return @(
        @{ Label = "Name";     Value = $Entry.Title;    Display = $Entry.Title }
        @{ Label = "URL";      Value = $Entry.Url;      Display = $Entry.Url }
        @{ Label = "Username"; Value = $Entry.Username; Display = $Entry.Username }
        @{ Label = "Password"; Value = $Entry.Password; Display = $mask }
        @{ Label = "Phone";    Value = $Entry.Phone;    Display = $Entry.Phone }
        @{ Label = "Email";    Value = $Entry.Email;    Display = $Entry.Email }
        @{ Label = "Notes";    Value = $Entry.Notes;    Display = $Entry.Notes }
        @{ Label = "Other";    Value = $Entry.Other;    Display = $Entry.Other }
    )
}

function Get-FilteredEntries {
    param(
        [array]$Entries,
        [string]$SearchTerm
    )
    $filtered = @()
    $map = @()
    if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
        for ($i = 0; $i -lt $Entries.Count; $i++) {
            $filtered += $Entries[$i]
            $map += $i
        }
        return @{
            Entries = $filtered
            Map = $map
        }
    }
    $term = $SearchTerm.ToLowerInvariant()
    for ($i = 0; $i -lt $Entries.Count; $i++) {
        $entry = $Entries[$i]
        $haystack = @(
            $entry.Title, $entry.Url, $entry.Username, $entry.Password,
            $entry.Phone, $entry.Email, $entry.Notes, $entry.Other
        ) -join " "
        if ($haystack.ToLowerInvariant().Contains($term)) {
            $filtered += $entry
            $map += $i
        }
    }
    return @{
        Entries = $filtered
        Map = $map
    }
}

function Show-EntryList {
    param(
        [array]$Entries,
        [int]$SelectedIndex = 0,
        [string]$SearchTerm = "",
        [string]$AccountName,
        [string]$Title = "Entries"
    )
    if ($Entries.Count -eq 0) { $SelectedIndex = 0 }
    $start = 0
    $selectedPos = 0
    $syncSelection = $true
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            $filterResult = Get-FilteredEntries -Entries $Entries -SearchTerm $SearchTerm
            $filtered = $filterResult.Entries
            $map = $filterResult.Map

            if ($syncSelection) {
                $selectedPos = 0
                if ($map.Count -gt 0) {
                    $found = [Array]::IndexOf($map, $SelectedIndex)
                    if ($found -ge 0) { $selectedPos = $found + 1 } else { $selectedPos = 1 }
                }
                $syncSelection = $false
            } else {
                if ($map.Count -eq 0) {
                    $selectedPos = 0
                } elseif ($selectedPos -gt $map.Count) {
                    $selectedPos = $map.Count
                } elseif ($selectedPos -lt 0) {
                    $selectedPos = 0
                }
            }

            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            $subtitle = $Title
            if ($AccountName) { $subtitle = "$Title - $AccountName" }
            Write-Header $subtitle -ShowBanner
            Write-Host ("Search: " + $SearchTerm) -ForegroundColor DarkGray
            Write-Host ""
            Write-MenuSeparator -Indent 0

            $backColor = if ($selectedPos -eq 0) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
            Write-MenuItem -Text "Back to menu" -IsSelected:($selectedPos -eq 0) -IsActive:$true -Color $backColor
            Write-Host ""
            if ($filtered.Count -eq 0) {
                if ($Entries.Count -eq 0) {
                    Write-Host "No entries yet." -ForegroundColor DarkGray
                } else {
                    Write-Host "No matches for current search." -ForegroundColor DarkGray
                }
            } else {
                $maxVisible = [Math]::Max(5, (Get-ConsoleHeight) - 18)
                if ($filtered.Count -le $maxVisible) {
                    $start = 0
                } else {
                    if ($start -gt ($filtered.Count - $maxVisible)) {
                        $start = [Math]::Max(0, $filtered.Count - $maxVisible)
                    }
                    $selectedEntryPos = [Math]::Max(0, $selectedPos - 1)
                    if ($selectedEntryPos -lt $start) { $start = $selectedEntryPos }
                    if ($selectedEntryPos -ge ($start + $maxVisible)) { $start = $selectedEntryPos - $maxVisible + 1 }
                }
                $end = [Math]::Min($filtered.Count - 1, $start + $maxVisible - 1)
                Write-Host "Entries" -ForegroundColor DarkGray
                for ($i = $start; $i -le $end; $i++) {
                    $entry = $filtered[$i]
                    $titleText = Format-DisplayValue $entry.Title 28
                    $url = Format-DisplayValue $entry.Url 40
                    $line = ("{0,-30} {1}" -f $titleText, $url)
                    $pos = $i + 1
                    $isSelected = ($pos -eq $selectedPos)
                    $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                    Write-MenuItem -Text $line -IsSelected $isSelected -Color $color
                }
                Write-Host ""
                if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
                    Write-Host ("Showing {0}-{1} of {2}" -f ($start + 1), ($end + 1), $filtered.Count) -ForegroundColor DarkGray
                } else {
                    Write-Host ("Showing {0}-{1} of {2} (total {3})" -f ($start + 1), ($end + 1), $filtered.Count, $Entries.Count) -ForegroundColor DarkGray
                }
            }

            Write-Host ""
            Write-Host "Up/Down move, Enter select, Esc go back." -ForegroundColor DarkGray
            Write-Host "Type to search, Backspace delete." -ForegroundColor DarkGray

            $skipIndexUpdate = $false
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    $totalItems = $filtered.Count + 1
                    if ($totalItems -gt 0) {
                        if ($selectedPos -gt 0) { $selectedPos-- } else { $selectedPos = $totalItems - 1 }
                    }
                }
                "DownArrow" {
                    $totalItems = $filtered.Count + 1
                    if ($totalItems -gt 0) {
                        if ($selectedPos -lt ($totalItems - 1)) { $selectedPos++ } else { $selectedPos = 0 }
                    }
                }
                "Enter" {
                    if ($selectedPos -eq 0) {
                        return @{ Action = "back"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm }
                    }
                    if ($map.Count -gt 0 -and $selectedPos -gt 0) {
                        return @{ Action = "select"; SelectedIndex = $map[$selectedPos - 1]; SearchTerm = $SearchTerm }
                    }
                    Show-Message "No entries available." ([ConsoleColor]::Red)
                }
                "Escape" {
                    return @{ Action = "back"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm }
                }
                "Backspace" {
                    if (-not [string]::IsNullOrEmpty($SearchTerm)) {
                        $SearchTerm = $SearchTerm.Substring(0, $SearchTerm.Length - 1)
                        $SelectedIndex = 0
                        $syncSelection = $true
                        $skipIndexUpdate = $true
                    }
                }
                default {
                    if ($key.Key.Length -eq 1 -and (($key.Modifiers -band [ConsoleModifiers]::Control) -eq 0) -and (($key.Modifiers -band [ConsoleModifiers]::Alt) -eq 0)) {
                        $SearchTerm += $key.Key
                        $SelectedIndex = 0
                        $syncSelection = $true
                        $skipIndexUpdate = $true
                    }
                }
            }

            if ($skipIndexUpdate) { continue }
            if ($map.Count -gt 0 -and $selectedPos -gt 0) {
                $SelectedIndex = $map[$selectedPos - 1]
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-AccountPicker {
    param(
        [array]$Accounts,
        [string]$Title = "Select vault"
    )
    if ($Accounts.Count -eq 0) { return $null }
    $selected = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header $Title -ShowBanner
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $Accounts.Count; $i++) {
                $isSelected = ($i -eq $selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $Accounts[$i].Name -IsSelected $isSelected -Color $color -Indent 0
            }
            $backIndex = $Accounts.Count
            $isSelected = ($selected -eq $backIndex)
            $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
            Write-MenuItem -Text "Back" -IsSelected $isSelected -Color $color -Indent 0
            Write-Host ""
            Write-Host "Up/Down move, Enter select, Esc go back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    $max = $Accounts.Count
                    if ($selected -gt 0) { $selected-- } else { $selected = $max }
                }
                "DownArrow" {
                    $max = $Accounts.Count
                    if ($selected -lt $max) { $selected++ } else { $selected = 0 }
                }
                "Enter" {
                    if ($selected -eq $backIndex) { return $null }
                    return $selected
                }
                "Escape" { return $null }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-VaultMenu {
    param(
        [string]$AccountName,
        [bool]$HasEntries
    )
    $actions = @(
        @{ Label = "View entries"; Action = "view"; RequiresEntry = $false }
        @{ Label = "Add entry"; Action = "add"; RequiresEntry = $false }
        @{ Label = "Edit entry"; Action = "edit"; RequiresEntry = $true }
        @{ Label = "Delete entry"; Action = "delete"; RequiresEntry = $true }
        @{ Label = "Export vault (encrypted)"; Action = "export"; RequiresEntry = $false }
        @{ Label = "Import browser passwords (CSV)"; Action = "import-browser"; RequiresEntry = $false }
        @{ Label = "Get browser CSV export links"; Action = "browser-links"; RequiresEntry = $false }
        @{ Label = "Recovery options"; Action = "recovery"; RequiresEntry = $false }
        @{ Label = "Back to vault list"; Action = "logout"; RequiresEntry = $false }
        @{ Label = "Quit VaultX"; Action = "quit"; RequiresEntry = $false }
    )
    $labels = $actions | ForEach-Object { $_.Label }
    $labelWidth = ($labels | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $menuWidth = Get-MenuBlockWidth -Items $labels -MinWidth 26 -MaxWidth 60
    $selected = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            $title = "Vault Menu"
            if ($AccountName) { $title = "Vault Menu - $AccountName" }
            Write-Header $title -ShowBanner
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $label = $action.Label.PadRight($labelWidth)
                $isDisabled = ($action.RequiresEntry -and -not $HasEntries)
                $isSelected = ($i -eq $selected)
                $color = if ($isDisabled) { $script:MenuDisabledColor } elseif ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $label -IsSelected $isSelected -IsActive:(!$isDisabled) -Color $color -Indent 0 -BlockWidth $menuWidth
            }
            Write-Host ""
            Write-Host "Up/Down move, Enter select, Esc go back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    if ($selected -gt 0) { $selected-- } else { $selected = $actions.Count - 1 }
                }
                "DownArrow" {
                    if ($selected -lt ($actions.Count - 1)) { $selected++ } else { $selected = 0 }
                }
                "Enter" {
                    $action = $actions[$selected]
                    if ($action.RequiresEntry -and -not $HasEntries) {
                        Show-Message "No entries available." ([ConsoleColor]::Red)
                        continue
                    }
                    return $action.Action
                }
                "Escape" { return "logout" }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-CustomizeMenu {
    $selectedAction = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            $actions = @(
                @{ Label = "Change font color"; Action = "font-color" }
                @{ Label = "Reset to script defaults"; Action = "reset" }
                @{ Label = "Back"; Action = "back" }
            )
            $labels = $actions | ForEach-Object { $_.Label }
            $labelWidth = ($labels | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
            $menuWidth = Get-MenuBlockWidth -Items $labels -MinWidth 24 -MaxWidth 60
            if ($selectedAction -ge $actions.Count) {
                $selectedAction = [Math]::Max(0, $actions.Count - 1)
            }

            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header "Customize Script"
            Write-Host ("Current font color: " + $script:MenuNormalColor) -ForegroundColor DarkGray
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $label = $action.Label.PadRight($labelWidth)
                $isSelected = ($i -eq $selectedAction)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $label -IsSelected $isSelected -IsActive:$true -Color $color -Indent 0 -BlockWidth $menuWidth
            }
            Write-Host ""
            Write-Host "Up/Down move, Enter select, Esc go back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    if ($selectedAction -gt 0) { $selectedAction-- } else { $selectedAction = $actions.Count - 1 }
                }
                "DownArrow" {
                    if ($selectedAction -lt ($actions.Count - 1)) { $selectedAction++ } else { $selectedAction = 0 }
                }
                "Enter" {
                    $action = $actions[$selectedAction].Action
                    if ($action -eq "font-color") {
                        Invoke-FontColorPrompt | Out-Null
                        $isFirstRender = $true
                    } elseif ($action -eq "reset") {
                        Reset-CustomizationDefaults
                        Show-Message "Customizations reset to script defaults." ([ConsoleColor]::Green)
                        $isFirstRender = $true
                    } else {
                        return "back"
                    }
                }
                "Escape" { return "back" }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-AccountMenu {
    param([array]$Accounts, [int]$Selected = 0)
    $accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
    $selectedAction = 0
    $cursorState = Get-CursorVisible
    $watcher = New-VaultFolderWatcher
    $vaultStamp = Get-VaultFilesStamp
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            $actions = @()
            if ($accounts.Count -gt 0) {
                $actions += @{ Label = "Open existing"; Action = "login" }
            }
            $actions += @{ Label = "Create new"; Action = "add" }
            $actions += @{ Label = "Import data"; Action = "import" }
            if ($accounts.Count -gt 0) {
                $actions += @{ Label = "Remove"; Action = "delete" }
            }
            $actions += @{ Label = "Wipe cache"; Action = "wipe-cache" }
            $actions += @{ Label = "Open data folder"; Action = "open-data" }
            $actions += @{ Label = "Customize script"; Action = "customize" }
            $actions += @{ Label = "Quit"; Action = "quit" }
            $labels = $actions | ForEach-Object { $_.Label }
            $labelWidth = ($labels | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
            $menuWidth = Get-MenuBlockWidth -Items $labels -MinWidth 24 -MaxWidth 60

            if ($selectedAction -ge $actions.Count) {
                $selectedAction = [Math]::Max(0, $actions.Count - 1)
            }

            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header "Main Menu" -ShowBanner
            if ($accounts.Count -eq 0) {
                Write-Host "No vaults yet." -ForegroundColor DarkGray
            } else {
                $names = $accounts | ForEach-Object { $_.Name } | Sort-Object
                Write-Host ("Vaults: " + ($names -join ", ")) -ForegroundColor DarkGray
            }
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $label = $action.Label.PadRight($labelWidth)
                $isSelected = ($i -eq $selectedAction)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $label -IsSelected $isSelected -IsActive:$true -Color $color -Indent 0 -BlockWidth $menuWidth
            }
            Write-Host ""
            Write-Host "Up/Down move, Enter select, Esc quit." -ForegroundColor DarkGray
            $key = Read-MenuKeyWithRefresh -RefreshIntervalMs 700 -OnRefresh {
                $currentStamp = Get-VaultFilesStamp
                if ($currentStamp -ne $vaultStamp) {
                    $vaultStamp = $currentStamp
                    Wipe-VaultCache -Force -Silent | Out-Null
                    $accounts = Sync-AccountsWithVaultFiles -Accounts @()
                    $selectedAction = 0
                    return $true
                }
                return $false
            } -Watcher $watcher -ChangePollMs 100 -OnChange {
                Wipe-VaultCache -Force -Silent | Out-Null
                $accounts = Sync-AccountsWithVaultFiles -Accounts @()
                $vaultStamp = Get-VaultFilesStamp
                $selectedAction = 0
                return $true
            }
            if ($null -eq $key) { continue }
            switch ($key.Key) {
                "UpArrow" {
                    if ($selectedAction -gt 0) { $selectedAction-- } else { $selectedAction = $actions.Count - 1 }
                }
                "DownArrow" {
                    if ($selectedAction -lt ($actions.Count - 1)) { $selectedAction++ } else { $selectedAction = 0 }
                }
                "Enter" {
                    $action = $actions[$selectedAction]
                    return @{ Action = $action.Action; Selected = 0; Accounts = $accounts }
                }
                "Escape" {
                    return @{ Action = "quit"; Selected = 0; Accounts = $accounts }
                }
            }
        }
    } finally {
        Close-VaultFolderWatcher -Watcher $watcher
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-EntryDetail {
    param($Entry)
    $fields = Get-EntryFields $Entry | Where-Object {
        $_.Label -eq "Name" -or -not [string]::IsNullOrWhiteSpace($_.Value)
    }
    $items = @()
    foreach ($field in $fields) {
        $items += @{ Type = "field"; Field = $field }
    }
    if (-not [string]::IsNullOrWhiteSpace($Entry.Url)) {
        $items += @{ Type = "action"; Label = "Open URL" }
    }
    $items += @{ Type = "action"; Label = "Back" }
    $selected = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header ("Entry: " + $Entry.Title)
            $labelWidth = 12
            for ($i = 0; $i -lt $items.Count; $i++) {
                $item = $items[$i]
                if ($item.Type -eq "field") {
                    $display = Format-DisplayValue $item.Field.Display 60
                    $line = ("{0,-$labelWidth} : {1}" -f $item.Field.Label, $display)
                } else {
                    $line = "[Action] " + $item.Label
                }
                $isSelected = ($i -eq $selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $line -IsSelected $isSelected -IsActive:$true -Color $color
            }
            Write-Host ""
            Write-Host "Enter copies field or runs action, Esc go back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    if ($items.Count -gt 0) {
                        if ($selected -gt 0) { $selected-- } else { $selected = $items.Count - 1 }
                    }
                }
                "DownArrow" {
                    if ($items.Count -gt 0) {
                        if ($selected -lt ($items.Count - 1)) { $selected++ } else { $selected = 0 }
                    }
                }
                "Enter" {
                    $item = $items[$selected]
                    if ($item.Type -eq "field") {
                        $value = $item.Field.Value
                        if ([string]::IsNullOrEmpty($value)) {
                            Show-Message "Nothing to copy." ([ConsoleColor]::Yellow)
                        } else {
                            if (Set-ClipboardSafe -Value $value) {
                                Show-Message "Copied to clipboard." ([ConsoleColor]::Green)
                            } else {
                                Show-Message "Clipboard not available in this session." ([ConsoleColor]::Yellow)
                            }
                        }
                    } elseif ($item.Label -eq "Open URL") {
                        Open-WebUrl -Url $Entry.Url
                    } elseif ($item.Label -eq "Back") {
                        return "back"
                    }
                }
                "Escape" { return "back" }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Read-OptionalText {
    param([string]$Label, [string]$Current)
    if ($Current) {
        $value = Read-Host "$Label [$Current] (blank keep, '-' clear)"
    } else {
        $value = Read-Host "$Label (blank skip)"
    }
    if ([string]::IsNullOrEmpty($value)) { return $Current }
    if ($value -eq "-") { return "" }
    return $value.Trim()
}

function Read-OptionalSecret {
    param([string]$Label, [string]$Current)
    if ($Current) {
        $secure = Read-Host "$Label [hidden] (blank keep, '-' clear)" -AsSecureString
    } else {
        $secure = Read-Host "$Label (blank skip)" -AsSecureString
    }
    $plain = Convert-SecureStringToPlain $secure
    if ([string]::IsNullOrEmpty($plain)) { return $Current }
    if ($plain -eq "-") { return "" }
    return $plain
}

function Read-Entry {
    param($Existing)
    $isEdit = $null -ne $Existing
    Clear-Host
    if ($isEdit) {
        Write-Header ("Edit entry: " + $Existing.Title)
    } else {
        Write-Header "Add new entry"
    }

    if ($isEdit) {
        $title = Read-OptionalText "Name" $Existing.Title
        if ([string]::IsNullOrEmpty($title)) { $title = $Existing.Title }
    } else {
        $title = Read-Host "Name (required, Enter to abort)"
        if ([string]::IsNullOrWhiteSpace($title)) { return $null }
        $title = $title.Trim()
    }

    $url = Read-OptionalText "URL" ($Existing.Url)
    $username = Read-OptionalText "Username" ($Existing.Username)
    $password = Read-OptionalSecret "Password" ($Existing.Password)
    $phone = Read-OptionalText "Phone" ($Existing.Phone)
    $email = Read-OptionalText "Email" ($Existing.Email)
    $notes = Read-OptionalText "Notes" ($Existing.Notes)
    $other = Read-OptionalText "Other" ($Existing.Other)

    if ($isEdit) {
        $Existing.Title = $title
        $Existing.Url = $url
        $Existing.Username = $username
        $Existing.Password = $password
        $Existing.Phone = $phone
        $Existing.Email = $email
        $Existing.Notes = $notes
        $Existing.Other = $other
        $Existing.UpdatedAt = (Get-Date).ToString("s")
        return $Existing
    }

    return [ordered]@{
        Id = [guid]::NewGuid().ToString()
        Title = $title
        Url = $url
        Username = $username
        Password = $password
        Phone = $phone
        Email = $email
        Notes = $notes
        Other = $other
        UpdatedAt = (Get-Date).ToString("s")
    }
}

function Confirm-Action {
    param([string]$Prompt)
    $choice = Show-ActionMenu -Title $Prompt -Options @("Yes", "No") -Selected 1
    return ($choice -eq "Yes")
}

function Invoke-VaultSession {
    param([string]$VaultPath, $Vault)
    $script:VaultMeta = $Vault.Meta
    $script:VaultData = $Vault.Data
    $script:VaultKey = $Vault.Key

    if ($null -eq $script:VaultData.Entries) {
        $script:VaultData | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $selectedIndex = 0
    $searchTerm = ""

    try {
        :VaultSession while ($true) {
            $hasEntries = ($script:VaultData.Entries.Count -gt 0)
            $menuAction = Show-VaultMenu -AccountName $script:VaultMeta.AccountName -HasEntries $hasEntries
            switch ($menuAction) {
                "view" {
                    $result = Show-EntryList -Entries $script:VaultData.Entries -SelectedIndex $selectedIndex -SearchTerm $searchTerm -AccountName $script:VaultMeta.AccountName -Title "Entries"
                    if ($null -ne $result) {
                        $selectedIndex = $result.SelectedIndex
                        $searchTerm = $result.SearchTerm
                        if ($result.Action -eq "select") {
                            $entry = $script:VaultData.Entries[$selectedIndex]
                            while ($true) {
                                $action = Show-EntryDetail -Entry $entry
                                if ($action -eq "edit") {
                                    $updated = Read-Entry -Existing $entry
                                    if ($null -ne $updated) {
                                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -Meta $script:VaultMeta -Data $script:VaultData
                                        $entry = $updated
                                    }
                                } else {
                                    break
                                }
                            }
                        }
                    }
                }
                "add" {
                    $newEntry = Read-Entry
                    if ($null -ne $newEntry) {
                        $script:VaultData.Entries += $newEntry
                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -Meta $script:VaultMeta -Data $script:VaultData
                        $selectedIndex = $script:VaultData.Entries.Count - 1
                    }
                }
                "edit" {
                    if ($script:VaultData.Entries.Count -gt 0) {
                        $result = Show-EntryList -Entries $script:VaultData.Entries -SelectedIndex $selectedIndex -SearchTerm $searchTerm -AccountName $script:VaultMeta.AccountName -Title "Select entry to edit"
                        if ($null -ne $result) {
                            $selectedIndex = $result.SelectedIndex
                            $searchTerm = $result.SearchTerm
                            if ($result.Action -eq "select") {
                                $entry = $script:VaultData.Entries[$selectedIndex]
                                $updated = Read-Entry -Existing $entry
                                if ($null -ne $updated) {
                                    Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -Meta $script:VaultMeta -Data $script:VaultData
                                }
                            }
                        }
                    }
                }
                "delete" {
                    if ($script:VaultData.Entries.Count -gt 0) {
                        $result = Show-EntryList -Entries $script:VaultData.Entries -SelectedIndex $selectedIndex -SearchTerm $searchTerm -AccountName $script:VaultMeta.AccountName -Title "Select entry to delete"
                        if ($null -ne $result) {
                            $selectedIndex = $result.SelectedIndex
                            $searchTerm = $result.SearchTerm
                            if ($result.Action -eq "select") {
                                $entry = $script:VaultData.Entries[$selectedIndex]
                                if (Confirm-Action "Delete '$($entry.Title)'?") {
                                    $script:VaultData.Entries = @($script:VaultData.Entries | Where-Object { $_.Id -ne $entry.Id })
                                    Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -Meta $script:VaultMeta -Data $script:VaultData
                                    if ($selectedIndex -ge $script:VaultData.Entries.Count) {
                                        $selectedIndex = [Math]::Max(0, $script:VaultData.Entries.Count - 1)
                                    }
                                }
                            }
                        }
                    }
                }
                "export" {
                    Export-VaultData -AccountName $script:VaultMeta.AccountName -VaultData $script:VaultData | Out-Null
                }
                "import-browser" {
                    Import-BrowserPasswords -VaultPath $VaultPath -Meta $script:VaultMeta -Data $script:VaultData -Key $script:VaultKey -AccountName $script:VaultMeta.AccountName | Out-Null
                }
                "browser-links" {
                    Open-BrowserExportLinks
                }
                "recovery" {
                    Invoke-RecoveryOptions -VaultPath $VaultPath -AccountName $script:VaultMeta.AccountName -Meta $script:VaultMeta -Data $script:VaultData -Key $script:VaultKey | Out-Null
                }
                "logout" { break VaultSession }
                "quit" {
                    Stop-VaultX -Message "$script:AppName closed."
                    break VaultSession
                }
            }
            if ($script:QuitRequested) { break }
        }
    } finally {
        Clear-VaultSession
        Clear-Host
    }
}

function Close-VaultX {
    param([string]$Message)
    Clear-VaultSession
    if ($Message) {
        Write-Host $Message -ForegroundColor DarkGray
    }
}

function Stop-VaultX {
    param([string]$Message)
    Clear-VaultSession
    if ($Message) {
        Write-Host $Message -ForegroundColor DarkGray
    }
    $script:QuitRequested = $true
}

function Start-InteractiveShellOnQuit {
    if ($script:IsDotSourced) { return }
    if ($script:SkipShellOnQuit) { return }
    if (-not $script:LaunchedFromFile) { return }
    if ($Host.Name -ne "ConsoleHost") { return }
    try {
        & powershell.exe -NoExit
    } catch {
    }
}

function Register-VaultXSession {
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { return }
    $escaped = $scriptPath.Replace('`', '``').Replace("'", "''")

    if (-not (Test-Path Function:\global:VaultX)) {
        $invoke = [ScriptBlock]::Create("param([object[]]`$Args) & '$escaped' @Args")
        Set-Item -Path Function:\global:VaultX -Value $invoke
    }
    if (-not (Test-Path Function:\global:Close-VaultX)) {
        $close = [ScriptBlock]::Create("& '$escaped' -Close")
        Set-Item -Path Function:\global:Close-VaultX -Value $close
    }
}

function Invoke-VaultX {
    $accounts = Get-Accounts
    $selectedAccount = 0

    try {
        Write-Log "VaultX started."
        Register-VaultXSession
        if (Invoke-UpdateCheck -CurrentVersion $script:AppVersion) {
            return
        }
        while ($true) {
            $accounts = Sync-AccountsWithVaultFiles -Accounts $accounts
            $menu = Show-AccountMenu -Accounts $accounts -Selected $selectedAccount
            if ($null -eq $menu) { break }
            if ($null -ne $menu.Accounts) { $accounts = $menu.Accounts }
            $selectedAccount = $menu.Selected
            switch ($menu.Action) {
                "add" {
                    $created = New-Account -Accounts $accounts
                    if ($null -ne $created) {
                        $accounts = $created.Accounts
                        $selectedAccount = $accounts.Count - 1
                        $vaultPath = Get-VaultPath -FileName $created.Account.File
                        Invoke-VaultSession -VaultPath $vaultPath -Vault $created.Vault
                    }
                }
                "delete" {
                    $chosen = Show-AccountPicker -Accounts $accounts -Title "Select vault to remove"
                    if ($null -ne $chosen) {
                        $accounts = Remove-Account -Accounts $accounts -Selected $chosen
                        if ($selectedAccount -ge $accounts.Count) {
                            $selectedAccount = [Math]::Max(0, $accounts.Count - 1)
                        }
                    }
                }
                "login" {
                    $chosen = Show-AccountPicker -Accounts $accounts -Title "Select vault to open"
                    if ($null -ne $chosen) {
                        $account = $accounts[$chosen]
                        $vaultPath = Get-VaultPath -FileName $account.File
                        $vault = Open-Vault -VaultPath $vaultPath -AccountName $account.Name
                        if ($null -ne $vault) {
                            Invoke-VaultSession -VaultPath $vaultPath -Vault $vault
                        }
                    }
                }
                "import" {
                    $result = Import-VaultData -Accounts $accounts
                    if ($null -ne $result -and $null -ne $result.Accounts) {
                        $accounts = $result.Accounts
                        $selectedAccount = [Math]::Max(0, $accounts.Count - 1)
                    }
                }
                "open-data" {
                    Open-AppDataFolder | Out-Null
                }
                "customize" {
                    Show-CustomizeMenu | Out-Null
                }
                "wipe-cache" {
                    if (Wipe-VaultCache) {
                        $accounts = Sync-AccountsWithVaultFiles -Accounts @()
                        $selectedAccount = 0
                    }
                }
                "quit" {
                    Stop-VaultX -Message "$script:AppName closed."
                    break
                }
            }
            if ($script:QuitRequested) { break }
        }
    } finally {
        Clear-VaultSession
        Write-Log "VaultX session closed."
    }
}

$script:IsDotSourced = $MyInvocation.InvocationName -eq "."
$script:LaunchedFromFile = [string]::IsNullOrWhiteSpace($MyInvocation.Line)
if ($Help) {
    Show-Usage
    return
}

if ($OpenData) {
    Open-AppDataFolder | Out-Null
    return
}

if (-not $script:IsDotSourced) {
    if ($Close) {
        Close-VaultX -Message "$script:AppName closed."
        return
    }
    try {
        Invoke-VaultX
    } catch {
        Show-Message "VaultX hit an unexpected error." ([ConsoleColor]::Red)
        Write-Log ("Unhandled error: {0}" -f $_.Exception.Message)
        Write-Log ($_.Exception | Out-String)
        Wait-ForExit -Prompt "Press Enter to close VaultX."
    } finally {
        Close-VaultX
        if ($script:WaitOnExit) {
            Wait-ForExit -Prompt "Press Enter to close VaultX."
        }
    }
    if ($script:QuitRequested) {
        Start-InteractiveShellOnQuit
        return
    }
}
