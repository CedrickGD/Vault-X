<#
VaultX - simple local password manager (single-user, local encryption)
#>

[CmdletBinding()]
param(
    [switch]$Close,
    [switch]$Gui,
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
$script:DefaultMenuHighlightColor = $script:MenuHighlightColor
$script:DefaultMenuSeparatorColor = $script:MenuSeparatorColor
$script:DefaultMenuDisabledColor = $script:MenuDisabledColor
$script:DefaultHostForegroundColor = $null
$script:GuiTheme = "dark"
$script:FrameBufferActive = $false
$script:FrameBufferLines = @()
$script:LastFrameLineCount = 0
try {
    if ($Host -and $Host.UI -and $Host.UI.RawUI) {
        $script:DefaultHostForegroundColor = $Host.UI.RawUI.ForegroundColor
    }
} catch {
    $script:DefaultHostForegroundColor = $null
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

function ConvertTo-VaultSecureString {
    param([string]$Value)
    if ($null -eq $Value) { return $null }
    $secure = New-Object Security.SecureString
    foreach ($character in $Value.ToCharArray()) {
        $secure.AppendChar($character)
    }
    $secure.MakeReadOnly()
    return $secure
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
        return
    }
}

function ConvertFrom-JsonSafe {
    param(
        [string]$Json,
        [int]$Depth = 6
    )
    $command = Get-Command ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Parameters.ContainsKey("Depth")) {
        return ($Json | ConvertFrom-Json -Depth $Depth)
    }
    return ($Json | ConvertFrom-Json)
}

function Wait-ForExit {
    param([string]$Prompt = "Press Enter to close VaultX.")
    try {
        [void](Read-Host $Prompt)
    } catch {
        return
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

function ConvertTo-NormalizedVersionString {
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
        try { $status = $_.Exception.Response.StatusCode } catch { $status = $null }
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
    $currentClean = ConvertTo-NormalizedVersionString -Value $Current
    $latestClean = ConvertTo-NormalizedVersionString -Value $Latest
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
        Write-Log ("Restart after update failed: {0}" -f $_.Exception.Message)
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
        Write-Log ("TLS 1.2 setup failed: {0}" -f $_.Exception.Message)
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
        $choice = Show-ActionMenu -Title "Update available" -Options @("Update", "Skip") -Subtitle $subtitle
        if ($choice -ne "Update") { return $false }
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

function Get-SafeFileBaseName {
    param([string]$Name, [string]$Fallback = "vault")
    if ([string]::IsNullOrWhiteSpace($Name)) { return $Fallback }
    $safe = $Name.Trim() -replace '[\\/:*?"<>|]', '_'
    $safe = $safe -replace '\s+', '_'
    $safe = $safe -replace '\.+$', ''
    if ([string]::IsNullOrWhiteSpace($safe)) { return $Fallback }
    return $safe
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
    try { $Watcher.EnableRaisingEvents = $false } catch { $null = $Watcher }
    try { $Watcher.Dispose() } catch { $null = $Watcher }
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

function Clear-VaultCache {
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
    if (-not (Confirm-Action "Delete vault '$($account.Name)' and its data? This cannot be undone.")) {
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
        $VaultData,
        $VaultMeta,
        [string]$VaultPath,
        [byte[]]$VaultKey,
        [byte[]]$VaultMacKey
    )
    if (-not (Confirm-VaultTwoFactor -VaultPath $VaultPath -Meta $VaultMeta -Data $VaultData -Key $VaultKey -MacKey $VaultMacKey -IgnoreTrust -Reason "Export requires a 2FA check.")) {
        return $false
    }
    Clear-Host
    Write-Header "Export vault"
    $baseName = Get-SafeFileBaseName -Name $AccountName -Fallback "vault"
    $defaultName = "{0}_export.json" -f $baseName
    $destination = $null
    while ($true) {
        $choice = Show-ActionMenu -Title "Export location" -Options @("Desktop", "Downloads", "Custom path", "Back") -Subtitle "Choose a destination folder."
        if ($null -eq $choice -or $choice -eq "Back") { return $false }
        if ($choice -eq "Desktop" -or $choice -eq "Downloads") {
            $baseDir = if ($choice -eq "Desktop") { Get-DesktopFolder } else { Get-DownloadsFolder }
            if ([string]::IsNullOrWhiteSpace($baseDir) -or -not (Test-PathSafe -Path $baseDir)) {
                Show-Message "Selected folder is unavailable." ([ConsoleColor]::Red)
                continue
            }
            $destination = Join-Path $baseDir $defaultName
        } else {
            $inputPath = Read-Host "Export folder path (Enter to abort)"
            if ([string]::IsNullOrWhiteSpace($inputPath)) { return $false }
            $inputPath = $inputPath.Trim()
            $lower = $inputPath.ToLowerInvariant()
            if ($lower -eq '$desktop' -or $lower -eq "desktop") {
                $baseDir = Get-DesktopFolder
                if ([string]::IsNullOrWhiteSpace($baseDir)) {
                    Show-Message "Desktop folder unavailable." ([ConsoleColor]::Red)
                    continue
                }
                $destination = Join-Path $baseDir $defaultName
            } elseif ($lower -eq '$downloads' -or $lower -eq "downloads") {
                $baseDir = Get-DownloadsFolder
                if ([string]::IsNullOrWhiteSpace($baseDir)) {
                    Show-Message "Downloads folder unavailable." ([ConsoleColor]::Red)
                    continue
                }
                $destination = Join-Path $baseDir $defaultName
            } else {
                $destination = [Environment]::ExpandEnvironmentVariables($inputPath)
                $destination = $destination.Trim()
                $candidateDir = $null
                if (Test-PathSafe -Path $destination) {
                    try {
                        $item = Get-Item -LiteralPath $destination -ErrorAction Stop
                        if ($item.PSIsContainer) {
                            $candidateDir = $destination
                        } else {
                            $candidateDir = Split-Path -Parent $destination
                        }
                    } catch {
                        $candidateDir = $null
                    }
                }
                if ($null -eq $candidateDir) {
                    if ($destination.EndsWith([IO.Path]::DirectorySeparatorChar)) {
                        $candidateDir = $destination
                    } elseif (-not [string]::IsNullOrWhiteSpace([IO.Path]::GetExtension($destination))) {
                        $candidateDir = Split-Path -Parent $destination
                    } else {
                        $candidateDir = $destination
                    }
                }
                if ([string]::IsNullOrWhiteSpace($candidateDir) -or -not (Test-PathSafe -Path $candidateDir)) {
                    Show-Message "Export path is invalid." ([ConsoleColor]::Red)
                    $destination = $null
                    continue
                }
                $destination = Join-Path $candidateDir $defaultName
            }
        }

        if ([string]::IsNullOrWhiteSpace($destination)) {
            Show-Message "Export path is invalid." ([ConsoleColor]::Red)
            continue
        }
        $destinationDir = Split-Path -Parent $destination
        if ([string]::IsNullOrWhiteSpace($destinationDir)) {
            $destinationDir = $PWD.Path
        }
        if (-not (Test-PathSafe -Path $destinationDir)) {
            Show-Message "Export path is invalid." ([ConsoleColor]::Red)
            $destination = $null
            continue
        }
        break
    }
    $exportChoice = Show-ActionMenu -Title "Export protection" -Options @("Use master password", "Create export password", "Back") -Subtitle "Choose how to protect the export file."
    if ($null -eq $exportChoice -or $exportChoice -eq "Back") { return $false }

    $exportKey = $null
    $exportMacKey = $null
    $salt = $null
    $iterations = $null
    if ($exportChoice -eq "Use master password") {
        $exportKey = $VaultKey
        $exportMacKey = $VaultMacKey
        if ($null -eq $exportKey -or $exportKey.Length -ne 32) {
            Show-Message "Export keys unavailable in this session." ([ConsoleColor]::Red)
            return $false
        }
        $salt = [Convert]::FromBase64String($VaultMeta.Salt)
        $iterations = [int]$VaultMeta.Iterations
    } else {
        $exportPassword = Read-ConfirmedSecret -Title "Export vault" -Prompt "Create export password" -ConfirmPrompt "Confirm export password"
        if ([string]::IsNullOrEmpty($exportPassword)) { return $false }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $pair = Get-KeyPairFromPassword -Password $exportPassword -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-Message "Unable to derive export key." ([ConsoleColor]::Red)
            return $false
        }
        $exportKey = $pair.EncKey
        $exportMacKey = $pair.MacKey
    }

    $exportData = Copy-VaultData -VaultData $VaultData
    Remove-VaultTotpSecret -VaultData $exportData
    $meta = [ordered]@{
        Version = 2
        VaultId = [guid]::NewGuid().ToString()
        AccountName = $AccountName
        Salt = [Convert]::ToBase64String($salt)
        Iterations = $iterations
        IV = ""
        Data = ""
    }
    Save-Vault -VaultPath $destination -Key $exportKey -MacKey $exportMacKey -Meta $meta -Data $exportData
    Show-Message "Vault exported." ([ConsoleColor]::Green)
    return $true
}

function Import-VaultData {
    param([array]$Accounts)
    $accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
    Clear-Host
    Write-Header "Import vault"
    $dataDir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dataDir)) { $dataDir = "(unknown)" }
    Write-Host ("Data folder: " + $dataDir) -ForegroundColor DarkGray
    Write-Host "Paste the exported vault file path below." -ForegroundColor DarkGray
    Write-Host ""
    $path = Read-Host "Vault file path (Enter to abort)"
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

function Get-CsvFieldValue {
    param(
        $Row,
        [string[]]$Names
    )
    if ($null -eq $Row -or $null -eq $Names) { return "" }
    foreach ($name in $Names) {
        foreach ($prop in $Row.PSObject.Properties) {
            if ($prop.Name -ieq $name) {
                if ($null -ne $prop.Value) {
                    $value = $prop.Value.ToString().Trim()
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        return $value
                    }
                }
            }
        }
    }
    return ""
}

function Convert-CsvRowToEntry {
    param($Row)
    if ($null -eq $Row) { return $null }
    $title = Get-CsvFieldValue -Row $Row -Names @("name", "title", "site", "site_name", "label")
    $url = Get-CsvFieldValue -Row $Row -Names @("url", "origin_url", "origin", "hostname", "host", "website", "site", "form_action_origin", "formActionOrigin", "login_uri", "uri", "domain")
    $username = Get-CsvFieldValue -Row $Row -Names @("username", "user", "login", "login_username", "login_name", "user_name")
    $password = Get-CsvFieldValue -Row $Row -Names @("password", "pass", "password_value", "passwords", "secret")
    $email = Get-CsvFieldValue -Row $Row -Names @("email", "email_address", "e-mail")
    $phone = Get-CsvFieldValue -Row $Row -Names @("phone", "phone_number", "tel")
    $notes = Get-CsvFieldValue -Row $Row -Names @("notes", "note", "comment", "comments", "memo", "description")
    $other = Get-CsvFieldValue -Row $Row -Names @("other", "extra", "misc")

    if ([string]::IsNullOrWhiteSpace($username) -and -not [string]::IsNullOrWhiteSpace($email)) {
        $username = $email
    }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = $url }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = $username }
    if ([string]::IsNullOrWhiteSpace($title)) { $title = "Imported entry" }

    if ([string]::IsNullOrWhiteSpace($title) -and [string]::IsNullOrWhiteSpace($url) -and [string]::IsNullOrWhiteSpace($username) -and [string]::IsNullOrWhiteSpace($password)) {
        return $null
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

function Import-CsvEntries {
    param([array]$Entries)
    $entries = if ($null -eq $Entries) { @() } else { @($Entries) }
    Clear-Host
    Write-Header "Import CSV"
    Write-Host "Browser CSV exports (Chrome, Edge, Firefox) are supported." -ForegroundColor DarkGray
    Write-Host ""
    $path = Read-Host "CSV file path (Enter to abort)"
    if ([string]::IsNullOrWhiteSpace($path)) { return @{ Entries = $entries; Imported = 0 } }
    $path = $path.Trim().Trim('"').Trim("'")
    if (-not (Test-PathSafe -Path $path)) {
        Show-Message "CSV path is invalid or not found." ([ConsoleColor]::Red)
        return @{ Entries = $entries; Imported = 0 }
    }
    try {
        $rows = Import-Csv -LiteralPath $path
    } catch {
        Show-Message "CSV file is unreadable." ([ConsoleColor]::Red)
        return @{ Entries = $entries; Imported = 0 }
    }
    if ($null -eq $rows) {
        Show-Message "CSV file contains no rows." ([ConsoleColor]::Yellow)
        return @{ Entries = $entries; Imported = 0 }
    }
    $rows = @($rows)
    if ($rows.Count -gt 0 -and $rows[0].PSObject.Properties.Count -eq 1) {
        $header = $rows[0].PSObject.Properties[0].Name
        if ($header -like "*;*") {
            try {
                $rows = Import-Csv -LiteralPath $path -Delimiter ';'
                $rows = @($rows)
            } catch {
                Show-Message "CSV delimiter not supported." ([ConsoleColor]::Red)
                return @{ Entries = $entries; Imported = 0 }
            }
        }
    }

    $added = 0
    foreach ($row in $rows) {
        $entry = Convert-CsvRowToEntry -Row $row
        if ($null -ne $entry) {
            $entries += $entry
            $added++
        }
    }

    if ($added -eq 0) {
        Show-Message "No valid entries found." ([ConsoleColor]::Yellow)
    } else {
        Show-Message ("Imported {0} entries." -f $added) ([ConsoleColor]::Green)
    }
    return @{ Entries = $entries; Imported = $added }
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
        $pair = Get-KeyPairFromPassword -Password $password -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-Message "Unable to derive vault key." ([ConsoleColor]::Red)
            return $false
        }
        try {
            $null = Get-DataFromMeta -Meta $meta -Key $pair.EncKey -MacKey $pair.MacKey
            $password = $null
            return $true
        } catch {
            Show-Message "Invalid password or vault corrupted." ([ConsoleColor]::Red)
            if ($recoveryAvailable) {
                $choice = Show-ActionMenu -Title "Password check failed" -Options @("Retry", "Recovery", "Abort") -Subtitle "A recovery password is configured for this vault."
                if ($choice -eq "Recovery") {
                    $recoveryPassword = Read-Host "Recovery password (Enter to abort)" -AsSecureString
                    if ($null -eq $recoveryPassword -or $recoveryPassword.Length -eq 0) { return $false }
                    $recoveryMaterial = Get-MasterKeyFromRecovery -Meta $meta -RecoveryPassword $recoveryPassword
                    $recoveryPassword = $null
                    if ($null -eq $recoveryMaterial) {
                        Show-Message "Invalid recovery password or vault corrupted." ([ConsoleColor]::Red)
                        continue
                    }
                    try {
                        $recoveryPair = Split-KeyMaterial -Material $recoveryMaterial
                        if ($null -eq $recoveryPair) {
                            $recoveryPair = @{ EncKey = $recoveryMaterial; MacKey = $null }
                        }
                        if ((Test-VaultMacRequired -Meta $meta) -and ($null -eq $recoveryPair.MacKey)) {
                            Show-Message "Recovery password must be updated to unlock this vault." ([ConsoleColor]::Red)
                            continue
                        }
                        $null = Get-DataFromMeta -Meta $meta -Key $recoveryPair.EncKey -MacKey $recoveryPair.MacKey
                        return $true
                    } catch {
                        Show-Message "Invalid recovery password or vault corrupted." ([ConsoleColor]::Red)
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

function Get-KeyMaterialFromPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "Password is used to derive encryption material and cleared from memory.")]
    param(
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations,
        [int]$Length
    )
    $derive = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, $Iterations)
    try {
        return $derive.GetBytes($Length)
    } finally {
        $derive.Dispose()
    }
}

function Get-DesktopFolder {
    try {
        $path = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
        if (-not [string]::IsNullOrWhiteSpace($path)) { return $path }
    } catch {
        Write-Log ("Desktop folder lookup failed: {0}" -f $_.Exception.Message)
    }
    return $null
}

function Get-DownloadsFolder {
    try {
        $path = [Environment]::GetFolderPath([Environment+SpecialFolder]::Downloads)
        if (-not [string]::IsNullOrWhiteSpace($path)) { return $path }
    } catch {
        Write-Log ("Downloads folder lookup failed: {0}" -f $_.Exception.Message)
    }
    $userProfilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($userProfilePath)) { return $null }
    $fallback = Join-Path $userProfilePath "Downloads"
    if (Test-PathSafe -Path $fallback) { return $fallback }
    return $userProfilePath
}

function Split-KeyMaterial {
    param([byte[]]$Material)
    if ($null -eq $Material -or $Material.Length -lt 64) { return $null }
    $encKey = New-Object byte[] 32
    $macKey = New-Object byte[] 32
    [Buffer]::BlockCopy($Material, 0, $encKey, 0, 32)
    [Buffer]::BlockCopy($Material, 32, $macKey, 0, 32)
    return @{ EncKey = $encKey; MacKey = $macKey }
}

function Get-KeyPairFromPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "Password is used to derive encryption material and cleared from memory.")]
    param(
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations
    )
    $material = Get-KeyMaterialFromPassword -Password $Password -Salt $Salt -Iterations $Iterations -Length 64
    $pair = Split-KeyMaterial -Material $material
    if ($null -eq $pair) { return $null }
    return $pair
}

function Get-CombinedKeyMaterial {
    param(
        [byte[]]$EncKey,
        [byte[]]$MacKey
    )
    if ($null -eq $EncKey -or $EncKey.Length -ne 32) { return $null }
    if ($null -eq $MacKey -or $MacKey.Length -ne 32) { return $EncKey }
    $material = New-Object byte[] 64
    [Buffer]::BlockCopy($EncKey, 0, $material, 0, 32)
    [Buffer]::BlockCopy($MacKey, 0, $material, 32, 32)
    return $material
}

function Get-KeyFromPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification = "Password is used to derive an encryption key and cleared from memory.")]
    param(
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations
    )
    return (Get-KeyMaterialFromPassword -Password $Password -Salt $Salt -Iterations $Iterations -Length 32)
}

function Get-VaultVersion {
    param($Meta)
    if ($null -eq $Meta) { return 1 }
    $raw = Get-VaultMetaValue -Meta $Meta -Name "Version"
    if ($null -eq $raw) { return 1 }
    $version = 0
    if ([int]::TryParse($raw.ToString(), [ref]$version)) {
        if ($version -lt 1) { return 1 }
        return $version
    }
    return 1
}

function Get-VaultMetaValue {
    param(
        $Meta,
        [string]$Name
    )
    if ($null -eq $Meta -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Meta -is [System.Collections.IDictionary]) {
        if ($Meta.Contains($Name)) { return $Meta[$Name] }
        return $null
    }
    if ($Meta.PSObject.Properties.Match($Name).Count -gt 0) {
        return $Meta.$Name
    }
    return $null
}

function Set-VaultMetaValue {
    param(
        $Meta,
        [string]$Name,
        $Value
    )
    if ($null -eq $Meta -or [string]::IsNullOrWhiteSpace($Name)) { return }
    if ($Meta -is [System.Collections.IDictionary]) {
        $Meta[$Name] = $Value
        return
    }
    $Meta | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Remove-VaultMetaValue {
    param(
        $Meta,
        [string]$Name
    )
    if ($null -eq $Meta -or [string]::IsNullOrWhiteSpace($Name)) { return }
    if ($Meta -is [System.Collections.IDictionary]) {
        $Meta.Remove($Name) | Out-Null
        return
    }
    $Meta.PSObject.Properties.Remove($Name)
}

function Initialize-VaultId {
    param($Meta)
    $current = Get-VaultMetaValue -Meta $Meta -Name "VaultId"
    if ([string]::IsNullOrWhiteSpace($current)) {
        $current = [guid]::NewGuid().ToString()
        Set-VaultMetaValue -Meta $Meta -Name "VaultId" -Value $current
    }
    return $current
}

function Test-VaultMacRequired {
    param($Meta)
    $version = Get-VaultVersion -Meta $Meta
    if ($version -ge 2) { return $true }
    $mac = Get-VaultMetaValue -Meta $Meta -Name "Mac"
    if ($Meta -and -not [string]::IsNullOrWhiteSpace($mac)) { return $true }
    return $false
}

function Compare-BytesConstantTime {
    param([byte[]]$Left, [byte[]]$Right)
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    if ($Left.Length -ne $Right.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $diff = $diff -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($diff -eq 0)
}

function New-HmacSignature {
    param(
        [byte[]]$MacKey,
        [byte[]]$IV,
        [byte[]]$CipherBytes
    )
    if ($null -eq $MacKey -or $MacKey.Length -ne 32) { return $null }
    if ($null -eq $IV) { $IV = @() }
    if ($null -eq $CipherBytes) { $CipherBytes = @() }
    $payload = New-Object byte[] ($IV.Length + $CipherBytes.Length)
    if ($IV.Length -gt 0) {
        [Buffer]::BlockCopy($IV, 0, $payload, 0, $IV.Length)
    }
    if ($CipherBytes.Length -gt 0) {
        [Buffer]::BlockCopy($CipherBytes, 0, $payload, $IV.Length, $CipherBytes.Length)
    }
    $hmac = [Security.Cryptography.HMACSHA256]::new($MacKey)
    try {
        $hash = $hmac.ComputeHash($payload)
        return [Convert]::ToBase64String($hash)
    } finally {
        $hmac.Dispose()
    }
}

function Test-HmacSignature {
    param(
        [byte[]]$MacKey,
        [byte[]]$IV,
        [byte[]]$CipherBytes,
        [string]$Expected
    )
    if ([string]::IsNullOrWhiteSpace($Expected)) { return $false }
    $expectedBytes = $null
    try { $expectedBytes = [Convert]::FromBase64String($Expected) } catch { return $false }
    $actualBase64 = New-HmacSignature -MacKey $MacKey -IV $IV -CipherBytes $CipherBytes
    if ([string]::IsNullOrWhiteSpace($actualBase64)) { return $false }
    $actualBytes = [Convert]::FromBase64String($actualBase64)
    return (Compare-BytesConstantTime -Left $actualBytes -Right $expectedBytes)
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
        [byte[]]$MacKey,
        $Meta,
        $Data
    )
    if ($null -eq $Data.Entries) {
        $Data | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $json = $Data | ConvertTo-Json -Depth 6
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($json)
    $encrypted = Protect-Bytes -PlainBytes $plainBytes -Key $Key
    Set-VaultMetaValue -Meta $Meta -Name "IV" -Value $encrypted.IV
    Set-VaultMetaValue -Meta $Meta -Name "Data" -Value $encrypted.Data
    $null = Initialize-VaultId -Meta $Meta
    $macReady = ($null -ne $MacKey -and $MacKey.Length -eq 32)
    if ($macReady) {
        $ivBytes = [Convert]::FromBase64String($encrypted.IV)
        $cipherBytes = [Convert]::FromBase64String($encrypted.Data)
        Set-VaultMetaValue -Meta $Meta -Name "Mac" -Value (New-HmacSignature -MacKey $MacKey -IV $ivBytes -CipherBytes $cipherBytes)
        if (Get-VaultVersion -Meta $Meta -lt 2) {
            Set-VaultMetaValue -Meta $Meta -Name "Version" -Value 2
        }
    } else {
        Remove-VaultMetaValue -Meta $Meta -Name "Mac"
        if ($null -eq (Get-VaultMetaValue -Meta $Meta -Name "Version")) {
            Set-VaultMetaValue -Meta $Meta -Name "Version" -Value 1
        }
    }
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
        [byte[]]$Key,
        [byte[]]$MacKey
    )
    if ([string]::IsNullOrEmpty($Meta.Data)) {
        if (Test-VaultMacRequired -Meta $Meta) {
            throw "Vault integrity check failed."
        }
        return [ordered]@{ Entries = @() }
    }
    if ([string]::IsNullOrWhiteSpace($Meta.IV)) {
        throw "Vault file is invalid."
    }
    $iv = [Convert]::FromBase64String($Meta.IV)
    $cipher = [Convert]::FromBase64String($Meta.Data)
    if (Test-VaultMacRequired -Meta $Meta) {
        if ($null -eq $MacKey -or $MacKey.Length -ne 32) {
            throw "Vault integrity check failed."
        }
        if (-not (Test-HmacSignature -MacKey $MacKey -IV $iv -CipherBytes $cipher -Expected $Meta.Mac)) {
            throw "Vault integrity check failed."
        }
    }
    $plainBytes = Unprotect-Bytes -CipherBytes $cipher -Key $Key -IV $iv
    $json = [Text.Encoding]::UTF8.GetString($plainBytes)
    try {
        $data = ConvertFrom-JsonSafe -Json $json -Depth 6
    } catch {
        $data = ConvertFrom-JsonSafe -Json $json -Depth 6
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
    try { [Convert]::FromBase64String($Meta.Salt) | Out-Null } catch { return $false }
    if (-not [string]::IsNullOrWhiteSpace($Meta.IV)) {
        try { [Convert]::FromBase64String($Meta.IV) | Out-Null } catch { return $false }
    }
    if (-not [string]::IsNullOrWhiteSpace($Meta.Data)) {
        try { [Convert]::FromBase64String($Meta.Data) | Out-Null } catch { return $false }
    }
    $version = Get-VaultVersion -Meta $Meta
    if ($version -ge 2) {
        if ([string]::IsNullOrWhiteSpace($Meta.Mac)) { return $false }
        try { [Convert]::FromBase64String($Meta.Mac) | Out-Null } catch { return $false }
    } elseif (-not [string]::IsNullOrWhiteSpace($Meta.Mac)) {
        try { [Convert]::FromBase64String($Meta.Mac) | Out-Null } catch { return $false }
    }
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
                Write-MenuTextLine -Text $line -Color $script:MenuBannerColor -NoEllipsis
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
    $hostLine = "Host: {0}@{1}" -f $env:USERNAME, $env:COMPUTERNAME
    $titleLine = if ([string]::IsNullOrWhiteSpace($script:AppVersion)) {
        $script:AppName
    } else {
        "{0} v{1}" -f $script:AppName, $script:AppVersion
    }
    Write-MenuTextLine -Text $greeting -Color DarkGray
    Write-MenuTextLine -Text $hostLine -Color DarkGray
    if ($ShowBanner) {
        Write-Banner
        Write-MenuTextLine -Text $titleLine -Color DarkGray
    } else {
        Write-MenuTextLine -Text $titleLine -Color Cyan
    }
    if ($Subtitle) {
        Write-MenuTextLine -Text $Subtitle -Color Gray
    }
    Write-MenuTextLine -Text ""
}

function Write-CompactHeader {
    param(
        [string]$Title,
        [switch]$ShowBanner
    )
    if ($ShowBanner) {
        Write-Banner
        if ([string]::IsNullOrWhiteSpace($script:AppVersion)) {
            Write-MenuTextLine -Text $script:AppName -Color DarkGray
        } else {
            Write-MenuTextLine -Text ("{0} v{1}" -f $script:AppName, $script:AppVersion) -Color DarkGray
        }
    } else {
        Write-MenuTextLine -Text $script:AppName -Color Cyan
    }
    if ($Title) {
        Write-MenuTextLine -Text $Title -Color Gray
    }
    Write-MenuTextLine -Text ""
}

function Show-Usage {
    Write-Host ("{0} v{1}" -f $script:AppName, $script:AppVersion) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Gray
    Write-Host "  VaultX.ps1             # Launch the app" -ForegroundColor Gray
    Write-Host "  VaultX.ps1 -Gui        # Launch the local GUI" -ForegroundColor Gray
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

function Write-MenuFrame {
    if (-not $script:FrameBufferActive) { return }
    try {
        $width = [Math]::Max(1, (Get-ConsoleWidth))
        $height = [Math]::Max(1, (Get-ConsoleHeight))
        $script:LastFrameLineCount = 0
        if ($null -ne $script:FrameBufferLines) {
            $script:LastFrameLineCount = $script:FrameBufferLines.Count
        }
        [Console]::SetCursorPosition(0, 0)
        $defaultColor = [Console]::ForegroundColor
        for ($i = 0; $i -lt $height; $i++) {
            $lineText = ""
            $lineColor = $defaultColor
            if ($i -lt $script:FrameBufferLines.Count) {
                $lineText = $script:FrameBufferLines[$i].Text
                $lineColor = $script:FrameBufferLines[$i].Color
            }
            if ($lineText.Length -gt $width) {
                $lineText = $lineText.Substring(0, $width)
            }
            $render = $lineText.PadRight($width)
            if ($null -ne $lineColor) {
                [Console]::ForegroundColor = $lineColor
            }
            [Console]::Write($render)
            if ($i -lt ($height - 1)) {
                [Console]::Write("`r`n")
            }
        }
        [Console]::ForegroundColor = $defaultColor
        try {
            $targetRow = [Math]::Min([Math]::Max(0, $script:LastFrameLineCount), [Math]::Max(0, $height - 1))
            [Console]::SetCursorPosition(0, $targetRow)
        } catch {
            Write-Log ("Frame cursor reset failed: {0}" -f $_.Exception.Message)
        }
    } catch {
        Clear-Host
        foreach ($line in $script:FrameBufferLines) {
            Write-Host $line.Text -ForegroundColor $line.Color
        }
    } finally {
        $script:FrameBufferLines = @()
        $script:FrameBufferActive = $false
    }
}

function Add-MenuFrameLine {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    if ($script:FrameBufferActive) {
        $script:FrameBufferLines += [pscustomobject]@{
            Text = $Text
            Color = $Color
        }
        return
    }
    Write-Host $Text -ForegroundColor $Color
}

function Read-MenuKey {
    Write-MenuFrame
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
        return $false
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
    Write-MenuFrame
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
        Write-Log ("Cursor visibility update failed: {0}" -f $_.Exception.Message)
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

function Clear-VaultSession {
    $script:VaultMeta = $null
    $script:VaultData = $null
    $script:VaultKey = $null
    $script:VaultMacKey = $null
}

function Get-ConsoleWidth {
    try {
        $width = [Console]::WindowWidth
        if ($width -gt 1) { return ($width - 1) }
        return $width
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

function Write-MenuTextLine {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [switch]$NoEllipsis
    )
    $width = [Math]::Max(1, (Get-ConsoleWidth))
    if ($NoEllipsis) {
        if ([string]::IsNullOrEmpty($Text)) {
            $safeText = ""
        } elseif ($Text.Length -le $width) {
            $safeText = $Text
        } else {
            $safeText = $Text.Substring(0, $width)
        }
    } else {
        $safeText = Format-MenuText -Text $Text -Max $width
    }
    $render = $safeText.PadRight($width)
    Add-MenuFrameLine -Text $render -Color $Color
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
    if ($Indent -gt 0) { $line = (" " * $Indent) + $line }
    Add-MenuFrameLine -Text $line -Color $script:MenuSeparatorColor
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
    if ($trimmed -match "^(?i)#?[0-9a-f]{6}$" -or $trimmed -match "^(?i)#?[0-9a-f]{3}$") {
        $hex = $trimmed.TrimStart("#")
        if ($hex.Length -eq 3) {
            $hex = ($hex[0].ToString() * 2) + ($hex[1].ToString() * 2) + ($hex[2].ToString() * 2)
        }
        $r = [Convert]::ToInt32($hex.Substring(0, 2), 16)
        $g = [Convert]::ToInt32($hex.Substring(2, 2), 16)
        $b = [Convert]::ToInt32($hex.Substring(4, 2), 16)
        $palette = Get-ConsoleColorPalette
        $closest = $palette | Sort-Object { ($_.R - $r) * ($_.R - $r) + ($_.G - $g) * ($_.G - $g) + ($_.B - $b) * ($_.B - $b) } | Select-Object -First 1
        return $closest.Color
    }
    $normalized = $trimmed.ToLowerInvariant().Replace(" ", "").Replace("-", "")
    $aliases = @{
        "purple" = "Magenta"
        "pink" = "Magenta"
        "violet" = "Magenta"
        "lavender" = "Magenta"
        "fuchsia" = "Magenta"
        "hotpink" = "Magenta"
        "teal" = "Cyan"
        "aqua" = "Cyan"
        "turquoise" = "Cyan"
        "orange" = "DarkYellow"
        "brown" = "DarkYellow"
        "gold" = "Yellow"
        "grey" = "Gray"
        "lightgrey" = "Gray"
        "lightgray" = "Gray"
        "darkgrey" = "DarkGray"
        "darkgray" = "DarkGray"
    }
    if ($aliases.ContainsKey($normalized)) {
        $trimmed = $aliases[$normalized]
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
    $script:MenuHighlightColor = $Color
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            $Host.UI.RawUI.ForegroundColor = $Color
        }
    } catch {
        Write-Log ("Host font color update failed: {0}" -f $_.Exception.Message)
    }
}

function Set-HighlightColor {
    param([ConsoleColor]$Color)
    $script:MenuHighlightColor = $Color
}

function Set-SeparatorColor {
    param([ConsoleColor]$Color)
    $script:MenuSeparatorColor = $Color
}

function Set-DisabledColor {
    param([ConsoleColor]$Color)
    $script:MenuDisabledColor = $Color
}

function Set-PromptColor {
    param([ConsoleColor]$Color)
    $script:MenuPromptColor = $Color
}

function Set-BannerColor {
    param([ConsoleColor]$Color)
    $script:MenuBannerColor = $Color
}

function Get-SettingsPath {
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) { return $null }
    return (Join-Path $dir "settings.json")
}

function Read-Settings {
    $path = Get-SettingsPath
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) { return @{} }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $data = $raw | ConvertFrom-Json
        if ($null -eq $data) { return @{} }
        return $data
    } catch {
        Write-Log ("Settings load failed: {0}" -f $_.Exception.Message)
        return @{}
    }
}

function Write-Settings {
    param($Settings)
    $path = Get-SettingsPath
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
        }
        $json = $Settings | ConvertTo-Json -Depth 4
        Set-Content -Path $path -Value $json -Encoding UTF8
    } catch {
        Write-Log ("Settings save failed: {0}" -f $_.Exception.Message)
    }
}

function Save-UiColorSettings {
    $settings = Read-Settings
    if ($null -eq $settings) { $settings = @{} }
    $settings | Add-Member -NotePropertyName FontColor -NotePropertyValue ($script:MenuNormalColor.ToString()) -Force
    $settings | Add-Member -NotePropertyName HighlightColor -NotePropertyValue ($script:MenuHighlightColor.ToString()) -Force
    $settings | Add-Member -NotePropertyName SeparatorColor -NotePropertyValue ($script:MenuSeparatorColor.ToString()) -Force
    $settings | Add-Member -NotePropertyName DisabledColor -NotePropertyValue ($script:MenuDisabledColor.ToString()) -Force
    $settings | Add-Member -NotePropertyName PromptColor -NotePropertyValue ($script:MenuPromptColor.ToString()) -Force
    $settings | Add-Member -NotePropertyName BannerColor -NotePropertyValue ($script:MenuBannerColor.ToString()) -Force
    Write-Settings -Settings $settings
}

function Clear-UiColorSettings {
    $settings = Read-Settings
    if ($null -eq $settings) { return }
    $names = @("FontColor", "HighlightColor", "SeparatorColor", "DisabledColor", "PromptColor", "BannerColor")
    foreach ($name in $names) {
        if ($settings.PSObject.Properties.Name -contains $name) {
            $settings.PSObject.Properties.Remove($name)
        }
    }
    $path = Get-SettingsPath
    if ($settings.PSObject.Properties.Count -eq 0) {
        if ($path -and (Test-Path $path)) {
            try { Remove-Item -Path $path -Force } catch { Write-Log ("Settings cleanup failed: {0}" -f $_.Exception.Message) }
        }
        return
    }
    Write-Settings -Settings $settings
}

function Initialize-Settings {
    $settings = Read-Settings
    if ($null -eq $settings) { return }
    $colorValue = $settings.FontColor
    if (-not [string]::IsNullOrWhiteSpace($colorValue)) {
        $color = Resolve-ConsoleColor -Value $colorValue
        if ($null -ne $color) {
            Set-FontColor -Color $color
        } else {
            Write-Log ("Invalid saved font color: {0}" -f $colorValue)
        }
    }
    $highlightValue = $settings.HighlightColor
    if (-not [string]::IsNullOrWhiteSpace($highlightValue)) {
        $color = Resolve-ConsoleColor -Value $highlightValue
        if ($null -ne $color) { Set-HighlightColor -Color $color }
    }
    $separatorValue = $settings.SeparatorColor
    if (-not [string]::IsNullOrWhiteSpace($separatorValue)) {
        $color = Resolve-ConsoleColor -Value $separatorValue
        if ($null -ne $color) { Set-SeparatorColor -Color $color }
    }
    $disabledValue = $settings.DisabledColor
    if (-not [string]::IsNullOrWhiteSpace($disabledValue)) {
        $color = Resolve-ConsoleColor -Value $disabledValue
        if ($null -ne $color) { Set-DisabledColor -Color $color }
    }
    $promptValue = $settings.PromptColor
    if (-not [string]::IsNullOrWhiteSpace($promptValue)) {
        $color = Resolve-ConsoleColor -Value $promptValue
        if ($null -ne $color) { Set-PromptColor -Color $color }
    }
    $bannerValue = $settings.BannerColor
    if (-not [string]::IsNullOrWhiteSpace($bannerValue)) {
        $color = Resolve-ConsoleColor -Value $bannerValue
        if ($null -ne $color) { Set-BannerColor -Color $color }
    }
    $guiThemeValue = $settings.GuiTheme
    if (-not [string]::IsNullOrWhiteSpace($guiThemeValue)) {
        $normalizedTheme = $guiThemeValue.Trim().ToLowerInvariant()
        if ($normalizedTheme -in @("dark", "light")) {
            $script:GuiTheme = $normalizedTheme
        }
    }
}

function Get-GuiThemeMode {
    if ([string]::IsNullOrWhiteSpace($script:GuiTheme)) {
        $script:GuiTheme = "dark"
    }
    $normalized = $script:GuiTheme.Trim().ToLowerInvariant()
    if ($normalized -notin @("dark", "light")) {
        $normalized = "dark"
    }
    $script:GuiTheme = $normalized
    return $normalized
}

function Save-GuiThemeSetting {
    param([string]$Theme)
    $normalized = if ([string]::IsNullOrWhiteSpace($Theme)) { "dark" } else { $Theme.Trim().ToLowerInvariant() }
    if ($normalized -notin @("dark", "light")) { $normalized = "dark" }
    $settings = Read-Settings
    if ($null -eq $settings) { $settings = @{} }
    $settings | Add-Member -NotePropertyName GuiTheme -NotePropertyValue $normalized -Force
    Write-Settings -Settings $settings
}

function Set-GuiThemeMode {
    param([string]$Theme)
    $normalized = if ([string]::IsNullOrWhiteSpace($Theme)) { "dark" } else { $Theme.Trim().ToLowerInvariant() }
    if ($normalized -notin @("dark", "light")) { $normalized = "dark" }
    $script:GuiTheme = $normalized
    Save-GuiThemeSetting -Theme $normalized
    return $script:GuiTheme
}

function Switch-GuiThemeMode {
    $current = Get-GuiThemeMode
    if ($current -eq "dark") {
        return (Set-GuiThemeMode -Theme "light")
    }
    return (Set-GuiThemeMode -Theme "dark")
}

function Reset-CustomizationDefaults {
    $script:MenuNormalColor = $script:DefaultMenuNormalColor
    $script:MenuPromptColor = $script:DefaultMenuPromptColor
    $script:MenuBannerColor = $script:DefaultMenuBannerColor
    $script:MenuHighlightColor = $script:DefaultMenuHighlightColor
    $script:MenuSeparatorColor = $script:DefaultMenuSeparatorColor
    $script:MenuDisabledColor = $script:DefaultMenuDisabledColor
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI -and $null -ne $script:DefaultHostForegroundColor) {
            $Host.UI.RawUI.ForegroundColor = $script:DefaultHostForegroundColor
        }
    } catch {
        Write-Log ("Reset customization defaults failed: {0}" -f $_.Exception.Message)
    }
    Clear-UiColorSettings
}

function Get-UiColorSnapshot {
    $hostColor = $null
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI) {
            $hostColor = $Host.UI.RawUI.ForegroundColor
        }
    } catch {
        $hostColor = $null
    }
    return [ordered]@{
        Normal    = $script:MenuNormalColor
        Prompt    = $script:MenuPromptColor
        Banner    = $script:MenuBannerColor
        Highlight = $script:MenuHighlightColor
        Separator = $script:MenuSeparatorColor
        Disabled  = $script:MenuDisabledColor
        HostFg    = $hostColor
    }
}

function Restore-UiColorSnapshot {
    param($Snapshot)
    if ($null -eq $Snapshot) { return }
    $script:MenuNormalColor = $Snapshot.Normal
    $script:MenuPromptColor = $Snapshot.Prompt
    $script:MenuBannerColor = $Snapshot.Banner
    $script:MenuHighlightColor = $Snapshot.Highlight
    $script:MenuSeparatorColor = $Snapshot.Separator
    $script:MenuDisabledColor = $Snapshot.Disabled
    try {
        if ($Host -and $Host.UI -and $Host.UI.RawUI -and $null -ne $Snapshot.HostFg) {
            $Host.UI.RawUI.ForegroundColor = $Snapshot.HostFg
        }
    } catch {
        Write-Log ("Restore UI color snapshot failed: {0}" -f $_.Exception.Message)
    }
}

function Invoke-ColorPreview {
    param(
        [string]$Title,
        [ScriptBlock]$Apply,
        [ConsoleColor]$Color
    )
    $snapshot = Get-UiColorSnapshot
    try {
        & $Apply $Color
        Clear-Host
        Write-CompactHeader -Title $Title
        Write-MenuRule -Char '-'
        Write-MenuItem -Text (Format-MenuLabel -Label "Sample" -IsSelected $true) -IsSelected $true -Color $script:MenuHighlightColor -Indent 0
        Write-MenuItem -Text (Format-MenuLabel -Label "Option" -IsSelected $false) -IsSelected $false -Color $script:MenuNormalColor -Indent 0
        Write-MenuItem -Text (Format-MenuLabel -Label "Disabled" -IsSelected $false) -IsSelected $false -IsActive:$false -Color $script:MenuDisabledColor -Indent 0
        Write-Host ""
        Write-Host "Prompt text" -ForegroundColor $script:MenuPromptColor
        Write-Host "Banner text" -ForegroundColor $script:MenuBannerColor
        Write-Host ""
        $choice = Read-Host "Apply color? (Y/N)"
        if ($choice -match '^(?i)y') {
            return $true
        }
        Restore-UiColorSnapshot -Snapshot $snapshot
        return $false
    } catch {
        Restore-UiColorSnapshot -Snapshot $snapshot
        Show-Message "Color preview failed." ([ConsoleColor]::Red)
        return $false
    }
}

function Invoke-FontColorPrompt {
    Clear-Host
    Write-Header "Customize Script"
    Write-Host "Enter a color name (e.g., Cyan), number (0-15), or hex (#RRGGBB)." -ForegroundColor DarkGray
    $names = [Enum]::GetNames([ConsoleColor]) -join ", "
    Write-Host ("Available colors: " + $names) -ForegroundColor DarkGray
    Write-Host "Aliases: Purple, Pink, Violet, Teal, Aqua, Orange, Grey." -ForegroundColor DarkGray
    Write-Host ""
    $colorInput = Read-Host "Font color"
    $color = Resolve-ConsoleColor -Value $colorInput
    if ($null -eq $color) {
        Show-Message "Invalid color value." ([ConsoleColor]::Red)
        return $false
    }
    $applied = Invoke-ColorPreview -Title "Font color preview" -Apply { param($c) Set-FontColor -Color $c } -Color $color
    if (-not $applied) { return $false }
    Save-UiColorSettings
    Show-Message ("Font color set to " + $color + ".") ([ConsoleColor]::Green)
    return $true
}

function Invoke-UiColorPrompt {
    param(
        [string]$Label,
        [ScriptBlock]$Apply
    )
    Clear-Host
    Write-Header "Customize Script"
    Write-Host "Enter a color name (e.g., Cyan), number (0-15), or hex (#RRGGBB)." -ForegroundColor DarkGray
    $names = [Enum]::GetNames([ConsoleColor]) -join ", "
    Write-Host ("Available colors: " + $names) -ForegroundColor DarkGray
    Write-Host "Aliases: Purple, Pink, Violet, Teal, Aqua, Orange, Grey." -ForegroundColor DarkGray
    Write-Host ""
    $colorInput = Read-Host "$Label color"
    $color = Resolve-ConsoleColor -Value $colorInput
    if ($null -eq $color) {
        Show-Message "Invalid color value." ([ConsoleColor]::Red)
        return $false
    }
    $applied = Invoke-ColorPreview -Title "$Label color preview" -Apply $Apply -Color $color
    if (-not $applied) { return $false }
    Save-UiColorSettings
    Show-Message ("{0} color set to {1}." -f $Label, $color) ([ConsoleColor]::Green)
    return $true
}

function Show-UiColorsMenu {
    while ($true) {
        $choice = Show-ActionMenu -Title "Other UI colors" -Options @("Highlight", "Separator", "Disabled", "Prompt", "Banner", "Back")
        if ($null -eq $choice -or $choice -eq "Back") { return }
        switch ($choice) {
            "Highlight" { Invoke-UiColorPrompt -Label "Highlight" -Apply { param($c) Set-HighlightColor -Color $c } | Out-Null }
            "Separator" { Invoke-UiColorPrompt -Label "Separator" -Apply { param($c) Set-SeparatorColor -Color $c } | Out-Null }
            "Disabled" { Invoke-UiColorPrompt -Label "Disabled" -Apply { param($c) Set-DisabledColor -Color $c } | Out-Null }
            "Prompt" { Invoke-UiColorPrompt -Label "Prompt" -Apply { param($c) Set-PromptColor -Color $c } | Out-Null }
            "Banner" { Invoke-UiColorPrompt -Label "Banner" -Apply { param($c) Set-BannerColor -Color $c } | Out-Null }
        }
    }
}

function Format-MenuText {
    param([string]$Text, [int]$Max)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($Max -le 0) { return "" }
    if ($Text.Length -le $Max) { return $Text }
    if ($Max -le 3) { return $Text.Substring(0, $Max) }
    return ($Text.Substring(0, $Max - 3) + "...")
}

function Format-ActionLabel {
    param([string]$Label)
    if ([string]::IsNullOrWhiteSpace($Label)) { return "[Action]" }
    return "[Action] " + $Label
}

function Format-MenuLabel {
    param(
        [string]$Label,
        [bool]$IsSelected
    )
    if ([string]::IsNullOrWhiteSpace($Label)) { return "" }
    if ($IsSelected) {
        return ("[{0}]" -f $Label)
    }
    return (" {0} " -f $Label)
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

function Write-MenuRule {
    param(
        [char]$Char = '-',
        [int]$Indent = 0
    )
    $width = [Math]::Max(10, (Get-ConsoleWidth) - $Indent)
    $line = ($Char.ToString() * $width)
    if ($Indent -gt 0) { $line = (" " * $Indent) + $line }
    Add-MenuFrameLine -Text $line -Color $script:MenuSeparatorColor
}

function Start-MenuFrame {
    param([ref]$IsFirstRender)
    if ($IsFirstRender.Value) {
        try {
            [Console]::SetCursorPosition(0, 0)
        } catch {
            Clear-Host
        }
        $IsFirstRender.Value = $false
    }
    $script:FrameBufferLines = @()
    $script:FrameBufferActive = $true
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
        [int]$Indent = 0,
        [ValidateSet("Left", "Center")]
        [string]$Align = "Left",
        [int]$BlockWidth = 0
    )
    $consoleWidth = [Math]::Max(10, (Get-ConsoleWidth))
    $maxWidth = [Math]::Max(10, $consoleWidth - ($Indent + 4))
    $safeText = Format-MenuText -Text $Text -Max $maxWidth
    if ($Align -eq "Center") {
        $prefix = if ($IsSelected -and $IsActive) { "$script:MenuPointerSymbol " } else { "  " }
        $line = $prefix + $safeText
        $width = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent * 2))
        $padding = [Math]::Max(0, [Math]::Floor(($width - $line.Length) / 2))
        $render = ((" " * $padding) + $line).PadRight($width)
        if ($Indent -gt 0) { $render = (" " * $Indent) + $render }
        Add-MenuFrameLine -Text $render -Color $Color
        return
    }
    if ($BlockWidth -gt 0) {
        $prefix = if ($IsSelected -and $IsActive) { "$script:MenuPointerSymbol " } else { "  " }
        $line = $prefix + $safeText
        $width = [Math]::Max($BlockWidth, $line.Length)
        $screenWidth = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent * 2))
        $padding = [Math]::Max(0, [Math]::Floor(($screenWidth - $width) / 2))
        $render = ((" " * $padding) + $line).PadRight($screenWidth)
        if ($Indent -gt 0) { $render = (" " * $Indent) + $render }
        Add-MenuFrameLine -Text $render -Color $Color
        return
    }
    $prefix = if ($IsSelected -and $IsActive) { "$script:MenuPointerSymbol " } else { "  " }
    $line = $prefix + $safeText
    $renderWidth = [Math]::Max(10, $consoleWidth - $Indent)
    $render = $line.PadRight($renderWidth)
    if ($Indent -gt 0) { $render = (" " * $Indent) + $render }
    Add-MenuFrameLine -Text $render -Color $Color
}

function Show-ActionMenu {
    param(
        [string]$Title,
        [string[]]$Options,
        [string]$Subtitle,
        [int]$Selected = 0,
        [switch]$ShowBanner,
        [string]$Hint = "",
        [bool]$Compact = $true
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
            if ($Compact) {
                Write-CompactHeader -Title $Title -ShowBanner:$ShowBanner
            } else {
                Write-Header $Title -ShowBanner:$ShowBanner
            }
            if ($Subtitle) {
                Write-MenuTextLine -Text $Subtitle -Color DarkGray
                Write-MenuTextLine -Text ""
            }
            $ruleChar = if ($Title -eq "Main Menu") { '=' } else { '-' }
            Write-MenuRule -Char $ruleChar
            for ($i = 0; $i -lt $Options.Count; $i++) {
                if ($i -gt 0 -and $Options[$i] -eq "Back") {
                    Write-MenuRule -Char '-'
                }
                $isSelected = ($i -eq $Selected)
                $line = Format-MenuLabel -Label $Options[$i] -IsSelected $isSelected
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $line -IsSelected $isSelected -Color $color -Indent 0
            }
            if (-not [string]::IsNullOrWhiteSpace($Hint)) {
                Write-MenuTextLine -Text ""
                Write-MenuTextLine -Text $Hint -Color DarkGray
            }
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
        [Security.SecureString]$RecoveryPassword
    )
    if (-not (Test-RecoveryMeta -Meta $Meta)) { return $null }
    if ($null -eq $RecoveryPassword -or $RecoveryPassword.Length -eq 0) { return $null }
    try {
        $recoveryPasswordPlain = Convert-SecureStringToPlain $RecoveryPassword
        if ([string]::IsNullOrEmpty($recoveryPasswordPlain)) { return $null }
        $salt = [Convert]::FromBase64String($Meta.RecoverySalt)
        $iterations = [int]$Meta.RecoveryIterations
        $recoveryKey = Get-KeyFromPassword -Password $recoveryPasswordPlain -Salt $salt -Iterations $iterations
        $iv = [Convert]::FromBase64String($Meta.RecoveryKeyIV)
        $cipher = [Convert]::FromBase64String($Meta.RecoveryKeyData)
        $masterKey = Unprotect-Bytes -CipherBytes $cipher -Key $recoveryKey -IV $iv
        return $masterKey
    } catch {
        return $null
    } finally {
        $recoveryPasswordPlain = $null
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
        $pair = Get-KeyPairFromPassword -Password $password -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-Message "Unable to derive vault key." ([ConsoleColor]::Red)
            return $null
        }
        $data = [ordered]@{ Entries = @() }
        $meta = [ordered]@{
            Version = 2
            VaultId = [guid]::NewGuid().ToString()
            AccountName = $AccountName
            Salt = [Convert]::ToBase64String($salt)
            Iterations = $iterations
            IV = ""
            Data = ""
        }
        Save-Vault -VaultPath $VaultPath -Key $pair.EncKey -MacKey $pair.MacKey -Meta $meta -Data $data
        $password = $null
        return @{
            Meta = $meta
            Data = $data
            Key  = $pair.EncKey
            MacKey = $pair.MacKey
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
        $pair = Get-KeyPairFromPassword -Password $password -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-Message "Unable to derive vault key." ([ConsoleColor]::Red)
            continue
        }
        try {
            $data = Get-DataFromMeta -Meta $meta -Key $pair.EncKey -MacKey $pair.MacKey
            if (-not (Confirm-VaultTwoFactor -VaultPath $VaultPath -Meta $meta -Data $data -Key $pair.EncKey -MacKey $pair.MacKey)) {
                return $null
            }
            $password = $null
            return @{
                Meta = $meta
                Data = $data
                Key  = $pair.EncKey
                MacKey = $pair.MacKey
            }
        } catch {
            Show-Message "Invalid password or vault corrupted." ([ConsoleColor]::Red)
            if ($recoveryAvailable) {
                $choice = Show-ActionMenu -Title "Unlock failed" -Options @("Retry", "Recovery", "Abort") -Subtitle "A recovery password is configured for this vault."
                if ($choice -eq "Recovery") {
                    $recoveryPassword = Read-Host "Recovery password (Enter to abort)" -AsSecureString
                    if ($null -eq $recoveryPassword -or $recoveryPassword.Length -eq 0) { return $null }
                    $recoveryMaterial = Get-MasterKeyFromRecovery -Meta $meta -RecoveryPassword $recoveryPassword
                    $recoveryPassword = $null
                    if ($null -eq $recoveryMaterial) {
                        Show-Message "Invalid recovery password or vault corrupted." ([ConsoleColor]::Red)
                        continue
                    }
                    try {
                        $recoveryPair = Split-KeyMaterial -Material $recoveryMaterial
                        if ($null -eq $recoveryPair) {
                            $recoveryPair = @{ EncKey = $recoveryMaterial; MacKey = $null }
                        }
                        if ((Test-VaultMacRequired -Meta $meta) -and ($null -eq $recoveryPair.MacKey)) {
                            Show-Message "Recovery password must be updated to unlock this vault." ([ConsoleColor]::Red)
                            continue
                        }
                        $data = Get-DataFromMeta -Meta $meta -Key $recoveryPair.EncKey -MacKey $recoveryPair.MacKey
                        if (-not (Confirm-VaultTwoFactor -VaultPath $VaultPath -Meta $meta -Data $data -Key $recoveryPair.EncKey -MacKey $recoveryPair.MacKey)) {
                            return $null
                        }
                        return @{
                            Meta = $meta
                            Data = $data
                            Key  = $recoveryPair.EncKey
                            MacKey = $recoveryPair.MacKey
                        }
                    } catch {
                        Show-Message "Invalid recovery password or vault corrupted." ([ConsoleColor]::Red)
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
        [byte[]]$Key,
        [byte[]]$MacKey
    )
    if ($null -eq $Key -or $Key.Length -ne 32) {
        Show-Message "Recovery options unavailable for this vault session." ([ConsoleColor]::Red)
        return $false
    }
    if ((Test-VaultMacRequired -Meta $Meta) -and ($null -eq $MacKey -or $MacKey.Length -ne 32)) {
        Show-Message "Recovery options unavailable without a valid vault signature key." ([ConsoleColor]::Red)
        return $false
    }
    while ($true) {
        $hasRecovery = Test-RecoveryMeta -Meta $Meta
        $options = if ($hasRecovery) {
            @("Update recovery", "Remove recovery", "Back")
        } else {
            @("Set recovery", "Back")
        }
        $subtitle = "Recovery passwords let you unlock this vault if the master password is lost."
        $choice = Show-ActionMenu -Title "Recovery" -Options $options -Subtitle $subtitle
        if ($null -eq $choice -or $choice -eq "Back") { return $false }
        if ($choice -eq "Remove recovery") {
            if (-not (Confirm-Action "Remove recovery password for this vault?")) { return $false }
            Remove-RecoveryFields -Meta $Meta
            Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            Show-Message "Recovery password removed." ([ConsoleColor]::Green)
            return $true
        }
        $title = if ($AccountName) { "Set recovery password for vault $AccountName" } else { "Set recovery password" }
        $recoveryPassword = Read-ConfirmedSecret -Title $title -Prompt "Create recovery password" -ConfirmPrompt "Confirm recovery password"
        if ([string]::IsNullOrEmpty($recoveryPassword)) { return $false }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $recoveryKey = Get-KeyFromPassword -Password $recoveryPassword -Salt $salt -Iterations $iterations
        $material = Get-CombinedKeyMaterial -EncKey $Key -MacKey $MacKey
        $wrapped = Protect-Bytes -PlainBytes $material -Key $recoveryKey
        $Meta.RecoverySalt = [Convert]::ToBase64String($salt)
        $Meta.RecoveryIterations = $iterations
        $Meta.RecoveryKeyIV = $wrapped.IV
        $Meta.RecoveryKeyData = $wrapped.Data
        Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
        $recoveryPassword = $null
        Show-Message "Recovery password saved." ([ConsoleColor]::Green)
        return $true
    }
}

function ConvertTo-Base32 {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return "" }
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $builder = New-Object System.Text.StringBuilder
    $buffer = 0
    $bitsLeft = 0
    foreach ($b in $Bytes) {
        $buffer = (($buffer -shl 8) -bor $b)
        $bitsLeft += 8
        while ($bitsLeft -ge 5) {
            $bitsLeft -= 5
            $index = ($buffer -shr $bitsLeft) -band 31
            [void]$builder.Append($alphabet[$index])
        }
    }
    if ($bitsLeft -gt 0) {
        $index = (($buffer -shl (5 - $bitsLeft)) -band 31)
        [void]$builder.Append($alphabet[$index])
    }
    return $builder.ToString()
}

function ConvertFrom-Base32 {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $clean = $Text.ToUpperInvariant() -replace "[^A-Z2-7]", ""
    if ([string]::IsNullOrWhiteSpace($clean)) { return @() }
    $map = @{
        'A' = 0;  'B' = 1;  'C' = 2;  'D' = 3;  'E' = 4;  'F' = 5;  'G' = 6;  'H' = 7;
        'I' = 8;  'J' = 9;  'K' = 10; 'L' = 11; 'M' = 12; 'N' = 13; 'O' = 14; 'P' = 15;
        'Q' = 16; 'R' = 17; 'S' = 18; 'T' = 19; 'U' = 20; 'V' = 21; 'W' = 22; 'X' = 23;
        'Y' = 24; 'Z' = 25; '2' = 26; '3' = 27; '4' = 28; '5' = 29; '6' = 30; '7' = 31
    }
    $buffer = 0
    $bitsLeft = 0
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($ch in $clean.ToCharArray()) {
        $key = [string]$ch
        if (-not $map.ContainsKey($key)) { throw "Invalid Base32 character." }
        $buffer = (($buffer -shl 5) -bor $map[$key])
        $bitsLeft += 5
        if ($bitsLeft -ge 8) {
            $bitsLeft -= 8
            $byte = ($buffer -shr $bitsLeft) -band 0xFF
            $bytes.Add([byte]$byte) | Out-Null
        }
    }
    return $bytes.ToArray()
}

function Format-TotpSecret {
    param([string]$Secret)
    if ([string]::IsNullOrWhiteSpace($Secret)) { return "" }
    $clean = ($Secret -replace "\s+", "")
    $groups = @()
    for ($i = 0; $i -lt $clean.Length; $i += 4) {
        $len = [Math]::Min(4, $clean.Length - $i)
        $groups += $clean.Substring($i, $len)
    }
    return ($groups -join " ")
}

function New-TotpSecret {
    $bytes = New-RandomBytes 20
    return (ConvertTo-Base32 -Bytes $bytes)
}

function Get-UnixTimeSeconds {
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Get-TotpCode {
    param(
        [string]$Secret,
        [int]$Digits = 6,
        [int]$StepSeconds = 30,
        [long]$Timestamp
    )
    if ([string]::IsNullOrWhiteSpace($Secret)) { return $null }
    try {
        $secretBytes = ConvertFrom-Base32 -Text $Secret
    } catch {
        return $null
    }
    if ($null -eq $secretBytes -or $secretBytes.Length -eq 0) { return $null }
    if ($null -eq $Timestamp -or $Timestamp -le 0) {
        $Timestamp = Get-UnixTimeSeconds
    }
    $counter = [Math]::Floor($Timestamp / $StepSeconds)
    $counterBytes = [BitConverter]::GetBytes([Int64]$counter)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($counterBytes)
    }
    $hmac = [Security.Cryptography.HMACSHA1]::new($secretBytes)
    try {
        $hash = $hmac.ComputeHash($counterBytes)
    } finally {
        $hmac.Dispose()
    }
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $binary = (($hash[$offset] -band 0x7F) -shl 24) -bor
        (($hash[$offset + 1] -band 0xFF) -shl 16) -bor
        (($hash[$offset + 2] -band 0xFF) -shl 8) -bor
        ($hash[$offset + 3] -band 0xFF)
    $mod = [Math]::Pow(10, $Digits)
    $code = [int]($binary % $mod)
    return $code.ToString(("D{0}" -f $Digits))
}

function Test-TotpCode {
    param(
        [string]$Secret,
        [string]$Code,
        [int]$Digits = 6,
        [int]$StepSeconds = 30
    )
    if ([string]::IsNullOrWhiteSpace($Secret) -or [string]::IsNullOrWhiteSpace($Code)) { return $false }
    $clean = ($Code -replace "\s+", "")
    if ($clean -notmatch "^\d{6}$") { return $false }
    $now = Get-UnixTimeSeconds
    for ($offset = -1; $offset -le 1; $offset++) {
        $timestamp = $now + ($offset * $StepSeconds)
        $candidate = Get-TotpCode -Secret $Secret -Digits $Digits -StepSeconds $StepSeconds -Timestamp $timestamp
        if ($candidate -eq $clean) { return $true }
    }
    return $false
}

function Get-VaultTotpSecret {
    param($VaultData)
    if ($null -eq $VaultData) { return $null }
    if ($VaultData -is [System.Collections.IDictionary]) {
        if ($VaultData.Contains("TotpSecret")) {
            return $VaultData["TotpSecret"]
        }
        return $null
    }
    if ($VaultData.PSObject.Properties.Match("TotpSecret").Count -gt 0) {
        return $VaultData.TotpSecret
    }
    return $null
}

function Set-VaultTotpSecret {
    param($VaultData, [string]$Secret)
    if ($null -eq $VaultData) { return }
    if ($VaultData -is [System.Collections.IDictionary]) {
        $VaultData["TotpSecret"] = $Secret
        return
    }
    $VaultData | Add-Member -NotePropertyName TotpSecret -NotePropertyValue $Secret -Force
}

function Remove-VaultTotpSecret {
    param($VaultData)
    if ($null -eq $VaultData) { return }
    if ($VaultData -is [System.Collections.IDictionary]) {
        $VaultData.Remove("TotpSecret") | Out-Null
        return
    }
    $VaultData.PSObject.Properties.Remove("TotpSecret")
}

function Copy-VaultData {
    param($VaultData)
    if ($null -eq $VaultData) { return $null }
    $json = $VaultData | ConvertTo-Json -Depth 8
    try {
        return (ConvertFrom-JsonSafe -Json $json -Depth 8)
    } catch {
        return (ConvertFrom-JsonSafe -Json $json -Depth 8)
    }
}

function Get-TrustTokenPath {
    param([string]$VaultId)
    if ([string]::IsNullOrWhiteSpace($VaultId)) { return $null }
    $dir = Get-AppDir
    if ([string]::IsNullOrWhiteSpace($dir)) { return $null }
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $safe = ($VaultId -replace "[^A-Za-z0-9\-]", "")
    return (Join-Path $dir ("trust_{0}.json" -f $safe))
}

function Get-TrustTokenPayload {
    param(
        [string]$VaultId,
        [Int64]$ExpiresTicks,
        [string]$DeviceName
    )
    return ("{0}|{1}|{2}" -f $VaultId, $ExpiresTicks, $DeviceName)
}

function New-TrustSignature {
    param(
        [string]$Secret,
        [string]$VaultId,
        [Int64]$ExpiresTicks,
        [string]$DeviceName
    )
    if ([string]::IsNullOrWhiteSpace($Secret)) { return $null }
    try {
        $secretBytes = ConvertFrom-Base32 -Text $Secret
    } catch {
        return $null
    }
    if ($null -eq $secretBytes -or $secretBytes.Length -eq 0) { return $null }
    $payload = Get-TrustTokenPayload -VaultId $VaultId -ExpiresTicks $ExpiresTicks -DeviceName $DeviceName
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $hmac = [Security.Cryptography.HMACSHA256]::new($secretBytes)
    try {
        $hash = $hmac.ComputeHash($payloadBytes)
        return [Convert]::ToBase64String($hash)
    } finally {
        $hmac.Dispose()
    }
}

function Save-TrustToken {
    param(
        [string]$VaultId,
        [string]$Secret,
        [Int64]$ExpiresTicks
    )
    $path = Get-TrustTokenPath -VaultId $VaultId
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $device = $env:COMPUTERNAME
    $signature = New-TrustSignature -Secret $Secret -VaultId $VaultId -ExpiresTicks $ExpiresTicks -DeviceName $device
    if ([string]::IsNullOrWhiteSpace($signature)) { return $false }
    $token = [ordered]@{
        VaultId = $VaultId
        Device = $device
        ExpiresTicks = $ExpiresTicks
        ExpiresUtc = ([DateTime]::new($ExpiresTicks, [DateTimeKind]::Utc)).ToString("o")
        Signature = $signature
    }
    $json = $token | ConvertTo-Json -Depth 4
    Set-Content -Path $path -Value $json -Encoding UTF8
    return $true
}

function Remove-TrustToken {
    param([string]$VaultId)
    $path = Get-TrustTokenPath -VaultId $VaultId
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    if (Test-Path $path) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
}

function Test-TrustToken {
    param(
        [string]$VaultId,
        [string]$Secret
    )
    if ([string]::IsNullOrWhiteSpace($VaultId) -or [string]::IsNullOrWhiteSpace($Secret)) { return $false }
    $path = Get-TrustTokenPath -VaultId $VaultId
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) { return $false }
    $token = $null
    try {
        $token = Get-Content -Path $path -Raw | ConvertFrom-Json
    } catch {
        return $false
    }
    if ($null -eq $token) { return $false }
    if ($token.VaultId -ne $VaultId) { return $false }
    if ($token.Device -ne $env:COMPUTERNAME) { return $false }
    $expiresTicks = 0
    if ($null -ne $token.ExpiresTicks -and [Int64]::TryParse($token.ExpiresTicks.ToString(), [ref]$expiresTicks)) {
    } elseif ($token.ExpiresUtc) {
        $parsed = $null
        if ([DateTime]::TryParse($token.ExpiresUtc.ToString(), [ref]$parsed)) {
            $expiresTicks = $parsed.ToUniversalTime().Ticks
        }
    }
    if ($expiresTicks -le 0) { return $false }
    if ([DateTime]::UtcNow.Ticks -gt $expiresTicks) { return $false }
    $signature = New-TrustSignature -Secret $Secret -VaultId $VaultId -ExpiresTicks $expiresTicks -DeviceName $token.Device
    if ([string]::IsNullOrWhiteSpace($signature)) { return $false }
    $signatureBytes = [Convert]::FromBase64String($signature)
    $expectedBytes = $null
    try { $expectedBytes = [Convert]::FromBase64String($token.Signature) } catch { return $false }
    return (Compare-BytesConstantTime -Left $signatureBytes -Right $expectedBytes)
}

function Confirm-VaultTwoFactor {
    param(
        [string]$VaultPath,
        $Meta,
        $Data,
        [byte[]]$Key,
        [byte[]]$MacKey,
        [switch]$IgnoreTrust,
        [string]$Reason
    )
    $secret = Get-VaultTotpSecret -VaultData $Data
    if ([string]::IsNullOrWhiteSpace($secret)) { return $true }
    $needsSave = $false
    $vaultId = Get-VaultMetaValue -Meta $Meta -Name "VaultId"
    if ([string]::IsNullOrWhiteSpace($vaultId)) {
        $vaultId = Initialize-VaultId -Meta $Meta
        $needsSave = $true
    }
    if (-not $IgnoreTrust) {
        if (Test-TrustToken -VaultId $vaultId -Secret $secret) {
            return $true
        }
    }
    while ($true) {
        Clear-Host
        Write-Header "Two-factor authentication"
        if ($Reason) {
            Write-Host $Reason -ForegroundColor DarkGray
        } else {
            Write-Host "Enter the 6-digit code from your authenticator." -ForegroundColor DarkGray
        }
        Write-Host ""
        $code = Read-Host "2FA code (Enter to abort)"
        if ([string]::IsNullOrWhiteSpace($code)) { return $false }
        if (Test-TotpCode -Secret $secret -Code $code) {
            if (-not $IgnoreTrust) {
                $expires = [DateTime]::UtcNow.AddHours(24)
                Save-TrustToken -VaultId $vaultId -Secret $secret -ExpiresTicks $expires.Ticks | Out-Null
            }
            if ($needsSave -and $VaultPath -and $Key -and $MacKey -and $Meta -and $Data) {
                Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            }
            return $true
        }
        $choice = Show-ActionMenu -Title "Invalid 2FA code" -Options @("Retry", "Abort")
        if ($null -eq $choice -or $choice -eq "Abort") { return $false }
    }
}

function Invoke-TwoFactorSettings {
    param(
        [string]$VaultPath,
        $Meta,
        $Data,
        [byte[]]$Key,
        [byte[]]$MacKey
    )
    if ($null -eq $Key -or $Key.Length -ne 32 -or $null -eq $MacKey -or $MacKey.Length -ne 32) {
        Show-Message "2FA settings unavailable for this vault session." ([ConsoleColor]::Red)
        return $false
    }
    while ($true) {
        $secret = Get-VaultTotpSecret -VaultData $Data
        $options = if ([string]::IsNullOrWhiteSpace($secret)) {
            @("Enable 2FA", "Back")
        } else {
            @("Show secret", "Reconfigure 2FA", "Disable 2FA", "Back")
        }
        $subtitle = if ([string]::IsNullOrWhiteSpace($secret)) {
            "Enable offline 2FA using a TOTP authenticator."
        } else {
            "2FA is enabled. Trusted devices stay unlocked for 24h."
        }
        $choice = Show-ActionMenu -Title "2FA Settings" -Options $options -Subtitle $subtitle
        if ($null -eq $choice -or $choice -eq "Back") { return $false }
        if ($choice -eq "Show secret") {
            Clear-Host
            Write-Header "2FA Secret Key"
            $formatted = Format-TotpSecret -Secret $secret
            Write-Host "Secret key (enter this into Google Authenticator / Authy / Ente):" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host $formatted -ForegroundColor Cyan
            Write-Host ""
            [void](Read-Host "Press Enter to return")
            continue
        }
        if ($choice -eq "Disable 2FA") {
            if (-not (Confirm-Action "Disable 2FA for this vault?")) { continue }
            Remove-VaultTotpSecret -VaultData $Data
            $vaultId = Get-VaultMetaValue -Meta $Meta -Name "VaultId"
            if ($vaultId) { Remove-TrustToken -VaultId $vaultId }
            Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            Show-Message "2FA disabled." ([ConsoleColor]::Green)
            continue
        }
        if ($choice -eq "Enable 2FA" -or $choice -eq "Reconfigure 2FA") {
            $newSecret = New-TotpSecret
            Clear-Host
            Write-Header "Enable 2FA"
            Write-Host "Secret key (enter this into Google Authenticator / Authy / Ente):" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host (Format-TotpSecret -Secret $newSecret) -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Enter the 6-digit code from your authenticator to confirm." -ForegroundColor DarkGray
            Write-Host ""
            $code = Read-Host "2FA code (Enter to abort)"
            if ([string]::IsNullOrWhiteSpace($code)) { continue }
            if (-not (Test-TotpCode -Secret $newSecret -Code $code)) {
                Show-Message "Invalid 2FA code." ([ConsoleColor]::Red)
                continue
            }
        Set-VaultTotpSecret -VaultData $Data -Secret $newSecret
        $vaultId = Initialize-VaultId -Meta $Meta
            Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            $expires = [DateTime]::UtcNow.AddHours(24)
            Save-TrustToken -VaultId $vaultId -Secret $newSecret -ExpiresTicks $expires.Ticks | Out-Null
            Show-Message "2FA enabled and this device is trusted for 24 hours." ([ConsoleColor]::Green)
            continue
        }
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
            Write-MenuTextLine -Text ("Search: " + $SearchTerm) -Color DarkGray
            Write-MenuTextLine -Text "" -Color DarkGray
            Write-MenuSeparator -Indent 0

            $backColor = if ($selectedPos -eq 0) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
            Write-MenuItem -Text "Back" -IsSelected:($selectedPos -eq 0) -IsActive:$true -Color $backColor
            Write-MenuTextLine -Text "" -Color DarkGray
            if ($filtered.Count -eq 0) {
                if ($Entries.Count -eq 0) {
                    Write-MenuTextLine -Text "No entries yet." -Color DarkGray
                } else {
                    Write-MenuTextLine -Text "No matches for current search." -Color DarkGray
                }
            } else {
                $footerLines = 5
                Write-MenuTextLine -Text "Entries" -Color DarkGray
                $headerLines = 0
                if ($script:FrameBufferActive -and $null -ne $script:FrameBufferLines) {
                    $headerLines = $script:FrameBufferLines.Count
                } else {
                    try { $headerLines = [Console]::CursorTop } catch { $headerLines = 0 }
                }
                $available = (Get-ConsoleHeight) - $headerLines - $footerLines
                if ($available -lt 1) { $available = 1 }
                $maxVisible = $available
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
                Write-MenuTextLine -Text "" -Color DarkGray
                if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
                    Write-MenuTextLine -Text ("Showing {0}-{1} of {2}" -f ($start + 1), ($end + 1), $filtered.Count) -Color DarkGray
                } else {
                    Write-MenuTextLine -Text ("Showing {0}-{1} of {2} (total {3})" -f ($start + 1), ($end + 1), $filtered.Count, $Entries.Count) -Color DarkGray
                }
            }

            Write-MenuTextLine -Text "" -Color DarkGray
            Write-MenuTextLine -Text "Up/Down move, Enter select, Esc back." -Color DarkGray
            Write-MenuTextLine -Text "Type to search, Backspace delete." -Color DarkGray

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
            Write-MenuTextLine -Text ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $Accounts.Count; $i++) {
                $isSelected = ($i -eq $selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text (Format-MenuLabel -Label $Accounts[$i].Name -IsSelected $isSelected) -IsSelected $isSelected -Color $color -Indent 0
            }
            $backIndex = $Accounts.Count
            $isSelected = ($selected -eq $backIndex)
            $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
            Write-MenuItem -Text (Format-MenuLabel -Label "Back" -IsSelected $isSelected) -IsSelected $isSelected -Color $color -Indent 0
            Write-MenuTextLine -Text ""
            Write-MenuTextLine -Text "Up/Down move, Enter select, Esc back." -Color DarkGray
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
        [bool]$HasEntries,
        [string]$StartSection = "main"
    )
    $section = if ([string]::IsNullOrWhiteSpace($StartSection)) { "main" } else { $StartSection }
    $title = "Vault"
    if ($AccountName) { $title = "Vault - $AccountName" }
    while ($true) {
        switch ($section) {
            "entries" {
                $entryOptions = @("View All Entries", "Back")
                if ($HasEntries) {
                    $entryOptions = @("View All Entries", "Edit Entry", "Delete Entry", "Back")
                }
                $entryChoice = Show-ActionMenu -Title "Browse Entries" -Options $entryOptions -Hint "Up/Down move, Enter select, Esc back."
                if ($null -eq $entryChoice -or $entryChoice -eq "Back") {
                    $section = "main"
                    continue
                }
                switch ($entryChoice) {
                    "View All Entries" { return @{ Action = "view"; Section = "entries" } }
                    "Edit Entry" { return @{ Action = "edit"; Section = "entries" } }
                    "Delete Entry" { return @{ Action = "delete"; Section = "entries" } }
                }
            }
            "security" {
                $securityChoice = Show-ActionMenu -Title "Security Tools" -Options @("2FA Settings", "Recovery", "Back") -Hint "Up/Down move, Enter select, Esc back."
                if ($null -eq $securityChoice -or $securityChoice -eq "Back") {
                    $section = "main"
                    continue
                }
                if ($securityChoice -eq "2FA Settings") { return @{ Action = "twofactor"; Section = "security" } }
                if ($securityChoice -eq "Recovery") { return @{ Action = "recovery"; Section = "security" } }
            }
            "transfer" {
                $transferChoice = Show-ActionMenu -Title "Backup & Export" -Options @("Export Vault", "Import CSV Entries", "Back") -Hint "Up/Down move, Enter select, Esc back."
                if ($null -eq $transferChoice -or $transferChoice -eq "Back") {
                    $section = "main"
                    continue
                }
                if ($transferChoice -eq "Export Vault") { return @{ Action = "export"; Section = "transfer" } }
                if ($transferChoice -eq "Import CSV Entries") { return @{ Action = "import-csv"; Section = "transfer" } }
            }
            default {
                $choice = Show-ActionMenu -Title $title -Options @("Search Entries", "Add Entry", "Browse Entries", "Security Tools", "Backup & Export", "Lock Vault", "Exit App") -ShowBanner -Hint "Up/Down move, Enter select, Esc back."
                if ($null -eq $choice -or $choice -eq "Lock Vault") { return @{ Action = "logout"; Section = "main" } }
                if ($choice -eq "Search Entries") { return @{ Action = "view"; Section = "entries" } }
                if ($choice -eq "Add Entry") { return @{ Action = "add"; Section = "entries" } }
                if ($choice -eq "Browse Entries") { $section = "entries"; continue }
                if ($choice -eq "Security Tools") { $section = "security"; continue }
                if ($choice -eq "Backup & Export") { $section = "transfer"; continue }
                if ($choice -eq "Exit App") { return @{ Action = "quit"; Section = "main" } }
            }
        }
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
                @{ Label = "Font color"; Action = "font-color" }
                @{ Label = "Other UI colors"; Action = "ui-colors" }
                @{ Label = "Reset"; Action = "reset" }
                @{ Label = "Back"; Action = "back" }
            )
            if ($selectedAction -ge $actions.Count) {
                $selectedAction = [Math]::Max(0, $actions.Count - 1)
            }

            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header "Customize Script"
            Write-MenuTextLine -Text ("Current font color: " + $script:MenuNormalColor) -Color DarkGray
            Write-MenuTextLine -Text ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $isSelected = ($i -eq $selectedAction)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text (Format-MenuLabel -Label $action.Label -IsSelected $isSelected) -IsSelected $isSelected -IsActive:$true -Color $color -Indent 0
            }
            Write-MenuTextLine -Text ""
            Write-MenuTextLine -Text "Up/Down move, Enter select, Esc back." -Color DarkGray
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
                    } elseif ($action -eq "ui-colors") {
                        Show-UiColorsMenu
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
    param(
        [array]$Accounts,
        [int]$Selected = 0,
        [string]$StartSection = "main"
    )
    $menuState = [ordered]@{
        Accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
        SelectedAction = [Math]::Max(0, $Selected)
        VaultStamp = Get-VaultFilesStamp
    }
    $section = if ([string]::IsNullOrWhiteSpace($StartSection)) { "main" } else { $StartSection }
    $cursorState = Get-CursorVisible
    $watcher = New-VaultFolderWatcher
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            switch ($section) {
                "settings" {
                    $settingsOptions = @("Customize", "Clear cache", "Back")
                    $choice = Show-ActionMenu -Title "Script Settings" -Options $settingsOptions -Hint "Up/Down move, Enter select, Esc back."
                    $isFirstRender = $true
                    if ($null -eq $choice -or $choice -eq "Back") {
                        $section = "main"
                        continue
                    }
                    if ($choice -eq "Customize") { return @{ Action = "customize"; Section = "settings"; Selected = 0; Accounts = $menuState.Accounts } }
                    if ($choice -eq "Clear cache") { return @{ Action = "wipe-cache"; Section = "settings"; Selected = 0; Accounts = $menuState.Accounts } }
                }
                "manage" {
                    $manageOptions = @("Remove Vault", "Back")
                    $choice = Show-ActionMenu -Title "Manage Vaults" -Options $manageOptions -Hint "Up/Down move, Enter select, Esc back."
                    $isFirstRender = $true
                    if ($null -eq $choice -or $choice -eq "Back") {
                        $section = "main"
                        continue
                    }
                    if ($choice -eq "Remove Vault") { return @{ Action = "delete"; Section = "manage"; Selected = 0; Accounts = $menuState.Accounts } }
                }
                default {
                    $actions = @()
                    if ($menuState.Accounts.Count -gt 0) {
                        $actions += @{ Label = "Open Existing"; Action = "login" }
                    }
                    $actions += @{ Label = "Create New"; Action = "add" }
                    $actions += @{ Label = "Import Data"; Action = "import" }
                    if ($menuState.Accounts.Count -gt 0) {
                        $actions += @{ Label = "Manage Vaults"; Action = "manage" }
                    }
                    $actions += @{ Label = "Switch to GUI"; Action = "gui" }
                    $actions += @{ Label = "Script Settings"; Action = "settings" }
                    $actions += @{ Label = "Exit App"; Action = "quit" }

                    if ($menuState.SelectedAction -ge $actions.Count) {
                        $menuState.SelectedAction = [Math]::Max(0, $actions.Count - 1)
                    }

                    Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
                    Write-Header "Main Menu" -ShowBanner
                    if ($menuState.Accounts.Count -eq 0) {
                        Write-MenuTextLine -Text "No vaults yet." -Color DarkGray
                    } else {
                        $names = $menuState.Accounts | ForEach-Object { $_.Name } | Sort-Object
                        Write-MenuTextLine -Text ("Vaults: " + ($names -join ", ")) -Color DarkGray
                    }
                    Write-MenuTextLine -Text ""
                    Write-MenuRule -Char '='
                    for ($i = 0; $i -lt $actions.Count; $i++) {
                        $action = $actions[$i]
                        $isSelected = ($i -eq $menuState.SelectedAction)
                        $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                        Write-MenuItem -Text (Format-MenuLabel -Label $action.Label -IsSelected $isSelected) -IsSelected $isSelected -IsActive:$true -Color $color -Indent 0
                    }
                    Write-MenuTextLine -Text ""
                    Write-MenuTextLine -Text "Up/Down move, Enter select, Esc quit." -Color DarkGray
                    $key = Read-MenuKeyWithRefresh -RefreshIntervalMs 700 -OnRefresh {
                        $currentStamp = Get-VaultFilesStamp
                        if ($currentStamp -ne $menuState.VaultStamp) {
                            $menuState.VaultStamp = $currentStamp
                            Clear-VaultCache -Force -Silent | Out-Null
                            $menuState.Accounts = Sync-AccountsWithVaultFiles -Accounts @()
                            $menuState.SelectedAction = 0
                            return $true
                        }
                        return $false
                    } -Watcher $watcher -ChangePollMs 100 -OnChange {
                        Clear-VaultCache -Force -Silent | Out-Null
                        $menuState.Accounts = Sync-AccountsWithVaultFiles -Accounts @()
                        $menuState.VaultStamp = Get-VaultFilesStamp
                        $menuState.SelectedAction = 0
                        return $true
                    }
                    if ($null -eq $key) { continue }
                    switch ($key.Key) {
                        "UpArrow" {
                            if ($menuState.SelectedAction -gt 0) { $menuState.SelectedAction-- } else { $menuState.SelectedAction = $actions.Count - 1 }
                        }
                        "DownArrow" {
                            if ($menuState.SelectedAction -lt ($actions.Count - 1)) { $menuState.SelectedAction++ } else { $menuState.SelectedAction = 0 }
                        }
                        "Enter" {
                            $action = $actions[$menuState.SelectedAction].Action
                            if ($action -eq "settings" -or $action -eq "manage") {
                                $section = $action
                                $isFirstRender = $true
                                continue
                            }
                            return @{ Action = $action; Section = "main"; Selected = 0; Accounts = $menuState.Accounts }
                        }
                        "Escape" {
                            return @{ Action = "quit"; Section = "main"; Selected = 0; Accounts = $menuState.Accounts }
                        }
                    }
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
        $items += @{ Type = "action"; Label = "Open Url" }
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
                    $line = Format-ActionLabel -Label $item.Label
                }
                $isSelected = ($i -eq $selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $line -IsSelected $isSelected -IsActive:$true -Color $color
            }
            Write-MenuTextLine -Text ""
            Write-MenuTextLine -Text "Enter copies field or runs action, Esc back." -Color DarkGray
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
                    } elseif ($item.Label -eq "Open Url") {
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
    $script:VaultMacKey = $Vault.MacKey

    if ($null -eq $script:VaultData.Entries) {
        $script:VaultData | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $selectedIndex = 0
    $searchTerm = ""
    $vaultSection = "main"

    try {
        :VaultSession while ($true) {
            $hasEntries = ($script:VaultData.Entries.Count -gt 0)
            $menu = Show-VaultMenu -AccountName $script:VaultMeta.AccountName -HasEntries $hasEntries -StartSection $vaultSection
            if ($null -eq $menu) { break }
            $vaultSection = if ($menu.Section) { $menu.Section } else { "main" }
            switch ($menu.Action) {
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
                                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -MacKey $script:VaultMacKey -Meta $script:VaultMeta -Data $script:VaultData
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
                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -MacKey $script:VaultMacKey -Meta $script:VaultMeta -Data $script:VaultData
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
                                    Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -MacKey $script:VaultMacKey -Meta $script:VaultMeta -Data $script:VaultData
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
                                    Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -MacKey $script:VaultMacKey -Meta $script:VaultMeta -Data $script:VaultData
                                    if ($selectedIndex -ge $script:VaultData.Entries.Count) {
                                        $selectedIndex = [Math]::Max(0, $script:VaultData.Entries.Count - 1)
                                    }
                                }
                            }
                        }
                    }
                }
                "import-csv" {
                    $result = Import-CsvEntries -Entries $script:VaultData.Entries
                    if ($null -ne $result -and $result.Imported -gt 0) {
                        $script:VaultData.Entries = $result.Entries
                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -MacKey $script:VaultMacKey -Meta $script:VaultMeta -Data $script:VaultData
                        $selectedIndex = [Math]::Max(0, $script:VaultData.Entries.Count - 1)
                    }
                }
                "export" {
                    Export-VaultData -AccountName $script:VaultMeta.AccountName -VaultData $script:VaultData -VaultMeta $script:VaultMeta -VaultPath $VaultPath -VaultKey $script:VaultKey -VaultMacKey $script:VaultMacKey | Out-Null
                }
                "twofactor" {
                    Invoke-TwoFactorSettings -VaultPath $VaultPath -Meta $script:VaultMeta -Data $script:VaultData -Key $script:VaultKey -MacKey $script:VaultMacKey | Out-Null
                }
                "recovery" {
                    Invoke-RecoveryOptions -VaultPath $VaultPath -AccountName $script:VaultMeta.AccountName -Meta $script:VaultMeta -Data $script:VaultData -Key $script:VaultKey -MacKey $script:VaultMacKey | Out-Null
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
        Write-Log ("Interactive shell relaunch failed: {0}" -f $_.Exception.Message)
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

function Initialize-ConsoleWindowInterop {
    if ($script:ConsoleInteropInitialized) { return $true }
    try {
        if (-not ("VaultXConsoleInterop" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class VaultXConsoleInterop
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@ -ErrorAction Stop
        }
        $script:ConsoleInteropInitialized = $true
        return $true
    } catch {
        Write-Log ("Console interop init failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Initialize-GuiFramework {
    if ($script:GuiInitialized) { return $true }
    try {
        if ($Host -and $Host.Runspace -and $Host.Runspace.ApartmentState) {
            $state = $Host.Runspace.ApartmentState.ToString()
            if ($state -ne "STA") {
                Write-Log ("GUI mode requires STA, current state: {0}" -f $state)
                return $false
            }
        }
    } catch {
        Write-Log ("GUI apartment-state check failed: {0}" -f $_.Exception.Message)
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        [System.Windows.Forms.Application]::EnableVisualStyles()
        Initialize-ConsoleWindowInterop | Out-Null
        $script:GuiInitialized = $true
        return $true
    } catch {
        Write-Log ("GUI init failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Set-ConsoleWindowVisible {
    param([bool]$Visible)
    if (-not (Initialize-ConsoleWindowInterop)) { return $false }
    $interop = "VaultXConsoleInterop" -as [type]
    if ($null -eq $interop) { return $false }
    $handle = $interop::GetConsoleWindow()
    if ($handle -eq [IntPtr]::Zero) { return $false }
    $mode = if ($Visible) { 5 } else { 0 }
    return $interop::ShowWindow($handle, $mode)
}

function Get-GuiThemePalette {
    param([string]$Theme)
    $mode = if ([string]::IsNullOrWhiteSpace($Theme)) { Get-GuiThemeMode } else { $Theme.Trim().ToLowerInvariant() }
    if ($mode -eq "light") {
        return @{
            Mode = "light"
            BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
            PanelColor = [System.Drawing.Color]::White
            TextColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
            MutedTextColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
            AccentColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
            InputBackColor = [System.Drawing.Color]::White
            InputTextColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
            ButtonBackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
            ButtonTextColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
            GridColor = [System.Drawing.Color]::FromArgb(224, 224, 224)
            SelectionBackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
            SelectionTextColor = [System.Drawing.Color]::White
            BorderColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
        }
    }
    return @{
        Mode = "dark"
        BackColor = [System.Drawing.Color]::FromArgb(24, 24, 28)
        PanelColor = [System.Drawing.Color]::FromArgb(32, 32, 38)
        TextColor = [System.Drawing.Color]::FromArgb(236, 236, 240)
        MutedTextColor = [System.Drawing.Color]::FromArgb(170, 170, 180)
        AccentColor = [System.Drawing.Color]::FromArgb(88, 166, 255)
        InputBackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
        InputTextColor = [System.Drawing.Color]::FromArgb(242, 242, 245)
        ButtonBackColor = [System.Drawing.Color]::FromArgb(44, 44, 52)
        ButtonTextColor = [System.Drawing.Color]::FromArgb(242, 242, 245)
        GridColor = [System.Drawing.Color]::FromArgb(58, 58, 68)
        SelectionBackColor = [System.Drawing.Color]::FromArgb(58, 110, 165)
        SelectionTextColor = [System.Drawing.Color]::White
        BorderColor = [System.Drawing.Color]::FromArgb(70, 70, 82)
    }
}

function Set-GuiTheme {
    param(
        [object]$Control,
        [string]$Theme
    )
    if ($null -eq $Control) { return }
    $palette = Get-GuiThemePalette -Theme $Theme

    if ($Control -is [System.Windows.Forms.Form]) {
        $Control.BackColor = $palette.BackColor
        $Control.ForeColor = $palette.TextColor
    } elseif ($Control -is [System.Windows.Forms.GroupBox]) {
        $Control.BackColor = $palette.BackColor
        $Control.ForeColor = $palette.TextColor
    } elseif ($Control -is [System.Windows.Forms.Panel]) {
        $Control.BackColor = $palette.PanelColor
        $Control.ForeColor = $palette.TextColor
    } elseif ($Control -is [System.Windows.Forms.Label]) {
        $Control.BackColor = [System.Drawing.Color]::Transparent
        $Control.ForeColor = $palette.TextColor
    } elseif ($Control -is [System.Windows.Forms.CheckBox]) {
        $Control.BackColor = $palette.BackColor
        $Control.ForeColor = $palette.TextColor
    } elseif ($Control -is [System.Windows.Forms.Button]) {
        $Control.BackColor = $palette.ButtonBackColor
        $Control.ForeColor = $palette.ButtonTextColor
        $Control.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $Control.FlatAppearance.BorderColor = $palette.BorderColor
        $Control.FlatAppearance.MouseOverBackColor = $palette.AccentColor
        $Control.FlatAppearance.MouseDownBackColor = $palette.AccentColor
    } elseif ($Control -is [System.Windows.Forms.TextBox]) {
        $Control.BackColor = $palette.InputBackColor
        $Control.ForeColor = $palette.InputTextColor
        if ($Control.ReadOnly) {
            $Control.BackColor = $palette.PanelColor
        }
        $Control.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    } elseif ($Control -is [System.Windows.Forms.ListBox]) {
        $Control.BackColor = $palette.InputBackColor
        $Control.ForeColor = $palette.InputTextColor
        $Control.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    } elseif ($Control -is [System.Windows.Forms.DataGridView]) {
        $Control.BackgroundColor = $palette.InputBackColor
        $Control.GridColor = $palette.GridColor
        $Control.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
        $Control.EnableHeadersVisualStyles = $false
        $Control.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
        $Control.RowHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
        $Control.DefaultCellStyle.BackColor = $palette.InputBackColor
        $Control.DefaultCellStyle.ForeColor = $palette.InputTextColor
        $Control.DefaultCellStyle.SelectionBackColor = $palette.SelectionBackColor
        $Control.DefaultCellStyle.SelectionForeColor = $palette.SelectionTextColor
        $Control.AlternatingRowsDefaultCellStyle.BackColor = if ($palette.Mode -eq "dark") { [System.Drawing.Color]::FromArgb(22, 22, 26) } else { [System.Drawing.Color]::FromArgb(245, 245, 245) }
        $Control.AlternatingRowsDefaultCellStyle.ForeColor = $palette.InputTextColor
        $Control.AlternatingRowsDefaultCellStyle.SelectionBackColor = $palette.SelectionBackColor
        $Control.AlternatingRowsDefaultCellStyle.SelectionForeColor = $palette.SelectionTextColor
        $Control.ColumnHeadersDefaultCellStyle.BackColor = $palette.PanelColor
        $Control.ColumnHeadersDefaultCellStyle.ForeColor = $palette.TextColor
        $Control.ColumnHeadersDefaultCellStyle.SelectionBackColor = $palette.PanelColor
        $Control.ColumnHeadersDefaultCellStyle.SelectionForeColor = $palette.TextColor
    }

    if ($Control.PSObject.Properties.Name -contains "Controls") {
        foreach ($child in $Control.Controls) {
            Set-GuiTheme -Control $child -Theme $palette.Mode
        }
    }
}

function Show-GuiMessage {
    param(
        [string]$Text,
        [string]$Title = $script:AppName,
        [string]$Kind = "Info",
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) {
        Show-Message $Text ([ConsoleColor]::Yellow)
        return
    }
    $icon = [System.Windows.Forms.MessageBoxIcon]::Information
    switch ($Kind.ToLowerInvariant()) {
        "error" { $icon = [System.Windows.Forms.MessageBoxIcon]::Error }
        "warning" { $icon = [System.Windows.Forms.MessageBoxIcon]::Warning }
        "question" { $icon = [System.Windows.Forms.MessageBoxIcon]::Question }
    }
    try {
        if ($null -ne $Owner) {
            [void][System.Windows.Forms.MessageBox]::Show($Owner, $Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon)
        } else {
            [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon)
        }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon)
    }
}

function Show-GuiConfirm {
    param(
        [string]$Text,
        [string]$Title = $script:AppName,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $false }
    try {
        if ($null -ne $Owner) {
            $result = [System.Windows.Forms.MessageBox]::Show($Owner, $Text, $Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        } else {
            $result = [System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        }
    } catch {
        $result = [System.Windows.Forms.MessageBox]::Show($Text, $Title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    }
    return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Show-GuiChoiceDialog {
    param(
        [string]$Title,
        [string]$Message,
        [string[]]$Options,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }
    if ($null -eq $Options -or $Options.Count -eq 0) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ([string]::IsNullOrWhiteSpace($Title)) { $script:AppName } else { $Title }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(540, 180)

    $messageLabel = New-Object System.Windows.Forms.Label
    $messageLabel.AutoSize = $false
    $messageLabel.Text = $Message
    $messageLabel.SetBounds(16, 16, 508, 78)
    $messageLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $form.Controls.Add($messageLabel)

    $buttonWidth = if ($Options.Count -ge 4) { 120 } else { 110 }
    $buttonGap = 10
    $totalWidth = ($Options.Count * $buttonWidth) + ([Math]::Max(0, $Options.Count - 1) * $buttonGap)
    $startX = [Math]::Max(16, [int](($form.ClientSize.Width - $totalWidth) / 2))
    $y = 112
    $buttons = @()
    $cancelButton = $null

    foreach ($option in $Options) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $option
        $button.Tag = $option
        $button.SetBounds($startX, $y, $buttonWidth, 32)
        $button.Add_Click({
            $form.Tag = [string]$this.Tag
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        })
        $buttons += $button
        $form.Controls.Add($button)
        if ($option -match "^(Cancel|Abort|Back|Close|No)$") {
            $cancelButton = $button
        }
        $startX += ($buttonWidth + $buttonGap)
    }

    if ($buttons.Count -gt 0) {
        $form.AcceptButton = $buttons[0]
    }
    if ($null -ne $cancelButton) {
        $form.CancelButton = $cancelButton
    }
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)

    $result = if ($null -ne $Owner) { $form.ShowDialog($Owner) } else { $form.ShowDialog() }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return [string]$form.Tag
    }
    return $null
}

function Show-GuiPromptDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$DefaultValue = "",
        [switch]$IsPassword,
        [switch]$Multiline,
        [switch]$AllowEmpty,
        [string]$OkText = "OK",
        [string]$CancelText = "Cancel",
        [int]$Width = 440,
        [int]$Height = 190,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ([string]::IsNullOrWhiteSpace($Title)) { $script:AppName } else { $Title }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size($Width, $Height)

    $promptLabel = New-Object System.Windows.Forms.Label
    $promptLabel.AutoSize = $false
    $promptLabel.Text = $Prompt
    $promptLabel.SetBounds(16, 16, $Width - 32, 36)
    $promptLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $form.Controls.Add($promptLabel)

    $inputBox = New-Object System.Windows.Forms.TextBox
    $inputHeight = if ($Multiline) { 76 } else { 24 }
    $inputBox.SetBounds(16, 60, $Width - 32, $inputHeight)
    $inputBox.Text = $DefaultValue
    $inputBox.Tag = if ($AllowEmpty) { "allow-empty" } else { "require-value" }
    if ($IsPassword) { $inputBox.UseSystemPasswordChar = $true }
    if ($Multiline) {
        $inputBox.Multiline = $true
        $inputBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    }
    $form.Controls.Add($inputBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = $OkText
    $okButton.SetBounds($Width - 196, $Height - 52, 84, 30)
    $okButton.Add_Click({
        if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($inputBox.Text)) {
            Show-GuiMessage -Text "A value is required." -Title $form.Text -Kind Warning -Owner $form
            return
        }
        $form.Tag = $inputBox.Text
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = $CancelText
    $cancelButton.SetBounds($Width - 104, $Height - 52, 84, 30)
    $cancelButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.Add_Shown({ $inputBox.Focus(); $inputBox.SelectAll() })
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)

    $result = if ($null -ne $Owner) { $form.ShowDialog($Owner) } else { $form.ShowDialog() }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return [string]$form.Tag
    }
    return $null
}

function Read-GuiConfirmedSecret {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$ConfirmPrompt,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ([string]::IsNullOrWhiteSpace($Title)) { $script:AppName } else { $Title }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(470, 210)

    $prompt1 = New-Object System.Windows.Forms.Label
    $prompt1.Text = $Prompt
    $prompt1.SetBounds(16, 18, 438, 18)
    $form.Controls.Add($prompt1)

    $box1 = New-Object System.Windows.Forms.TextBox
    $box1.UseSystemPasswordChar = $true
    $box1.SetBounds(16, 40, 438, 24)
    $form.Controls.Add($box1)

    $prompt2 = New-Object System.Windows.Forms.Label
    $prompt2.Text = $ConfirmPrompt
    $prompt2.SetBounds(16, 80, 438, 18)
    $form.Controls.Add($prompt2)

    $box2 = New-Object System.Windows.Forms.TextBox
    $box2.UseSystemPasswordChar = $true
    $box2.SetBounds(16, 102, 438, 24)
    $form.Controls.Add($box2)

    $showCheck = New-Object System.Windows.Forms.CheckBox
    $showCheck.Text = "Show password"
    $showCheck.SetBounds(16, 136, 120, 22)
    $showCheck.Add_CheckedChanged({
        $visible = -not $showCheck.Checked
        $box1.UseSystemPasswordChar = $visible
        $box2.UseSystemPasswordChar = $visible
    })
    $form.Controls.Add($showCheck)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "Save"
    $okButton.SetBounds(286, 166, 80, 30)
    $okButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($box1.Text) -or [string]::IsNullOrWhiteSpace($box2.Text)) {
            Show-GuiMessage -Text "Both password fields are required." -Title $form.Text -Kind Warning -Owner $form
            return
        }
        if ($box1.Text -ne $box2.Text) {
            Show-GuiMessage -Text "Passwords do not match." -Title $form.Text -Kind Error -Owner $form
            return
        }
        $form.Tag = $box1.Text
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.SetBounds(374, 166, 80, 30)
    $cancelButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.Add_Shown({ $box1.Focus() })
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)

    $result = if ($null -ne $Owner) { $form.ShowDialog($Owner) } else { $form.ShowDialog() }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return [string]$form.Tag
    }
    return $null
}

function Show-GuiReadOnlyTextDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$Value,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ([string]::IsNullOrWhiteSpace($Title)) { $script:AppName } else { $Title }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(520, 220)

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $false
    $label.Text = $Prompt
    $label.SetBounds(16, 16, 488, 34)
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.ReadOnly = $true
    $textBox.Multiline = $true
    $textBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $textBox.Text = $Value
    $textBox.SetBounds(16, 54, 488, 110)
    $form.Controls.Add($textBox)

    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = "Copy"
    $copyButton.SetBounds(332, 178, 80, 30)
    $copyButton.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($textBox.Text)) {
            Set-ClipboardSafe -Value $textBox.Text | Out-Null
        }
    })
    $form.Controls.Add($copyButton)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.SetBounds(424, 178, 80, 30)
    $closeButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $form.Controls.Add($closeButton)

    $form.CancelButton = $closeButton
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)
    if ($null -ne $Owner) {
        [void]$form.ShowDialog($Owner)
    } else {
        [void]$form.ShowDialog()
    }
}

function Show-GuiTotpSetupDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$Secret,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ([string]::IsNullOrWhiteSpace($Title)) { $script:AppName } else { $Title }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(540, 250)

    $label = New-Object System.Windows.Forms.Label
    $label.AutoSize = $false
    $label.Text = $Prompt
    $label.SetBounds(16, 16, 508, 38)
    $form.Controls.Add($label)

    $secretLabel = New-Object System.Windows.Forms.Label
    $secretLabel.Text = "Secret key"
    $secretLabel.SetBounds(16, 66, 120, 18)
    $form.Controls.Add($secretLabel)

    $secretBox = New-Object System.Windows.Forms.TextBox
    $secretBox.ReadOnly = $true
    $secretBox.Text = $Secret
    $secretBox.SetBounds(16, 88, 408, 24)
    $form.Controls.Add($secretBox)

    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = "Copy"
    $copyButton.SetBounds(434, 86, 90, 28)
    $copyButton.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($secretBox.Text)) {
            Set-ClipboardSafe -Value ($secretBox.Text -replace "\s+", "") | Out-Null
        }
    })
    $form.Controls.Add($copyButton)

    $codeLabel = New-Object System.Windows.Forms.Label
    $codeLabel.Text = "Authenticator code"
    $codeLabel.SetBounds(16, 132, 160, 18)
    $form.Controls.Add($codeLabel)

    $codeBox = New-Object System.Windows.Forms.TextBox
    $codeBox.SetBounds(16, 154, 508, 24)
    $form.Controls.Add($codeBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "Confirm"
    $okButton.SetBounds(352, 198, 80, 30)
    $okButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($codeBox.Text)) {
            Show-GuiMessage -Text "Enter the 6-digit code from your authenticator." -Title $form.Text -Kind Warning -Owner $form
            return
        }
        $form.Tag = $codeBox.Text
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.SetBounds(444, 198, 80, 30)
    $cancelButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $form.Add_Shown({ $codeBox.Focus() })
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)

    $result = if ($null -ne $Owner) { $form.ShowDialog($Owner) } else { $form.ShowDialog() }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return [string]$form.Tag
    }
    return $null
}

function Open-WebUrlGui {
    param(
        [string]$Url,
        [object]$Owner
    )
    $normalized = ConvertTo-WebUrl -Url $Url
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        Show-GuiMessage -Text "URL is empty or invalid." -Title "Open URL" -Kind Warning -Owner $Owner
        return
    }
    try {
        Start-Process -FilePath $normalized | Out-Null
    } catch {
        Show-GuiMessage -Text "Unable to open URL on this system." -Title "Open URL" -Kind Error -Owner $Owner
    }
}

function Show-GuiEntryEditor {
    param(
        $Existing,
        [switch]$ReadOnly,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($ReadOnly) { "View Entry" } elseif ($null -ne $Existing) { "Edit Entry" } else { "Add Entry" }
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(660, 600)

    $fieldConfigs = @(
        @{ Name = "Title"; Label = "Name"; Multiline = $false; Password = $false }
        @{ Name = "Url"; Label = "URL"; Multiline = $false; Password = $false }
        @{ Name = "Username"; Label = "Username"; Multiline = $false; Password = $false }
        @{ Name = "Password"; Label = "Password"; Multiline = $false; Password = $true }
        @{ Name = "Phone"; Label = "Phone"; Multiline = $false; Password = $false }
        @{ Name = "Email"; Label = "Email"; Multiline = $false; Password = $false }
        @{ Name = "Notes"; Label = "Notes"; Multiline = $true; Password = $false }
        @{ Name = "Other"; Label = "Other"; Multiline = $true; Password = $false }
    )

    $inputs = @{}
    $y = 16
    foreach ($config in $fieldConfigs) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $config.Label
        $label.SetBounds(16, $y, 120, 18)
        $form.Controls.Add($label)

        $height = if ($config.Multiline) { 72 } else { 24 }
        $inputBox = New-Object System.Windows.Forms.TextBox
        $inputBox.SetBounds(16, $y + 20, 628, $height)
        if ($config.Multiline) {
            $inputBox.Multiline = $true
            $inputBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        }
        if ($ReadOnly) {
            $inputBox.ReadOnly = $true
            $inputBox.TabStop = $false
        }
        if ($config.Password) {
            $inputBox.UseSystemPasswordChar = $true
        }
        if ($null -ne $Existing) {
            $inputBox.Text = [string]($Existing.$($config.Name))
        }
        $inputs[$config.Name] = $inputBox
        $form.Controls.Add($inputBox)

        if ($config.Password) {
            $showCheck = New-Object System.Windows.Forms.CheckBox
            $showCheck.Text = "Show password"
            $showCheck.SetBounds(526, $y - 1, 118, 18)
            $showCheck.Add_CheckedChanged({
                $inputs["Password"].UseSystemPasswordChar = (-not $showCheck.Checked)
            })
            if ($ReadOnly) {
                $showCheck.TabStop = $false
            }
            $form.Controls.Add($showCheck)
        }

        $y += if ($config.Multiline) { 104 } else { 52 }
    }

    if ($ReadOnly) {
        $updatedLabel = New-Object System.Windows.Forms.Label
        $updatedLabel.Text = "Updated"
        $updatedLabel.SetBounds(16, 556, 120, 18)
        $form.Controls.Add($updatedLabel)

        $updatedValue = New-Object System.Windows.Forms.Label
        $updatedValue.Text = if ($null -ne $Existing -and -not [string]::IsNullOrWhiteSpace([string]$Existing.UpdatedAt)) { [string]$Existing.UpdatedAt } else { "(unknown)" }
        $updatedValue.SetBounds(16, 574, 360, 18)
        $form.Controls.Add($updatedValue)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = "Close"
        $closeButton.SetBounds(562, 556, 82, 30)
        $closeButton.Add_Click({
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        })
        $form.Controls.Add($closeButton)

        $form.AcceptButton = $closeButton
        $form.CancelButton = $closeButton
    } else {
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = if ($null -ne $Existing) { "Save" } else { "Add" }
        $okButton.SetBounds(468, 556, 82, 30)
        $okButton.Add_Click({
            $title = $inputs["Title"].Text.Trim()
            if ([string]::IsNullOrWhiteSpace($title)) {
                Show-GuiMessage -Text "Entry name is required." -Title $form.Text -Kind Warning -Owner $form
                return
            }
            $values = [ordered]@{
                Title = $title
                Url = $inputs["Url"].Text.Trim()
                Username = $inputs["Username"].Text.Trim()
                Password = $inputs["Password"].Text
                Phone = $inputs["Phone"].Text.Trim()
                Email = $inputs["Email"].Text.Trim()
                Notes = $inputs["Notes"].Text.Trim()
                Other = $inputs["Other"].Text.Trim()
            }
            $form.Tag = $values
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        })
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"
        $cancelButton.SetBounds(562, 556, 82, 30)
        $cancelButton.Add_Click({
            $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $form.Close()
        })
        $form.Controls.Add($cancelButton)

        $form.AcceptButton = $okButton
        $form.CancelButton = $cancelButton
        $form.Add_Shown({ $inputs["Title"].Focus() })
    }
    Set-GuiTheme -Control $form -Theme (Get-GuiThemeMode)

    $result = if ($null -ne $Owner) { $form.ShowDialog($Owner) } else { $form.ShowDialog() }
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($ReadOnly) { return $Existing }

    $values = $form.Tag
    if ($null -ne $Existing) {
        $Existing.Title = $values.Title
        $Existing.Url = $values.Url
        $Existing.Username = $values.Username
        $Existing.Password = $values.Password
        $Existing.Phone = $values.Phone
        $Existing.Email = $values.Email
        $Existing.Notes = $values.Notes
        $Existing.Other = $values.Other
        $Existing.UpdatedAt = (Get-Date).ToString("s")
        return $Existing
    }

    return [ordered]@{
        Id = [guid]::NewGuid().ToString()
        Title = $values.Title
        Url = $values.Url
        Username = $values.Username
        Password = $values.Password
        Phone = $values.Phone
        Email = $values.Email
        Notes = $values.Notes
        Other = $values.Other
        UpdatedAt = (Get-Date).ToString("s")
    }
}

function Confirm-VaultTwoFactorGui {
    param(
        [string]$VaultPath,
        $Meta,
        $Data,
        [byte[]]$Key,
        [byte[]]$MacKey,
        [switch]$IgnoreTrust,
        [string]$Reason,
        [object]$Owner
    )
    $secret = Get-VaultTotpSecret -VaultData $Data
    if ([string]::IsNullOrWhiteSpace($secret)) { return $true }

    $needsSave = $false
    $vaultId = Get-VaultMetaValue -Meta $Meta -Name "VaultId"
    if ([string]::IsNullOrWhiteSpace($vaultId)) {
        $vaultId = Initialize-VaultId -Meta $Meta
        $needsSave = $true
    }

    if (-not $IgnoreTrust) {
        if (Test-TrustToken -VaultId $vaultId -Secret $secret) {
            return $true
        }
    }

    while ($true) {
        $prompt = if ([string]::IsNullOrWhiteSpace($Reason)) {
            "Enter the 6-digit code from your authenticator."
        } else {
            $Reason
        }
        $code = Show-GuiPromptDialog -Title "Two-factor authentication" -Prompt $prompt -OkText "Verify" -Owner $Owner
        if ([string]::IsNullOrWhiteSpace($code)) { return $false }
        if (Test-TotpCode -Secret $secret -Code $code) {
            if (-not $IgnoreTrust) {
                $expires = [DateTime]::UtcNow.AddHours(24)
                Save-TrustToken -VaultId $vaultId -Secret $secret -ExpiresTicks $expires.Ticks | Out-Null
            }
            if ($needsSave -and $VaultPath -and $Meta -and $Data -and $Key) {
                Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            }
            return $true
        }
        $choice = Show-GuiChoiceDialog -Title "Invalid 2FA code" -Message "The code was not accepted." -Options @("Retry", "Abort") -Owner $Owner
        if ($choice -ne "Retry") { return $false }
    }
}

function Open-VaultGui {
    param(
        [string]$VaultPath,
        [string]$AccountName,
        [switch]$CreateIfMissing,
        [object]$Owner
    )
    if (-not (Test-Path $VaultPath)) {
        if (-not $CreateIfMissing) {
            Show-GuiMessage -Text "Vault not found." -Title "Open Vault" -Kind Error -Owner $Owner
            return $null
        }
        $title = if ($AccountName) { "Set master password for vault $AccountName" } else { "Set master password" }
        $password = Read-GuiConfirmedSecret -Title $title -Prompt "Create master password" -ConfirmPrompt "Confirm master password" -Owner $Owner
        if ([string]::IsNullOrEmpty($password)) { return $null }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $pair = Get-KeyPairFromPassword -Password $password -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-GuiMessage -Text "Unable to derive vault key." -Title "Create Vault" -Kind Error -Owner $Owner
            return $null
        }
        $data = [ordered]@{ Entries = @() }
        $meta = [ordered]@{
            Version = 2
            VaultId = [guid]::NewGuid().ToString()
            AccountName = $AccountName
            Salt = [Convert]::ToBase64String($salt)
            Iterations = $iterations
            IV = ""
            Data = ""
        }
        Save-Vault -VaultPath $VaultPath -Key $pair.EncKey -MacKey $pair.MacKey -Meta $meta -Data $data
        $password = $null
        return @{
            Meta = $meta
            Data = $data
            Key = $pair.EncKey
            MacKey = $pair.MacKey
        }
    }

    try {
        $meta = Get-Content -Path $VaultPath -Raw | ConvertFrom-Json
    } catch {
        Show-GuiMessage -Text "Vault file is corrupted or unreadable." -Title "Open Vault" -Kind Error -Owner $Owner
        return $null
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-GuiMessage -Text "Vault file is invalid." -Title "Open Vault" -Kind Error -Owner $Owner
        return $null
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-GuiMessage -Text "Vault encryption salt is invalid." -Title "Open Vault" -Kind Error -Owner $Owner
        return $null
    }

    $iterations = [int]$meta.Iterations
    $recoveryAvailable = Test-RecoveryMeta -Meta $meta
    $mode = "password"

    while ($true) {
        if ($mode -eq "password") {
            $title = if ($meta.AccountName) { "Unlock vault $($meta.AccountName)" } else { "Unlock vault" }
            $password = Show-GuiPromptDialog -Title $title -Prompt "Master password" -IsPassword -OkText "Unlock" -Owner $Owner
            if ([string]::IsNullOrEmpty($password)) { return $null }
            $pair = Get-KeyPairFromPassword -Password $password -Salt $salt -Iterations $iterations
            if ($null -eq $pair) {
                Show-GuiMessage -Text "Unable to derive vault key." -Title $title -Kind Error -Owner $Owner
                continue
            }
            try {
                $data = Get-DataFromMeta -Meta $meta -Key $pair.EncKey -MacKey $pair.MacKey
                if (-not (Confirm-VaultTwoFactorGui -VaultPath $VaultPath -Meta $meta -Data $data -Key $pair.EncKey -MacKey $pair.MacKey -Owner $Owner)) {
                    return $null
                }
                return @{
                    Meta = $meta
                    Data = $data
                    Key = $pair.EncKey
                    MacKey = $pair.MacKey
                }
            } catch {
                Show-GuiMessage -Text "Invalid password or vault corrupted." -Title $title -Kind Error -Owner $Owner
                if (-not $recoveryAvailable) { continue }
                $choice = Show-GuiChoiceDialog -Title "Unlock failed" -Message "A recovery password is configured for this vault." -Options @("Retry", "Use Recovery", "Abort") -Owner $Owner
                if ($choice -eq "Use Recovery") {
                    $mode = "recovery"
                    continue
                }
                if ($choice -ne "Retry") { return $null }
            } finally {
                $password = $null
            }
        } else {
            $recoveryPassword = Show-GuiPromptDialog -Title "Recovery password" -Prompt "Enter recovery password" -IsPassword -OkText "Unlock" -Owner $Owner
            if ([string]::IsNullOrEmpty($recoveryPassword)) { return $null }
            $recoveryPasswordSecure = ConvertTo-VaultSecureString -Value $recoveryPassword
            $recoveryPassword = $null
            $recoveryMaterial = Get-MasterKeyFromRecovery -Meta $meta -RecoveryPassword $recoveryPasswordSecure
            $recoveryPasswordSecure = $null
            if ($null -eq $recoveryMaterial) {
                Show-GuiMessage -Text "Invalid recovery password or vault corrupted." -Title "Recovery Unlock" -Kind Error -Owner $Owner
                $choice = Show-GuiChoiceDialog -Title "Recovery failed" -Message "Recovery unlock did not succeed." -Options @("Retry Recovery", "Back") -Owner $Owner
                if ($choice -ne "Retry Recovery") {
                    $mode = "password"
                }
                continue
            }
            try {
                $recoveryPair = Split-KeyMaterial -Material $recoveryMaterial
                if ($null -eq $recoveryPair) {
                    $recoveryPair = @{ EncKey = $recoveryMaterial; MacKey = $null }
                }
                if ((Test-VaultMacRequired -Meta $meta) -and ($null -eq $recoveryPair.MacKey)) {
                    Show-GuiMessage -Text "Recovery password must be updated to unlock this vault." -Title "Recovery Unlock" -Kind Error -Owner $Owner
                    $mode = "password"
                    continue
                }
                $data = Get-DataFromMeta -Meta $meta -Key $recoveryPair.EncKey -MacKey $recoveryPair.MacKey
                if (-not (Confirm-VaultTwoFactorGui -VaultPath $VaultPath -Meta $meta -Data $data -Key $recoveryPair.EncKey -MacKey $recoveryPair.MacKey -Owner $Owner)) {
                    return $null
                }
                return @{
                    Meta = $meta
                    Data = $data
                    Key = $recoveryPair.EncKey
                    MacKey = $recoveryPair.MacKey
                }
            } catch {
                Show-GuiMessage -Text "Invalid recovery password or vault corrupted." -Title "Recovery Unlock" -Kind Error -Owner $Owner
                $choice = Show-GuiChoiceDialog -Title "Recovery failed" -Message "Recovery unlock did not succeed." -Options @("Retry Recovery", "Back") -Owner $Owner
                if ($choice -ne "Retry Recovery") {
                    $mode = "password"
                }
            }
        }
    }
}

function New-AccountGui {
    param(
        [array]$Accounts,
        [object]$Owner
    )
    $accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
    while ($true) {
        $name = Show-GuiPromptDialog -Title "Create Vault" -Prompt "Vault name" -OkText "Create" -Owner $Owner
        if ($null -eq $name) { return $null }
        $trimmed = $name.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            Show-GuiMessage -Text "Vault name is required." -Title "Create Vault" -Kind Warning -Owner $Owner
            continue
        }
        $exists = $accounts | Where-Object { $_.Name -ieq $trimmed }
        if ($exists) {
            Show-GuiMessage -Text "Vault already exists." -Title "Create Vault" -Kind Error -Owner $Owner
            continue
        }
        $fileName = Get-AccountFileName -AccountName $trimmed
        $vaultPath = Get-VaultPath -FileName $fileName
        $vault = Open-VaultGui -VaultPath $vaultPath -AccountName $trimmed -CreateIfMissing -Owner $Owner
        if ($null -eq $vault) { return $null }
        $account = [ordered]@{
            Name = $trimmed
            File = $fileName
            CreatedAt = (Get-Date).ToString("s")
        }
        $accounts += $account
        Save-Accounts -Accounts $accounts
        return @{
            Accounts = $accounts
            Account = $account
            Vault = $vault
        }
    }
}

function Import-VaultDataGui {
    param(
        [array]$Accounts,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return $null }
    $accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $dialog.Title = "Import Vault"
    $dialog.RestoreDirectory = $true
    $result = if ($null -ne $Owner) { $dialog.ShowDialog($Owner) } else { $dialog.ShowDialog() }
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return @{ Accounts = $accounts; Imported = $false }
    }

    $path = $dialog.FileName
    if (-not (Test-PathSafe -Path $path)) {
        Show-GuiMessage -Text "Import file path is invalid or not found." -Title "Import Vault" -Kind Error -Owner $Owner
        return @{ Accounts = $accounts; Imported = $false }
    }

    try {
        $meta = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } catch {
        Show-GuiMessage -Text "Import file is corrupted or unreadable." -Title "Import Vault" -Kind Error -Owner $Owner
        return @{ Accounts = $accounts; Imported = $false }
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-GuiMessage -Text "Import file is not a valid vault." -Title "Import Vault" -Kind Error -Owner $Owner
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
        Show-GuiMessage -Text "Vault already exists. Import aborted." -Title "Import Vault" -Kind Error -Owner $Owner
        return @{ Accounts = $accounts; Imported = $false }
    }

    $meta.AccountName = $name
    $json = $meta | ConvertTo-Json -Depth 6
    $dir = Split-Path -Parent $destination
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    Set-Content -Path $destination -Value $json -Encoding UTF8

    $account = [ordered]@{
        Name = $name
        File = $fileName
        CreatedAt = (Get-Date).ToString("s")
    }
    $accounts += $account
    Save-Accounts -Accounts $accounts
    Show-GuiMessage -Text ("Imported vault '{0}'." -f $name) -Title "Import Vault" -Owner $Owner
    return @{
        Accounts = $accounts
        Imported = $true
        Account = $account
    }
}

function Import-CsvEntriesGui {
    param(
        [array]$Entries,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return @{ Entries = $Entries; Imported = 0 } }
    $entries = if ($null -eq $Entries) { @() } else { @($Entries) }

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dialog.Title = "Import CSV Entries"
    $dialog.RestoreDirectory = $true
    $result = if ($null -ne $Owner) { $dialog.ShowDialog($Owner) } else { $dialog.ShowDialog() }
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return @{ Entries = $entries; Imported = 0 }
    }

    $path = $dialog.FileName
    if (-not (Test-PathSafe -Path $path)) {
        Show-GuiMessage -Text "CSV path is invalid or not found." -Title "Import CSV" -Kind Error -Owner $Owner
        return @{ Entries = $entries; Imported = 0 }
    }

    try {
        $rows = Import-Csv -LiteralPath $path
    } catch {
        Show-GuiMessage -Text "CSV file is unreadable." -Title "Import CSV" -Kind Error -Owner $Owner
        return @{ Entries = $entries; Imported = 0 }
    }
    if ($null -eq $rows) {
        Show-GuiMessage -Text "CSV file contains no rows." -Title "Import CSV" -Kind Warning -Owner $Owner
        return @{ Entries = $entries; Imported = 0 }
    }

    $rows = @($rows)
    if ($rows.Count -gt 0 -and $rows[0].PSObject.Properties.Count -eq 1) {
        $header = $rows[0].PSObject.Properties[0].Name
        if ($header -like "*;*") {
            try {
                $rows = @(Import-Csv -LiteralPath $path -Delimiter ';')
            } catch {
                Show-GuiMessage -Text "CSV delimiter not supported." -Title "Import CSV" -Kind Error -Owner $Owner
                return @{ Entries = $entries; Imported = 0 }
            }
        }
    }

    $added = 0
    foreach ($row in $rows) {
        $entry = Convert-CsvRowToEntry -Row $row
        if ($null -ne $entry) {
            $entries += $entry
            $added++
        }
    }

    if ($added -eq 0) {
        Show-GuiMessage -Text "No valid entries found." -Title "Import CSV" -Kind Warning -Owner $Owner
    } else {
        Show-GuiMessage -Text ("Imported {0} entries." -f $added) -Title "Import CSV" -Owner $Owner
    }
    return @{ Entries = $entries; Imported = $added }
}

function Export-VaultDataGui {
    param(
        [string]$AccountName,
        $VaultData,
        $VaultMeta,
        [string]$VaultPath,
        [byte[]]$VaultKey,
        [byte[]]$VaultMacKey,
        [object]$Owner
    )
    if (-not (Confirm-VaultTwoFactorGui -VaultPath $VaultPath -Meta $VaultMeta -Data $VaultData -Key $VaultKey -MacKey $VaultMacKey -IgnoreTrust -Reason "Export requires a 2FA check." -Owner $Owner)) {
        return $false
    }

    if (-not (Initialize-GuiFramework)) { return $false }
    $baseName = Get-SafeFileBaseName -Name $AccountName -Fallback "vault"
    $defaultName = "{0}_export.json" -f $baseName

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
    $dialog.FileName = $defaultName
    $dialog.Title = "Export Vault"
    $dialog.RestoreDirectory = $true
    $result = if ($null -ne $Owner) { $dialog.ShowDialog($Owner) } else { $dialog.ShowDialog() }
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $false }

    $exportChoice = Show-GuiChoiceDialog -Title "Export Protection" -Message "Choose how to protect the export file." -Options @("Use master password", "Create export password", "Cancel") -Owner $Owner
    if ($exportChoice -ne "Use master password" -and $exportChoice -ne "Create export password") { return $false }

    $exportKey = $null
    $exportMacKey = $null
    $salt = $null
    $iterations = $null
    if ($exportChoice -eq "Use master password") {
        $exportKey = $VaultKey
        $exportMacKey = $VaultMacKey
        if ($null -eq $exportKey -or $exportKey.Length -ne 32) {
            Show-GuiMessage -Text "Export keys unavailable in this session." -Title "Export Vault" -Kind Error -Owner $Owner
            return $false
        }
        $salt = [Convert]::FromBase64String($VaultMeta.Salt)
        $iterations = [int]$VaultMeta.Iterations
    } else {
        $exportPassword = Read-GuiConfirmedSecret -Title "Export Vault" -Prompt "Create export password" -ConfirmPrompt "Confirm export password" -Owner $Owner
        if ([string]::IsNullOrEmpty($exportPassword)) { return $false }
        $salt = New-RandomBytes 16
        $iterations = 100000
        $pair = Get-KeyPairFromPassword -Password $exportPassword -Salt $salt -Iterations $iterations
        if ($null -eq $pair) {
            Show-GuiMessage -Text "Unable to derive export key." -Title "Export Vault" -Kind Error -Owner $Owner
            return $false
        }
        $exportKey = $pair.EncKey
        $exportMacKey = $pair.MacKey
    }

    $exportData = Copy-VaultData -VaultData $VaultData
    Remove-VaultTotpSecret -VaultData $exportData
    $meta = [ordered]@{
        Version = 2
        VaultId = [guid]::NewGuid().ToString()
        AccountName = $AccountName
        Salt = [Convert]::ToBase64String($salt)
        Iterations = $iterations
        IV = ""
        Data = ""
    }
    Save-Vault -VaultPath $dialog.FileName -Key $exportKey -MacKey $exportMacKey -Meta $meta -Data $exportData
    Show-GuiMessage -Text "Vault exported." -Title "Export Vault" -Owner $Owner
    return $true
}

function Show-GuiRecoverySettings {
    param(
        [string]$VaultPath,
        [string]$AccountName,
        $Meta,
        $Data,
        [byte[]]$Key,
        [byte[]]$MacKey,
        [object]$Owner
    )
    if ($null -eq $Key -or $Key.Length -ne 32) {
        Show-GuiMessage -Text "Recovery options unavailable for this vault session." -Title "Recovery" -Kind Error -Owner $Owner
        return $false
    }
    if ((Test-VaultMacRequired -Meta $Meta) -and ($null -eq $MacKey -or $MacKey.Length -ne 32)) {
        Show-GuiMessage -Text "Recovery options unavailable without a valid vault signature key." -Title "Recovery" -Kind Error -Owner $Owner
        return $false
    }

    while ($true) {
        $hasRecovery = Test-RecoveryMeta -Meta $Meta
        $options = if ($hasRecovery) {
            @("Update recovery", "Remove recovery", "Close")
        } else {
            @("Set recovery", "Close")
        }
        $choice = Show-GuiChoiceDialog -Title "Recovery" -Message "Recovery passwords let you unlock this vault if the master password is lost." -Options $options -Owner $Owner
        if ($null -eq $choice -or $choice -eq "Close") { return $false }
        if ($choice -eq "Remove recovery") {
            if (-not (Show-GuiConfirm -Text "Remove recovery password for this vault?" -Title "Recovery" -Owner $Owner)) {
                continue
            }
            Remove-RecoveryFields -Meta $Meta
            Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
            Show-GuiMessage -Text "Recovery password removed." -Title "Recovery" -Owner $Owner
            return $true
        }

        $title = if ($AccountName) { "Set recovery password for vault $AccountName" } else { "Set recovery password" }
        $recoveryPassword = Read-GuiConfirmedSecret -Title $title -Prompt "Create recovery password" -ConfirmPrompt "Confirm recovery password" -Owner $Owner
        if ([string]::IsNullOrEmpty($recoveryPassword)) { return $false }

        $salt = New-RandomBytes 16
        $iterations = 100000
        $recoveryKey = Get-KeyFromPassword -Password $recoveryPassword -Salt $salt -Iterations $iterations
        $material = Get-CombinedKeyMaterial -EncKey $Key -MacKey $MacKey
        $wrapped = Protect-Bytes -PlainBytes $material -Key $recoveryKey
        $Meta.RecoverySalt = [Convert]::ToBase64String($salt)
        $Meta.RecoveryIterations = $iterations
        $Meta.RecoveryKeyIV = $wrapped.IV
        $Meta.RecoveryKeyData = $wrapped.Data
        Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
        Show-GuiMessage -Text "Recovery password saved." -Title "Recovery" -Owner $Owner
        return $true
    }
}

function Show-GuiTwoFactorSettings {
    param(
        [string]$VaultPath,
        $Meta,
        $Data,
        [byte[]]$Key,
        [byte[]]$MacKey,
        [object]$Owner
    )
    if ($null -eq $Key -or $Key.Length -ne 32 -or $null -eq $MacKey -or $MacKey.Length -ne 32) {
        Show-GuiMessage -Text "2FA settings unavailable for this vault session." -Title "2FA Settings" -Kind Error -Owner $Owner
        return $false
    }

    while ($true) {
        $secret = Get-VaultTotpSecret -VaultData $Data
        if ([string]::IsNullOrWhiteSpace($secret)) {
            $choice = Show-GuiChoiceDialog -Title "2FA Settings" -Message "Enable offline 2FA using a TOTP authenticator." -Options @("Enable 2FA", "Close") -Owner $Owner
            if ($choice -ne "Enable 2FA") { return $false }
        } else {
            $choice = Show-GuiChoiceDialog -Title "2FA Settings" -Message "2FA is enabled. Trusted devices stay unlocked for 24 hours." -Options @("Show secret", "Reconfigure 2FA", "Disable 2FA", "Close") -Owner $Owner
            if ($null -eq $choice -or $choice -eq "Close") { return $false }
            if ($choice -eq "Show secret") {
                Show-GuiReadOnlyTextDialog -Title "2FA Secret Key" -Prompt "Enter this secret into Google Authenticator, Authy, or Ente." -Value (Format-TotpSecret -Secret $secret) -Owner $Owner
                continue
            }
            if ($choice -eq "Disable 2FA") {
                if (-not (Show-GuiConfirm -Text "Disable 2FA for this vault?" -Title "2FA Settings" -Owner $Owner)) {
                    continue
                }
                Remove-VaultTotpSecret -VaultData $Data
                $vaultId = Get-VaultMetaValue -Meta $Meta -Name "VaultId"
                if ($vaultId) { Remove-TrustToken -VaultId $vaultId }
                Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
                Show-GuiMessage -Text "2FA disabled." -Title "2FA Settings" -Owner $Owner
                return $true
            }
        }

        $newSecret = New-TotpSecret
        $code = Show-GuiTotpSetupDialog -Title "Enable 2FA" -Prompt "Add this secret to your authenticator, then enter the 6-digit code to confirm." -Secret (Format-TotpSecret -Secret $newSecret) -Owner $Owner
        if ([string]::IsNullOrWhiteSpace($code)) { return $false }
        if (-not (Test-TotpCode -Secret $newSecret -Code $code)) {
            Show-GuiMessage -Text "Invalid 2FA code." -Title "2FA Settings" -Kind Error -Owner $Owner
            continue
        }

            Set-VaultTotpSecret -VaultData $Data -Secret $newSecret
            $vaultId = Initialize-VaultId -Meta $Meta
        Save-Vault -VaultPath $VaultPath -Key $Key -MacKey $MacKey -Meta $Meta -Data $Data
        $expires = [DateTime]::UtcNow.AddHours(24)
        Save-TrustToken -VaultId $vaultId -Secret $newSecret -ExpiresTicks $expires.Ticks | Out-Null
        Show-GuiMessage -Text "2FA enabled and this device is trusted for 24 hours." -Title "2FA Settings" -Owner $Owner
        return $true
    }
}

function Show-VaultGui {
    param(
        [string]$VaultPath,
        $Vault,
        [object]$Owner
    )
    if (-not (Initialize-GuiFramework)) { return }
    if ([string]::IsNullOrWhiteSpace($VaultPath)) { return }

    $vaultMeta = $Vault.Meta
    $vaultData = $Vault.Data
    $vaultKey = $Vault.Key
    $vaultMacKey = $Vault.MacKey
    if ($null -eq $vaultData.Entries) {
        $vaultData | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    $state = [ordered]@{
        SelectedEntryId = $null
    }

    $form = New-Object System.Windows.Forms.Form
    $title = if ($vaultMeta.AccountName) { "$script:AppName - $($vaultMeta.AccountName)" } else { "$script:AppName - Vault" }
    $form.Text = $title
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $form.ClientSize = New-Object System.Drawing.Size(1035, 610)
    $form.MinimumSize = New-Object System.Drawing.Size(1051, 649)

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Search"
    $searchLabel.SetBounds(16, 18, 48, 18)
    $form.Controls.Add($searchLabel)

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.SetBounds(70, 14, 320, 24)
    $form.Controls.Add($searchBox)

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.SetBounds(410, 18, 360, 18)
    $form.Controls.Add($statusLabel)

    $themeButton = New-Object System.Windows.Forms.Button
    $themeButton.SetBounds(796, 12, 223, 30)
    $form.Controls.Add($themeButton)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.SetBounds(16, 50, 760, 544)
    $grid.AutoGenerateColumns = $false
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.MultiSelect = $false
    $grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::None
    $form.Controls.Add($grid)

    $columns = @(
        @{ Name = "EntryId"; Header = "EntryId"; Property = "EntryId"; Width = 5; Visible = $false }
        @{ Name = "Title"; Header = "Name"; Property = "Title"; Width = 240; Visible = $true }
        @{ Name = "Url"; Header = "URL"; Property = "Url"; Width = 260; Visible = $true }
        @{ Name = "Username"; Header = "Username"; Property = "Username"; Width = 150; Visible = $true }
        @{ Name = "UpdatedAt"; Header = "Updated"; Property = "UpdatedAt"; Width = 110; Visible = $true }
    )
    foreach ($columnSpec in $columns) {
        $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $column.Name = $columnSpec.Name
        $column.HeaderText = $columnSpec.Header
        $column.DataPropertyName = $columnSpec.Property
        $column.Width = $columnSpec.Width
        $column.Visible = $columnSpec.Visible
        $column.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
        [void]$grid.Columns.Add($column)
    }

    $buttonSpecs = @(
        @{ Name = "add"; Label = "Add Entry"; Top = 50 }
        @{ Name = "view"; Label = "View Entry"; Top = 86 }
        @{ Name = "edit"; Label = "Edit Entry"; Top = 122 }
        @{ Name = "delete"; Label = "Delete Entry"; Top = 158 }
        @{ Name = "copy-user"; Label = "Copy Username"; Top = 194 }
        @{ Name = "copy-pass"; Label = "Copy Password"; Top = 230 }
        @{ Name = "open-url"; Label = "Open URL"; Top = 266 }
        @{ Name = "import-csv"; Label = "Import CSV"; Top = 302 }
        @{ Name = "export"; Label = "Export Vault"; Top = 338 }
        @{ Name = "twofactor"; Label = "2FA Settings"; Top = 374 }
        @{ Name = "recovery"; Label = "Recovery"; Top = 410 }
        @{ Name = "lock"; Label = "Lock Vault"; Top = 446 }
    )
    $buttons = @{}
    foreach ($buttonSpec in $buttonSpecs) {
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $buttonSpec.Label
        $button.SetBounds(796, $buttonSpec.Top, 223, 30)
        $buttons[$buttonSpec.Name] = $button
        $form.Controls.Add($button)
    }

    $getSelectedEntry = {
        $row = $null
        if ($null -ne $grid.CurrentRow -and $grid.CurrentRow.Index -ge 0) {
            $row = $grid.CurrentRow
        } elseif ($grid.SelectedRows.Count -gt 0) {
            $row = $grid.SelectedRows[0]
        }
        if ($null -eq $row) { return $null }
        $entryId = [string]$row.Cells["EntryId"].Value
        if ([string]::IsNullOrWhiteSpace($entryId)) { return $null }
        foreach ($entry in $vaultData.Entries) {
            if ($entry.Id -eq $entryId) {
                return $entry
            }
        }
        return $null
    }

    $refreshGrid = {
        $filterResult = Get-FilteredEntries -Entries $vaultData.Entries -SearchTerm $searchBox.Text
        $entries = @($filterResult.Entries)

        $table = New-Object System.Data.DataTable
        [void]$table.Columns.Add("EntryId")
        [void]$table.Columns.Add("Title")
        [void]$table.Columns.Add("Url")
        [void]$table.Columns.Add("Username")
        [void]$table.Columns.Add("UpdatedAt")
        foreach ($entry in $entries) {
            $row = $table.NewRow()
            $row["EntryId"] = $entry.Id
            $row["Title"] = $entry.Title
            $row["Url"] = $entry.Url
            $row["Username"] = $entry.Username
            $row["UpdatedAt"] = $entry.UpdatedAt
            [void]$table.Rows.Add($row)
        }

        $grid.DataSource = $table
        $statusLabel.Text = if ([string]::IsNullOrWhiteSpace($searchBox.Text)) {
            "{0} entries" -f $vaultData.Entries.Count
        } else {
            "{0} matching of {1} entries" -f $entries.Count, $vaultData.Entries.Count
        }

        if ($grid.Rows.Count -gt 0) {
            $targetRow = 0
            if (-not [string]::IsNullOrWhiteSpace($state.SelectedEntryId)) {
                for ($i = 0; $i -lt $grid.Rows.Count; $i++) {
                    if ([string]$grid.Rows[$i].Cells["EntryId"].Value -eq $state.SelectedEntryId) {
                        $targetRow = $i
                        break
                    }
                }
            }
            $grid.ClearSelection()
            $grid.Rows[$targetRow].Selected = $true
            $grid.CurrentCell = $grid.Rows[$targetRow].Cells["Title"]
        } else {
            $grid.ClearSelection()
            $state.SelectedEntryId = $null
        }
    }

    $applyTheme = {
        $theme = Get-GuiThemeMode
        $themeButton.Text = if ($theme -eq "dark") { "Theme: Dark" } else { "Theme: Light" }
        Set-GuiTheme -Control $form -Theme $theme
    }

    $grid.Add_SelectionChanged({
        $entry = & $getSelectedEntry
        if ($null -ne $entry) {
            $state.SelectedEntryId = $entry.Id
        } else {
            $state.SelectedEntryId = $null
        }
    })
    $grid.Add_CellDoubleClick({
        if ($null -ne (& $getSelectedEntry)) {
            $buttons["view"].PerformClick()
        }
    })
    $searchBox.Add_TextChanged({ & $refreshGrid })
    $themeButton.Add_Click({
        Switch-GuiThemeMode | Out-Null
        & $applyTheme
    })

    $buttons["add"].Add_Click({
        try {
            $newEntry = Show-GuiEntryEditor -Owner $form
            if ($null -ne $newEntry) {
                $vaultData.Entries += $newEntry
                Save-Vault -VaultPath $VaultPath -Key $vaultKey -MacKey $vaultMacKey -Meta $vaultMeta -Data $vaultData
                $state.SelectedEntryId = $newEntry.Id
                & $refreshGrid
            }
        } catch {
            Write-Log ("GUI add entry failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to add the entry." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["view"].Add_Click({
        $entry = & $getSelectedEntry
        if ($null -eq $entry) {
            Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
            return
        }
        [void](Show-GuiEntryEditor -Existing $entry -ReadOnly -Owner $form)
    })

    $buttons["edit"].Add_Click({
        try {
            $entry = & $getSelectedEntry
            if ($null -eq $entry) {
                Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
                return
            }
            $updated = Show-GuiEntryEditor -Existing $entry -Owner $form
            if ($null -ne $updated) {
                Save-Vault -VaultPath $VaultPath -Key $vaultKey -MacKey $vaultMacKey -Meta $vaultMeta -Data $vaultData
                $state.SelectedEntryId = $updated.Id
                & $refreshGrid
            }
        } catch {
            Write-Log ("GUI edit entry failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to update the entry." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["delete"].Add_Click({
        try {
            $entry = & $getSelectedEntry
            if ($null -eq $entry) {
                Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
                return
            }
            if (-not (Show-GuiConfirm -Text ("Delete '{0}'?" -f $entry.Title) -Title "Delete Entry" -Owner $form)) {
                return
            }
            $vaultData.Entries = @($vaultData.Entries | Where-Object { $_.Id -ne $entry.Id })
            Save-Vault -VaultPath $VaultPath -Key $vaultKey -MacKey $vaultMacKey -Meta $vaultMeta -Data $vaultData
            $state.SelectedEntryId = $null
            & $refreshGrid
        } catch {
            Write-Log ("GUI delete entry failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to delete the entry." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["copy-user"].Add_Click({
        $entry = & $getSelectedEntry
        if ($null -eq $entry) {
            Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
            return
        }
        if ([string]::IsNullOrWhiteSpace($entry.Username)) {
            Show-GuiMessage -Text "The selected entry has no username." -Title $title -Kind Warning -Owner $form
            return
        }
        if (-not (Set-ClipboardSafe -Value $entry.Username)) {
            Show-GuiMessage -Text "Clipboard is not available in this session." -Title $title -Kind Warning -Owner $form
        }
    })

    $buttons["copy-pass"].Add_Click({
        $entry = & $getSelectedEntry
        if ($null -eq $entry) {
            Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
            return
        }
        if ([string]::IsNullOrWhiteSpace($entry.Password)) {
            Show-GuiMessage -Text "The selected entry has no password." -Title $title -Kind Warning -Owner $form
            return
        }
        if (-not (Set-ClipboardSafe -Value $entry.Password)) {
            Show-GuiMessage -Text "Clipboard is not available in this session." -Title $title -Kind Warning -Owner $form
        }
    })

    $buttons["open-url"].Add_Click({
        $entry = & $getSelectedEntry
        if ($null -eq $entry) {
            Show-GuiMessage -Text "Select an entry first." -Title $title -Kind Warning -Owner $form
            return
        }
        Open-WebUrlGui -Url $entry.Url -Owner $form
    })

    $buttons["import-csv"].Add_Click({
        try {
            $result = Import-CsvEntriesGui -Entries $vaultData.Entries -Owner $form
            if ($null -ne $result -and $result.Imported -gt 0) {
                $vaultData.Entries = $result.Entries
                Save-Vault -VaultPath $VaultPath -Key $vaultKey -MacKey $vaultMacKey -Meta $vaultMeta -Data $vaultData
                if ($vaultData.Entries.Count -gt 0) {
                    $state.SelectedEntryId = $vaultData.Entries[-1].Id
                }
                & $refreshGrid
            }
        } catch {
            Write-Log ("GUI CSV import failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to import the CSV file." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["export"].Add_Click({
        try {
            Export-VaultDataGui -AccountName $vaultMeta.AccountName -VaultData $vaultData -VaultMeta $vaultMeta -VaultPath $VaultPath -VaultKey $vaultKey -VaultMacKey $vaultMacKey -Owner $form | Out-Null
        } catch {
            Write-Log ("GUI export failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to export the vault." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["twofactor"].Add_Click({
        try {
            Show-GuiTwoFactorSettings -VaultPath $VaultPath -Meta $vaultMeta -Data $vaultData -Key $vaultKey -MacKey $vaultMacKey -Owner $form | Out-Null
        } catch {
            Write-Log ("GUI 2FA settings failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to open 2FA settings." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["recovery"].Add_Click({
        try {
            Show-GuiRecoverySettings -VaultPath $VaultPath -AccountName $vaultMeta.AccountName -Meta $vaultMeta -Data $vaultData -Key $vaultKey -MacKey $vaultMacKey -Owner $form | Out-Null
        } catch {
            Write-Log ("GUI recovery settings failed: {0}" -f $_.Exception.Message)
            Show-GuiMessage -Text "Unable to open recovery settings." -Title $title -Kind Error -Owner $form
        }
    })

    $buttons["lock"].Add_Click({
        $form.Close()
    })

    $form.Add_Shown({
        & $applyTheme
        & $refreshGrid
    })
    if ($null -ne $Owner) {
        [void]$form.ShowDialog($Owner)
    } else {
        [void]$form.ShowDialog()
    }
}

function Start-VaultXGui {
    param([array]$Accounts)
    if (-not (Initialize-GuiFramework)) {
        Show-Message "GUI mode requires a Windows desktop session with STA PowerShell." ([ConsoleColor]::Red)
        return @{ Accounts = Sync-AccountsWithVaultFiles -Accounts (Get-Accounts); Quit = $false }
    }

    $state = [ordered]@{
        Accounts = if ($null -eq $Accounts) { @() } else { @($Accounts) }
    }
    $consoleHidden = $false
    try {
        $consoleHidden = Set-ConsoleWindowVisible -Visible:$false

        $form = New-Object System.Windows.Forms.Form
        $form.Text = "$script:AppName GUI"
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.ClientSize = New-Object System.Drawing.Size(760, 420)
        $form.MinimumSize = New-Object System.Drawing.Size(776, 459)

        $titleLabel = New-Object System.Windows.Forms.Label
        $titleLabel.Text = "$script:AppName GUI"
        $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
        $titleLabel.SetBounds(20, 16, 220, 30)
        $form.Controls.Add($titleLabel)

        $subtitleLabel = New-Object System.Windows.Forms.Label
        $subtitleLabel.Text = "The terminal process stays active while you work in the local window."
        $subtitleLabel.SetBounds(20, 50, 500, 18)
        $form.Controls.Add($subtitleLabel)

        $vaultsLabel = New-Object System.Windows.Forms.Label
        $vaultsLabel.Text = "Vaults"
        $vaultsLabel.SetBounds(20, 86, 60, 18)
        $form.Controls.Add($vaultsLabel)

        $vaultList = New-Object System.Windows.Forms.ListBox
        $vaultList.SetBounds(20, 110, 430, 250)
        $form.Controls.Add($vaultList)

        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.SetBounds(20, 372, 430, 18)
        $form.Controls.Add($statusLabel)

        $themeButton = New-Object System.Windows.Forms.Button
        $themeButton.SetBounds(568, 16, 160, 30)
        $form.Controls.Add($themeButton)

        $buttonSpecs = @(
            @{ Name = "open"; Label = "Open Selected"; Top = 110 }
            @{ Name = "create"; Label = "Create Vault"; Top = 146 }
            @{ Name = "import"; Label = "Import Vault"; Top = 182 }
            @{ Name = "remove"; Label = "Remove Vault"; Top = 218 }
            @{ Name = "refresh"; Label = "Refresh"; Top = 254 }
            @{ Name = "open-data"; Label = "Open Data Folder"; Top = 290 }
            @{ Name = "terminal"; Label = "Return to Terminal"; Top = 326 }
        )
        $buttons = @{}
        foreach ($buttonSpec in $buttonSpecs) {
            $button = New-Object System.Windows.Forms.Button
            $button.Text = $buttonSpec.Label
            $button.SetBounds(488, $buttonSpec.Top, 240, 30)
            $buttons[$buttonSpec.Name] = $button
            $form.Controls.Add($button)
        }

        $refreshAccounts = {
            $selectedName = if ($vaultList.SelectedIndex -ge 0) { [string]$vaultList.SelectedItem } else { $null }
            $state.Accounts = @(Sync-AccountsWithVaultFiles -Accounts (Get-Accounts) | Sort-Object Name)
            $vaultList.BeginUpdate()
            $vaultList.Items.Clear()
            foreach ($account in $state.Accounts) {
                [void]$vaultList.Items.Add($account.Name)
            }
            $vaultList.EndUpdate()
            if ($vaultList.Items.Count -eq 0) {
                $statusLabel.Text = "No vaults found. Create or import one to get started."
                return
            }
            $targetIndex = -1
            if (-not [string]::IsNullOrWhiteSpace($selectedName)) {
                $targetIndex = $vaultList.Items.IndexOf($selectedName)
            }
            if ($targetIndex -lt 0) { $targetIndex = 0 }
            $vaultList.SelectedIndex = $targetIndex
            $statusLabel.Text = "{0} vault(s) available." -f $state.Accounts.Count
        }

        $getSelectedAccount = {
            if ($vaultList.SelectedIndex -lt 0 -or $vaultList.SelectedIndex -ge $state.Accounts.Count) {
                return $null
            }
            return $state.Accounts[$vaultList.SelectedIndex]
        }

        $applyTheme = {
            $theme = Get-GuiThemeMode
            $themeButton.Text = if ($theme -eq "dark") { "Theme: Dark" } else { "Theme: Light" }
            Set-GuiTheme -Control $form -Theme $theme
        }

        $openSelectedVault = {
            try {
                $account = & $getSelectedAccount
                if ($null -eq $account) {
                    Show-GuiMessage -Text "Select a vault first." -Title $form.Text -Kind Warning -Owner $form
                    return
                }
                $vaultPath = Get-VaultPath -FileName $account.File
                $vault = Open-VaultGui -VaultPath $vaultPath -AccountName $account.Name -Owner $form
                if ($null -ne $vault) {
                    Show-VaultGui -VaultPath $vaultPath -Vault $vault -Owner $form
                    & $refreshAccounts
                }
            } catch {
                Write-Log ("GUI open vault failed: {0}" -f $_.Exception.Message)
                Show-GuiMessage -Text "Unable to open the selected vault." -Title $form.Text -Kind Error -Owner $form
            }
        }

        $buttons["open"].Add_Click({ & $openSelectedVault })
        $vaultList.Add_DoubleClick({ & $openSelectedVault })
        $themeButton.Add_Click({
            Switch-GuiThemeMode | Out-Null
            & $applyTheme
        })

        $buttons["create"].Add_Click({
            try {
                $created = New-AccountGui -Accounts $state.Accounts -Owner $form
                if ($null -eq $created) { return }
                $state.Accounts = $created.Accounts
                & $refreshAccounts
                if ($null -ne $created.Account) {
                    $vaultPath = Get-VaultPath -FileName $created.Account.File
                    Show-VaultGui -VaultPath $vaultPath -Vault $created.Vault -Owner $form
                    & $refreshAccounts
                }
            } catch {
                Write-Log ("GUI create vault failed: {0}" -f $_.Exception.Message)
                Show-GuiMessage -Text "Unable to create a new vault." -Title $form.Text -Kind Error -Owner $form
            }
        })

        $buttons["import"].Add_Click({
            try {
                $result = Import-VaultDataGui -Accounts $state.Accounts -Owner $form
                if ($null -ne $result -and $null -ne $result.Accounts) {
                    $state.Accounts = $result.Accounts
                    & $refreshAccounts
                }
            } catch {
                Write-Log ("GUI import vault failed: {0}" -f $_.Exception.Message)
                Show-GuiMessage -Text "Unable to import the vault file." -Title $form.Text -Kind Error -Owner $form
            }
        })

        $buttons["remove"].Add_Click({
            try {
                $account = & $getSelectedAccount
                if ($null -eq $account) {
                    Show-GuiMessage -Text "Select a vault first." -Title $form.Text -Kind Warning -Owner $form
                    return
                }
                $vaultPath = Get-VaultPath -FileName $account.File
                if (-not (Show-GuiConfirm -Text ("Delete vault '{0}' and its data? This cannot be undone." -f $account.Name) -Title "Remove Vault" -Owner $form)) {
                    return
                }
                if (Test-Path $vaultPath) {
                    Remove-Item -Path $vaultPath -Force
                }
                $state.Accounts = @($state.Accounts | Where-Object { $_.Name -ne $account.Name })
                Save-Accounts -Accounts $state.Accounts
                & $refreshAccounts
                Show-GuiMessage -Text "Vault removed." -Title "Remove Vault" -Owner $form
            } catch {
                Write-Log ("GUI remove vault failed: {0}" -f $_.Exception.Message)
                Show-GuiMessage -Text "Unable to remove the selected vault." -Title $form.Text -Kind Error -Owner $form
            }
        })

        $buttons["refresh"].Add_Click({ & $refreshAccounts })

        $buttons["open-data"].Add_Click({
            try {
                $dir = Get-AppDir
                if ([string]::IsNullOrWhiteSpace($dir)) {
                    Show-GuiMessage -Text "Data folder unavailable." -Title $form.Text -Kind Error -Owner $form
                    return
                }
                if (-not (Test-Path $dir)) {
                    New-Item -ItemType Directory -Path $dir | Out-Null
                }
                Start-Process -FilePath $dir | Out-Null
            } catch {
                Write-Log ("GUI open data folder failed: {0}" -f $_.Exception.Message)
                Show-GuiMessage -Text "Unable to open the data folder." -Title $form.Text -Kind Error -Owner $form
            }
        })

        $buttons["terminal"].Add_Click({ $form.Close() })

        $form.Add_Shown({
            & $applyTheme
            & $refreshAccounts
        })
        [void]$form.ShowDialog()
    } finally {
        if ($consoleHidden) {
            Set-ConsoleWindowVisible -Visible:$true | Out-Null
        }
        Clear-Host
    }

    return @{
        Accounts = Sync-AccountsWithVaultFiles -Accounts (Get-Accounts)
        Quit = $false
    }
}

function Invoke-VaultX {
    Initialize-Settings
    $accounts = Get-Accounts
    $selectedAccount = 0
    $menuSection = "main"

    try {
        Write-Log "VaultX started."
        Register-VaultXSession
        if (Invoke-UpdateCheck -CurrentVersion $script:AppVersion) {
            return
        }
        while ($true) {
            $accounts = Sync-AccountsWithVaultFiles -Accounts $accounts
            $menu = Show-AccountMenu -Accounts $accounts -Selected $selectedAccount -StartSection $menuSection
            if ($null -eq $menu) { break }
            if ($null -ne $menu.Accounts) { $accounts = $menu.Accounts }
            $selectedAccount = $menu.Selected
            $menuSection = if ($menu.Section) { $menu.Section } else { "main" }
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
                "gui" {
                    $guiResult = Start-VaultXGui -Accounts $accounts
                    if ($null -ne $guiResult -and $null -ne $guiResult.Accounts) {
                        $accounts = $guiResult.Accounts
                    } else {
                        $accounts = Sync-AccountsWithVaultFiles -Accounts (Get-Accounts)
                    }
                    $selectedAccount = 0
                    $menuSection = "main"
                }
                "open-data" {
                    Open-AppDataFolder | Out-Null
                }
                "customize" {
                    Show-CustomizeMenu | Out-Null
                }
                "wipe-cache" {
                    if (Clear-VaultCache) {
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

if ($Gui) {
    $guiResult = Start-VaultXGui -Accounts (Get-Accounts)
    if ($null -ne $guiResult -and $guiResult.Quit) {
        Close-VaultX -Message "$script:AppName closed."
    }
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
