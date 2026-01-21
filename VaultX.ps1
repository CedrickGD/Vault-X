<# 
VaultX - simple local password manager (single-user, local encryption)
#>

[CmdletBinding()]
param(
    [switch]$Close,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$script:AppName = "VaultX"
$script:AppVersion = "1.0.1"
$script:UpdateConfigUrl = "https://raw.githubusercontent.com/CedrickGD/Vault-X/main/version.yml"
$script:UpdateCheckEnabled = ($env:VAULTX_UPDATE_CHECK -ne "0")
$script:MenuNormalColor = [ConsoleColor]::Gray
$script:MenuHighlightColor = [ConsoleColor]::Cyan
$script:MenuDisabledColor = [ConsoleColor]::DarkGray
$script:MenuSeparatorColor = [ConsoleColor]::DarkGray
$script:MenuPromptColor = [ConsoleColor]::Gray
$script:MenuPointerSymbol = ">"
$script:WaitOnExit = ($env:VAULTX_WAIT_ON_EXIT -eq "1")

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

function Resolve-UpdateTemplate {
    param([string]$Value, [string]$Version)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $Value }
    return ($Value -replace "\{version\}", $Version)
}

function Compare-VersionString {
    param([string]$Current, [string]$Latest)
    $currentVersion = $null
    $latestVersion = $null
    if ([Version]::TryParse($Current, [ref]$currentVersion) -and [Version]::TryParse($Latest, [ref]$latestVersion)) {
        return $currentVersion.CompareTo($latestVersion)
    }
    return [string]::Compare($Current, $Latest, $true)
}

function Install-Update {
    param(
        [string]$DownloadUrl,
        [string]$LatestVersion
    )
    if ([string]::IsNullOrWhiteSpace($DownloadUrl)) { return $false }
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        Show-Message "Update failed: script path unavailable." ([ConsoleColor]::Red)
        return $false
    }
    $tempFile = [IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
        $firstLine = (Get-Content -Path $tempFile -TotalCount 1 -ErrorAction SilentlyContinue)
        if ([string]::IsNullOrWhiteSpace($firstLine) -or $firstLine -match "<!DOCTYPE html|Not Found") {
            Show-Message "Update download failed." ([ConsoleColor]::Red)
            Write-Log "Update download returned invalid content."
            return $false
        }
        $backupPath = "$scriptPath.bak"
        Copy-Item -Path $scriptPath -Destination $backupPath -Force
        Move-Item -Path $tempFile -Destination $scriptPath -Force
        Show-Message ("Updated to version " + $LatestVersion + ". Restart VaultX to use the new version.") ([ConsoleColor]::Green)
        return $true
    } catch {
        Write-Log ("Update install failed: {0}" -f $_.Exception.Message)
        Show-Message "Update failed." ([ConsoleColor]::Red)
        return $false
    } finally {
        if (Test-Path $tempFile) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-UpdateCheck {
    param([string]$CurrentVersion)
    if (-not $script:UpdateCheckEnabled) { return $false }
    if ([string]::IsNullOrWhiteSpace($script:UpdateConfigUrl)) { return $false }
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
    if (Compare-VersionString -Current $CurrentVersion -Latest $latestVersion -ge 0) { return $false }
    $downloadUrl = Resolve-UpdateTemplate -Value $info.Url -Version $latestVersion
    if ([string]::IsNullOrWhiteSpace($downloadUrl)) { return $false }
    $subtitle = ("Current: {0}  Latest: {1}" -f $CurrentVersion, $latestVersion)
    $updateNow = $info.Mandatory
    if (-not $updateNow) {
        $choice = Show-ActionMenu -Title "Update available" -Options @("Update now", "Skip") -Subtitle $subtitle
        if ($choice -ne "Update now") { return $false }
    }
    if (Install-Update -DownloadUrl $downloadUrl -LatestVersion $latestVersion) {
        Stop-VaultX -Message "$script:AppName updated. Please restart."
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
        Show-Message "Database list file is corrupted. Starting with empty list." ([ConsoleColor]::Red)
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

function Read-AccountName {
    param([array]$Accounts)
    while ($true) {
        Clear-Host
        Write-Header "Create database"
        $name = Read-Host "Database name (required, Enter to abort)"
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        $exists = $Accounts | Where-Object { $_.Name -ieq $name }
        if ($exists) {
            Show-Message "Database already exists." ([ConsoleColor]::Red)
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
    if (-not (Confirm-Action "Delete database '$($account.Name)' and its data?")) {
        return $Accounts
    }
    if (Test-Path $vaultPath) {
        Remove-Item -Path $vaultPath -Force
    }
    $updated = @($Accounts | Where-Object { $_.Name -ne $account.Name })
    Save-Accounts -Accounts $updated
    return $updated
}

function Confirm-AccountPassword {
    param([string]$VaultPath, [string]$AccountName)
    if (-not (Test-Path $VaultPath)) {
        Show-Message "Database file missing. Delete aborted." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $meta = Get-Content -Path $VaultPath -Raw | ConvertFrom-Json
    } catch {
        Show-Message "Database file is corrupted or unreadable." ([ConsoleColor]::Red)
        return $false
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-Message "Database file is invalid." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Database encryption salt is invalid." ([ConsoleColor]::Red)
        return $false
    }
    $iterations = [int]$meta.Iterations
    while ($true) {
        Clear-Host
        Write-Header "Confirm deletion"
        if ($AccountName) {
            Write-Host ("Database: " + $AccountName) -ForegroundColor DarkGray
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
                Write-Host $line -ForegroundColor Cyan
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
    $greeting = "{0}@{1}" -f $env:USERNAME, $env:COMPUTERNAME
    $titleLine = if ([string]::IsNullOrWhiteSpace($script:AppVersion)) {
        $script:AppName
    } else {
        "{0} v{1}" -f $script:AppName, $script:AppVersion
    }
    Write-Host $greeting -ForegroundColor DarkGray
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
            Write-Host "Use Up/Down to move, Enter to select." -ForegroundColor DarkGray
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
        if ($AccountName) { $title = "Set master password for database $AccountName" }
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

function Open-Vault {
    param(
        [string]$VaultPath,
        [string]$AccountName,
        [switch]$CreateIfMissing
    )
    if (-not (Test-Path $VaultPath)) {
        if (-not $CreateIfMissing) {
            Show-Message "Database not found." ([ConsoleColor]::Red)
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
        Show-Message "Database file is corrupted or unreadable." ([ConsoleColor]::Red)
        return $null
    }
    if (-not (Test-VaultMeta -Meta $meta)) {
        Show-Message "Database file is invalid." ([ConsoleColor]::Red)
        return $null
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Database encryption salt is invalid." ([ConsoleColor]::Red)
        return $null
    }
    $iterations = [int]$meta.Iterations
    while ($true) {
        Clear-Host
        $title = "Unlock database"
        if ($meta.AccountName) { $title = "Unlock database $($meta.AccountName)" }
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
        } finally {
            $password = $null
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
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            $filterResult = Get-FilteredEntries -Entries $Entries -SearchTerm $SearchTerm
            $filtered = $filterResult.Entries
            $map = $filterResult.Map

            $selectedPos = 0
            if ($map.Count -gt 0) {
                $found = [Array]::IndexOf($map, $SelectedIndex)
                if ($found -ge 0) { $selectedPos = $found + 1 }
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
            Write-Host "Up/Down move, Enter select." -ForegroundColor DarkGray
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
                "Backspace" {
                    if (-not [string]::IsNullOrEmpty($SearchTerm)) {
                        $SearchTerm = $SearchTerm.Substring(0, $SearchTerm.Length - 1)
                        $SelectedIndex = 0
                        $skipIndexUpdate = $true
                    }
                }
                default {
                    if ($key.Key.Length -eq 1 -and (($key.Modifiers -band [ConsoleModifiers]::Control) -eq 0) -and (($key.Modifiers -band [ConsoleModifiers]::Alt) -eq 0)) {
                        $SearchTerm += $key.Key
                        $SelectedIndex = 0
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
        [string]$Title = "Select database"
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
            Write-Host "Up/Down move, Enter select." -ForegroundColor DarkGray
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
        @{ Label = "Back to database list"; Action = "logout"; RequiresEntry = $false }
        @{ Label = "Quit VaultX"; Action = "quit"; RequiresEntry = $false }
    )
    $selected = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            $title = "Database Menu"
            if ($AccountName) { $title = "Database Menu - $AccountName" }
            Write-Header $title -ShowBanner
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $isDisabled = ($action.RequiresEntry -and -not $HasEntries)
                $isSelected = ($i -eq $selected)
                $color = if ($isDisabled) { $script:MenuDisabledColor } elseif ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $action.Label -IsSelected $isSelected -IsActive:(!$isDisabled) -Color $color -Indent 0
            }
            Write-Host ""
            Write-Host "Up/Down move, Enter select." -ForegroundColor DarkGray
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
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-AccountMenu {
    param([array]$Accounts, [int]$Selected = 0)
    $actions = @()
    if ($Accounts.Count -gt 0) {
        $actions += @{ Label = "Open database"; Action = "login" }
        $actions += @{ Label = "Remove database"; Action = "delete" }
    }
    $actions += @{ Label = "Add database"; Action = "add" }
    $actions += @{ Label = "Quit"; Action = "quit" }

    $selectedAction = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        $isFirstRender = $true
        while ($true) {
            Start-MenuFrame -IsFirstRender ([ref]$isFirstRender)
            Write-Header "Main Menu" -ShowBanner
            if ($Accounts.Count -eq 0) {
                Write-Host "No databases yet." -ForegroundColor DarkGray
            } else {
                $names = $Accounts | ForEach-Object { $_.Name } | Sort-Object
                Write-Host ("Databases: " + ($names -join ", ")) -ForegroundColor DarkGray
            }
            Write-Host ""
            Write-MenuSeparator -Indent 0
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                $isSelected = ($i -eq $selectedAction)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $action.Label -IsSelected $isSelected -IsActive:$true -Color $color -Indent 0
            }
            Write-Host ""
            Write-Host "Up/Down move, Enter select." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" {
                    if ($selectedAction -gt 0) { $selectedAction-- } else { $selectedAction = $actions.Count - 1 }
                }
                "DownArrow" {
                    if ($selectedAction -lt ($actions.Count - 1)) { $selectedAction++ } else { $selectedAction = 0 }
                }
                "Enter" {
                    $action = $actions[$selectedAction]
                    return @{ Action = $action.Action; Selected = 0 }
                }
            }
        }
    } finally {
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
            Write-Host "Enter copies field or runs action." -ForegroundColor DarkGray
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
            $menu = Show-AccountMenu -Accounts $accounts -Selected $selectedAccount
            if ($null -eq $menu) { break }
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
                    $chosen = Show-AccountPicker -Accounts $accounts -Title "Select database to remove"
                    if ($null -ne $chosen) {
                        $accounts = Remove-Account -Accounts $accounts -Selected $chosen
                        if ($selectedAccount -ge $accounts.Count) {
                            $selectedAccount = [Math]::Max(0, $accounts.Count - 1)
                        }
                    }
                }
                "login" {
                    $chosen = Show-AccountPicker -Accounts $accounts -Title "Select database to open"
                    if ($null -ne $chosen) {
                        $account = $accounts[$chosen]
                        $vaultPath = Get-VaultPath -FileName $account.File
                        $vault = Open-Vault -VaultPath $vaultPath -AccountName $account.Name
                        if ($null -ne $vault) {
                            Invoke-VaultSession -VaultPath $vaultPath -Vault $vault
                        }
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
