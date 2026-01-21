<# 
VaultX - simple local password manager (single-user, local encryption)
#>

[CmdletBinding()]
param(
    [switch]$Close,
    [switch]$Quit,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$script:AppName = "VaultX"
$script:AppVersion = "1.0.1"
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
        Show-Message "Accounts file is corrupted. Starting with empty list." ([ConsoleColor]::Red)
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
        Write-Header "Create account"
        $name = Read-Host "Account name (required, Enter to abort)"
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        $exists = $Accounts | Where-Object { $_.Name -ieq $name }
        if ($exists) {
            Show-Message "Account already exists." ([ConsoleColor]::Red)
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
    if (-not (Confirm-Action "Delete account '$($account.Name)' and its vault?")) {
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
        Show-Message "Vault metadata is invalid." ([ConsoleColor]::Red)
        return $false
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Vault salt is invalid." ([ConsoleColor]::Red)
        return $false
    }
    $iterations = [int]$meta.Iterations
    while ($true) {
        Clear-Host
        Write-Header "Confirm deletion"
        if ($AccountName) {
            Write-Host ("Account: " + $AccountName) -ForegroundColor DarkGray
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
____   _________   ____ ___.____  ___________ ____  ___
\   \ /   /  _  \ |    |   \    | \__    ___/ \   \/  /
 \   Y   /  /_\  \|    |   /    |   |    |     \     / 
  \     /    |    \    |  /|    |___|    |     /     \ 
   \___/\____|__  /______/ |_______ \____|    /___/\  \
                \/                 \/               \_/
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
    Write-Host "  VaultX.ps1 -Quit        # Quit the app session" -ForegroundColor Gray
    Write-Host "  VaultX.ps1 -Help        # Show this help" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Session shortcuts (after first run):" -ForegroundColor Gray
    Write-Host "  VaultX                 # Launch again in the same session" -ForegroundColor Gray
    Write-Host "  Close-VaultX           # Close the app session" -ForegroundColor Gray
    Write-Host "  Quit-VaultX            # Quit the app session" -ForegroundColor Gray
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
    $line = "-" * $width
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

function Write-MenuItem {
    param(
        [string]$Text,
        [bool]$IsSelected,
        [bool]$IsActive = $true,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [int]$Indent = 2
    )
    $maxWidth = [Math]::Max(10, (Get-ConsoleWidth) - ($Indent + 4))
    $safeText = Format-MenuText -Text $Text -Max $maxWidth
    if ($IsSelected) {
        $pointerColor = if ($IsActive) { $script:MenuHighlightColor } else { $script:MenuDisabledColor }
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
        while ($true) {
            Clear-Host
            Write-Header $Title
            if ($Subtitle) {
                Write-Host $Subtitle -ForegroundColor DarkGray
                Write-Host ""
            }
            for ($i = 0; $i -lt $Options.Count; $i++) {
                $line = $Options[$i]
                $isSelected = ($i -eq $Selected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $line -IsSelected $isSelected -Color $color
            }
            Write-Host ""
            Write-Host "Use Up/Down to move, Enter to select, Esc to cancel." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" { $Selected = [Math]::Max(0, $Selected - 1) }
                "DownArrow" { $Selected = [Math]::Min($Options.Count - 1, $Selected + 1) }
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
        if ($AccountName) { $title = "Set master password for $AccountName" }
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
        Show-Message "Vault metadata is invalid." ([ConsoleColor]::Red)
        return $null
    }
    try {
        $salt = [Convert]::FromBase64String($meta.Salt)
    } catch {
        Show-Message "Vault salt is invalid." ([ConsoleColor]::Red)
        return $null
    }
    $iterations = [int]$meta.Iterations
    while ($true) {
        Clear-Host
        $title = "Unlock vault"
        if ($meta.AccountName) { $title = "Unlock $($meta.AccountName)" }
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
        [string]$AccountName
    )
    if ($Entries.Count -eq 0) { $SelectedIndex = 0 }
    $actions = @(
        @{ Label = "View entry"; Action = "view"; RequiresEntry = $true }
        @{ Label = "Add entry"; Action = "add"; RequiresEntry = $false }
        @{ Label = "Edit entry"; Action = "edit"; RequiresEntry = $true }
        @{ Label = "Delete entry"; Action = "delete"; RequiresEntry = $true }
        @{ Label = "Search"; Action = "search"; RequiresEntry = $false }
        @{ Label = "Clear search"; Action = "clear"; RequiresSearch = $true }
        @{ Label = "Logout"; Action = "logout"; RequiresEntry = $false }
    )
    $actionSelected = 0
    for ($i = 0; $i -lt $actions.Count; $i++) {
        if (-not $actions[$i].RequiresEntry) { $actionSelected = $i; break }
    }
    $focus = if ($Entries.Count -gt 0) { "entries" } else { "actions" }
    $start = 0
    $helpHint = "SHOW KEYBINDINGS AND INSTRUCTIONS: [ALT+V] OR [CTRL+V]"
    $helpLines = @(
        "VaultX entry menu:",
        "  Up/Down  - move selection",
        "  Enter    - open entry or run action",
        "  Esc/Q    - logout",
        "  Alt+V / Ctrl+V - show this help",
        "",
        "Actions:",
        "  View entry, Add entry, Edit entry, Delete entry",
        "  Search filters the list, Clear search resets it"
    )
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        while ($true) {
        $filterResult = Get-FilteredEntries -Entries $Entries -SearchTerm $SearchTerm
        $filtered = $filterResult.Entries
        $map = $filterResult.Map
        $selectedPos = 0
        if ($map.Count -gt 0) {
            $found = [Array]::IndexOf($map, $SelectedIndex)
            if ($found -ge 0) { $selectedPos = $found }
        }
        if ($filtered.Count -eq 0) { $focus = "actions" }

        $hasEntries = ($filtered.Count -gt 0)
        $hasSearch = (-not [string]::IsNullOrWhiteSpace($SearchTerm))
        $actionSelected = [Math]::Max(0, [Math]::Min($actionSelected, $actions.Count - 1))

        Clear-Host
        $subtitle = "Vault entries"
        if ($AccountName) { $subtitle = "Vault entries - $AccountName" }
        Write-Header $subtitle -ShowBanner
        if (-not [string]::IsNullOrWhiteSpace($SearchTerm)) {
            Write-Host ("Search: " + $SearchTerm) -ForegroundColor DarkGray
            Write-Host ""
        }
        if ($filtered.Count -eq 0) {
            if ($Entries.Count -eq 0) {
                Write-Host "No entries yet." -ForegroundColor DarkGray
            } else {
                Write-Host "No matches for current search." -ForegroundColor DarkGray
            }
        } else {
            $maxVisible = [Math]::Max(5, (Get-ConsoleHeight) - 16)
            if ($filtered.Count -le $maxVisible) {
                $start = 0
            } else {
                if ($start -gt ($filtered.Count - $maxVisible)) {
                    $start = [Math]::Max(0, $filtered.Count - $maxVisible)
                }
                if ($selectedPos -lt $start) { $start = $selectedPos }
                if ($selectedPos -ge ($start + $maxVisible)) { $start = $selectedPos - $maxVisible + 1 }
            }
            $end = [Math]::Min($filtered.Count - 1, $start + $maxVisible - 1)
            Write-Host "Entries" -ForegroundColor DarkGray
            for ($i = $start; $i -le $end; $i++) {
                $entry = $filtered[$i]
                $title = Format-DisplayValue $entry.Title 28
                $url = Format-DisplayValue $entry.Url 40
                $line = ("{0,-30} {1}" -f $title, $url)
                $isSelected = ($focus -eq "entries" -and $i -eq $selectedPos)
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
        Write-Host "Actions" -ForegroundColor DarkGray
        if ($hasEntries) {
            Write-Host ("Selected: " + $filtered[$selectedPos].Title) -ForegroundColor DarkGray
        }
        for ($i = 0; $i -lt $actions.Count; $i++) {
            $action = $actions[$i]
            $enabled = $true
            if ($action.RequiresEntry -and -not $hasEntries) { $enabled = $false }
            if ($action.ContainsKey("RequiresSearch") -and $action.RequiresSearch -and -not $hasSearch) { $enabled = $false }
            $isSelected = ($focus -eq "actions" -and $i -eq $actionSelected)
            if ($enabled) {
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
            } else {
                $color = $script:MenuDisabledColor
            }
            Write-MenuItem -Text $action.Label -IsSelected $isSelected -IsActive:$enabled -Color $color
        }
        Write-Host ""
        Write-Host "Arrows: Up/Down move, Enter select, Esc/Q logout." -ForegroundColor DarkGray
        Write-MenuHelpHint $helpHint

        $skipIndexUpdate = $false
        $key = Read-MenuKey
        if ($key.Key -eq "V" -and (($key.Modifiers -band [ConsoleModifiers]::Alt) -ne 0 -or ($key.Modifiers -band [ConsoleModifiers]::Control) -ne 0)) {
            Show-MenuHelp -Title "VaultX Keybindings" -Lines $helpLines
            continue
        }
        switch ($key.Key) {
            "UpArrow" {
                if ($focus -eq "entries") {
                    if ($filtered.Count -gt 0 -and $selectedPos -gt 0) {
                        $selectedPos--
                    }
                } else {
                    if ($actionSelected -gt 0) {
                        $actionSelected--
                    } elseif ($filtered.Count -gt 0) {
                        $focus = "entries"
                    }
                }
            }
            "DownArrow" {
                if ($focus -eq "entries") {
                    if ($filtered.Count -gt 0 -and $selectedPos -lt ($filtered.Count - 1)) {
                        $selectedPos++
                    } else {
                        $focus = "actions"
                    }
                } else {
                    if ($actionSelected -lt ($actions.Count - 1)) {
                        $actionSelected++
                    }
                }
            }
            "Enter" {
                if ($focus -eq "entries") {
                    if ($hasEntries) { return @{ Action = "view"; SelectedIndex = $map[$selectedPos]; SearchTerm = $SearchTerm } }
                    Show-Message "No entries available." ([ConsoleColor]::Red)
                    break
                }
                $action = $actions[$actionSelected]
                if ($action.RequiresEntry -and -not $hasEntries) {
                    Show-Message "No entries available." ([ConsoleColor]::Red)
                    break
                }
                if ($action.ContainsKey("RequiresSearch") -and $action.RequiresSearch -and -not $hasSearch) {
                    Show-Message "No active search." ([ConsoleColor]::Yellow)
                    break
                }
                switch ($action.Action) {
                    "view" { return @{ Action = "view"; SelectedIndex = $map[$selectedPos]; SearchTerm = $SearchTerm } }
                    "edit" { return @{ Action = "edit"; SelectedIndex = $map[$selectedPos]; SearchTerm = $SearchTerm } }
                    "delete" { return @{ Action = "delete"; SelectedIndex = $map[$selectedPos]; SearchTerm = $SearchTerm } }
                    "add" { return @{ Action = "add"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm } }
                    "search" {
                        $newTerm = Read-Host "Search (Enter to abort)"
                        if (-not [string]::IsNullOrEmpty($newTerm)) {
                            $SearchTerm = $newTerm
                            $SelectedIndex = 0
                            $skipIndexUpdate = $true
                        }
                    }
                    "clear" {
                        $SearchTerm = ""
                        if ($Entries.Count -gt 0) { $SelectedIndex = 0 }
                        $skipIndexUpdate = $true
                    }
                    "logout" { return @{ Action = "logout"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm } }
                }
            }
            "Escape" { return @{ Action = "logout"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm } }
            "Q" { return @{ Action = "logout"; SelectedIndex = $SelectedIndex; SearchTerm = $SearchTerm } }
        }
        if ($skipIndexUpdate) { continue }
        if ($map.Count -gt 0) {
            $SelectedIndex = $map[$selectedPos]
        }
    }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-AccountMenu {
    param([array]$Accounts, [int]$Selected = 0)
    if ($Accounts.Count -eq 0) {
        $Selected = 0
    } else {
        $Selected = [Math]::Max(0, [Math]::Min($Selected, $Accounts.Count - 1))
    }
    $actions = @(
        @{ Label = "Login"; Action = "login"; RequiresAccount = $true }
        @{ Label = "Add account"; Action = "add"; RequiresAccount = $false }
        @{ Label = "Delete account"; Action = "delete"; RequiresAccount = $true }
        @{ Label = "Quit"; Action = "quit"; RequiresAccount = $false }
    )
    $actionSelected = 0
    for ($i = 0; $i -lt $actions.Count; $i++) {
        if (-not $actions[$i].RequiresAccount) { $actionSelected = $i; break }
    }
    $focus = if ($Accounts.Count -gt 0) { "accounts" } else { "actions" }
    $helpHint = "SHOW KEYBINDINGS AND INSTRUCTIONS: [ALT+V] OR [CTRL+V]"
    $helpLines = @(
        "VaultX main menu:",
        "  Up/Down  - move selection",
        "  Enter    - confirm action (or login on an account)",
        "  Esc/Q    - quit",
        "  Alt+V / Ctrl+V - show this help",
        "",
        "Accounts:",
        "  Highlight an account, then pick Login or Delete",
        "Actions:",
        "  Add account creates a new vault"
    )
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        while ($true) {
            $actionSelected = [Math]::Max(0, [Math]::Min($actionSelected, $actions.Count - 1))
            Clear-Host
            Write-Header "Main Menu" -ShowBanner
            Write-MenuPrompt "VaultX Main Menu: What would you like to do?"
            if ($Accounts.Count -eq 0) {
                Write-Host "No accounts yet." -ForegroundColor DarkGray
            } else {
                Write-Host "Accounts" -ForegroundColor DarkGray
                for ($i = 0; $i -lt $Accounts.Count; $i++) {
                    $account = $Accounts[$i]
                    $isSelected = ($focus -eq "accounts" -and $i -eq $Selected)
                    $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                    Write-MenuItem -Text $account.Name -IsSelected $isSelected -Color $color
                }
            }
            Write-Host ""
            Write-Host "Actions" -ForegroundColor DarkGray
            if ($Accounts.Count -gt 0) {
                Write-Host ("Selected: " + $Accounts[$Selected].Name) -ForegroundColor DarkGray
            }
            Write-MenuSeparator
            for ($i = 0; $i -lt $actions.Count; $i++) {
                $action = $actions[$i]
                if ($action.Action -eq "quit") { continue }
                $enabled = $true
                if ($action.RequiresAccount -and $Accounts.Count -eq 0) { $enabled = $false }
                $isSelected = ($focus -eq "actions" -and $i -eq $actionSelected)
                if ($enabled) {
                    $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                } else {
                    $color = $script:MenuDisabledColor
                }
                Write-MenuItem -Text $action.Label -IsSelected $isSelected -IsActive:$enabled -Color $color
            }
            Write-MenuSeparator
            $quitIndex = -1
            for ($i = 0; $i -lt $actions.Count; $i++) {
                if ($actions[$i].Action -eq "quit") {
                    $quitIndex = $i
                    break
                }
            }
            if ($quitIndex -ge 0) {
                $quitAction = $actions[$quitIndex]
                $isSelected = ($focus -eq "actions" -and $quitIndex -eq $actionSelected)
                $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                Write-MenuItem -Text $quitAction.Label -IsSelected $isSelected -IsActive:$true -Color $color
            }
            Write-Host ""
            Write-Host "Arrows: Up/Down move, Enter select, Esc/Q quit." -ForegroundColor DarkGray
            Write-MenuHelpHint $helpHint
            $key = Read-MenuKey
            if ($key.Key -eq "V" -and (($key.Modifiers -band [ConsoleModifiers]::Alt) -ne 0 -or ($key.Modifiers -band [ConsoleModifiers]::Control) -ne 0)) {
                Show-MenuHelp -Title "VaultX Keybindings" -Lines $helpLines
                continue
            }
            switch ($key.Key) {
                "UpArrow" {
                    if ($focus -eq "accounts") {
                        if ($Accounts.Count -gt 0 -and $Selected -gt 0) {
                            $Selected--
                        }
                    } else {
                        if ($actionSelected -gt 0) {
                            $actionSelected--
                        } elseif ($Accounts.Count -gt 0) {
                            $focus = "accounts"
                        }
                    }
                }
                "DownArrow" {
                    if ($focus -eq "accounts") {
                        if ($Accounts.Count -gt 0 -and $Selected -lt ($Accounts.Count - 1)) {
                            $Selected++
                        } else {
                            $focus = "actions"
                            $actionSelected = 0
                        }
                    } else {
                        if ($actionSelected -lt ($actions.Count - 1)) {
                            $actionSelected++
                        }
                    }
                }
                "Enter" {
                    if ($focus -eq "accounts") {
                        return @{ Action = "login"; Selected = $Selected }
                    }
                    $action = $actions[$actionSelected]
                    if ($action.RequiresAccount -and $Accounts.Count -eq 0) {
                        Show-Message "No accounts available." ([ConsoleColor]::Red)
                        break
                    }
                    return @{ Action = $action.Action; Selected = $Selected }
                }
                "Escape" { return @{ Action = "quit"; Selected = $Selected } }
                "Q" { return @{ Action = "quit"; Selected = $Selected } }
            }
        }
    } finally {
        if ($null -ne $cursorState) { Set-CursorVisible $cursorState }
    }
}

function Show-EntryDetail {
    param($Entry)
    $fields = Get-EntryFields $Entry
    $items = @()
    foreach ($field in $fields) {
        $items += @{ Type = "field"; Field = $field }
    }
    $items += @{ Type = "action"; Label = "Open URL"; Enabled = (-not [string]::IsNullOrWhiteSpace($Entry.Url)) }
    $items += @{ Type = "action"; Label = "Edit entry" }
    $items += @{ Type = "action"; Label = "Back" }
    $selected = 0
    $cursorState = Get-CursorVisible
    if ($null -ne $cursorState) { Set-CursorVisible $false }
    try {
        while ($true) {
            Clear-Host
            Write-Header ("Entry: " + $Entry.Title)
            $labelWidth = 12
            for ($i = 0; $i -lt $items.Count; $i++) {
                $item = $items[$i]
                $isActive = $true
                if ($item.Type -eq "field") {
                    $display = Format-DisplayValue $item.Field.Display 60
                    $line = ("{0,-$labelWidth} : {1}" -f $item.Field.Label, $display)
                } else {
                    if ($item.PSObject.Properties.Match("Enabled").Count -gt 0 -and -not $item.Enabled) {
                        $isActive = $false
                    }
                    $line = "[Action] " + $item.Label
                }
                $isSelected = ($i -eq $selected)
                if ($isActive) {
                    $color = if ($isSelected) { $script:MenuHighlightColor } else { $script:MenuNormalColor }
                } else {
                    $color = $script:MenuDisabledColor
                }
                Write-MenuItem -Text $line -IsSelected $isSelected -IsActive:$isActive -Color $color
            }
            Write-Host ""
            Write-Host "Enter copies field or runs action, Esc to back." -ForegroundColor DarkGray
            $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow" { $selected = [Math]::Max(0, $selected - 1) }
                "DownArrow" { $selected = [Math]::Min($items.Count - 1, $selected + 1) }
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
                        if ($item.PSObject.Properties.Match("Enabled").Count -gt 0 -and -not $item.Enabled) {
                            Show-Message "No URL available to open." ([ConsoleColor]::Yellow)
                        } else {
                            Open-WebUrl -Url $Entry.Url
                        }
                    } elseif ($item.Label -eq "Edit entry") {
                        return "edit"
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
    Write-Host "Press Enter to continue or Esc to abort." -ForegroundColor DarkGray
    while ($true) {
        $key = Read-MenuKey -Prompt "Command (enter/esc)"
        if ($key.Key -eq "Escape") { return $null }
        if ($key.Key -eq "Enter") { break }
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

    while ($true) {
        $result = Show-EntryList -Entries $script:VaultData.Entries -SelectedIndex $selectedIndex -SearchTerm $searchTerm -AccountName $script:VaultMeta.AccountName
        if ($null -eq $result) { break }
        $selectedIndex = $result.SelectedIndex
        $searchTerm = $result.SearchTerm
        switch ($result.Action) {
            "view" {
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
                    $entry = $script:VaultData.Entries[$selectedIndex]
                    $updated = Read-Entry -Existing $entry
                    if ($null -ne $updated) {
                        Save-Vault -VaultPath $VaultPath -Key $script:VaultKey -Meta $script:VaultMeta -Data $script:VaultData
                    }
                }
            }
            "delete" {
                if ($script:VaultData.Entries.Count -gt 0) {
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
            "logout" { break }
        }
    }
}

function Close-VaultX {
    param([string]$Message)
    Clear-VaultSession
    if ($Message) {
        Write-Host $Message -ForegroundColor DarkGray
    }
}

function Quit-VaultX {
    param([string]$Message)
    Clear-VaultSession
    if ($Message) {
        Write-Host $Message -ForegroundColor DarkGray
    }
    exit
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
    if (-not (Test-Path Function:\global:Quit-VaultX)) {
        $quit = [ScriptBlock]::Create("& '$escaped' -Quit")
        Set-Item -Path Function:\global:Quit-VaultX -Value $quit
    }
}

function Invoke-VaultX {
    $accounts = Get-Accounts
    $selectedAccount = 0

    try {
        Write-Log "VaultX started."
        Register-VaultXSession
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
                    $accounts = Remove-Account -Accounts $accounts -Selected $selectedAccount
                    if ($selectedAccount -ge $accounts.Count) {
                        $selectedAccount = [Math]::Max(0, $accounts.Count - 1)
                    }
                }
                "login" {
                    $account = $accounts[$selectedAccount]
                    $vaultPath = Get-VaultPath -FileName $account.File
                    $vault = Open-Vault -VaultPath $vaultPath -AccountName $account.Name
                    if ($null -ne $vault) {
                        Invoke-VaultSession -VaultPath $vaultPath -Vault $vault
                    }
                }
                "quit" { break }
            }
        }
    } finally {
        Clear-VaultSession
        Write-Log "VaultX session closed."
    }
}

$script:IsDotSourced = $MyInvocation.InvocationName -eq "."
if ($Help) {
    Show-Usage
    return
}

if (-not $script:IsDotSourced) {
    if ($Close) {
        Close-VaultX -Message "$script:AppName closed."
        return
    }
    if ($Quit) {
        Quit-VaultX -Message "$script:AppName closed."
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
}
