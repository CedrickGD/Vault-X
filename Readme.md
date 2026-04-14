# VaultX

A local, single-user password manager built in PowerShell. Encrypted JSON vaults live in your profile, and you can manage them through either the terminal menu or a local Windows GUI. Ships as a portable `.exe` or a standalone `.ps1` script with built-in auto-update.

## Features

### Vault & Encryption
- Local-only vaults stored under your user profile (no cloud sync).
- AES encryption with per-vault salt and password-derived key.
- Encrypt-then-MAC integrity (HMAC-SHA256) to detect tampering or corruption.
- Optional recovery password to unlock vaults locally if the master password is lost.

### Entry Management
- Add, view, edit, and delete entries for logins, URLs, and notes.
- Built-in password generator in the entry editor plus `/gen` shortcut support in terminal prompts.
- Search plus quick clipboard copy for entry fields.
- Clipboard copies auto-clear after a short delay when unchanged.

### GUI
- Optional local Windows GUI mode with vault browser, entry editor, CSV import, export, 2FA, and recovery controls.
- Persistent theme toggle with dark and light modes.
- Entry details open on demand and show full stored fields while masking passwords by default.

### 2FA
- Offline TOTP compatible with Google Authenticator / Authy / Ente.
- Optional 24h trusted device token after successful 2FA.
- 2FA secrets are stored inside the encrypted vault and never written in plaintext to disk.

### Import & Export
- Export and import encrypted vaults for local migration between machines.
- Export flow strips 2FA secret so recipients aren’t locked out.
- Export can use master password or a separate export password.
- Quick export locations (Desktop/Downloads) plus custom folder path.
- Import browser CSV exports into entries.

### Auto-Update
- Checks GitHub releases for new versions on startup.
- Supports deferred updates (apply on next launch) and in-place updates.
- Can be disabled in-app or by setting the environment variable `VAULTX_UPDATE_CHECK=0`.

### Installation
- Run `VaultX.exe` directly as a portable app, or run `VaultX.ps1` from any terminal.
- In-app option to install a Start Menu shortcut so VaultX is searchable from the Windows search bar.
- Build your own `.exe` with the included `Build-VaultX.ps1` script (requires the `ps2exe` module).

## Quick Start
1. Download `VaultX.exe` (or `VaultX.ps1`) from the [latest release](https://github.com/CedrickGD/Vault-X/releases/latest).
2. Run `VaultX.exe`, or launch `VaultX.ps1` from PowerShell (add `-Gui` to open the GUI directly).
3. Create or select a vault and set a master password.
4. Add entries, generate passwords, enable 2FA, and manage your vaults.

## Building from Source
```powershell
# Install the ps2exe module (one-time)
Install-Module ps2exe -Scope CurrentUser -Force

# Compile VaultX.exe into the dist/ folder
.\Build-VaultX.ps1
```
The build script compiles `VaultX.ps1` into `dist/VaultX.exe` with the app icon, installs it to `%LOCALAPPDATA%\VaultX`, and creates a Start Menu shortcut.

## Files
| File | Description |
|------|-------------|
| `VaultX.ps1` | Main script — terminal UI and local GUI |
| `Build-VaultX.ps1` | Compiles the script into a portable `.exe` |
| `version.yml` | Version manifest used by auto-update |
| `assets/VaultX.ico` | Application icon |

## Notes
- VaultX is designed for local use. If you do not set a recovery password, a lost master password cannot be recovered.
- Exported vaults default to `VaultName_export.json`.
- Customizable UI colors (names or hex) with persistent settings and reset.
