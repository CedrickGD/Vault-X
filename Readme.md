# VaultX

TL;DR: A local, single-user password manager built in PowerShell. Encrypted JSON vaults live in your profile, managed through a clean terminal menu. Auto-detects new vault files dropped into the data folder. 🔐⚡

## Features
- Local-only vaults stored under your user profile (no cloud sync).
- AES encryption with per-vault salt and password-derived key.
- Encrypt-then-MAC integrity (HMAC-SHA256) to detect tampering or corruption.
- Menu-driven UI with fast navigation and a reliable back option.
- Add, view, edit, and delete entries for logins, URLs, and notes.
- Search plus quick clipboard copy for entry fields.
- Auto-refreshes when a new vault file is added to the data folder.
- Offline 2FA (TOTP) compatible with Google Authenticator / Authy / Ente.
- Optional 24h trusted device token after successful 2FA.
- Export and import encrypted vaults for local migration between machines.
- Export flow strips 2FA secret so recipients aren’t locked out.
- Export can use master password or a separate export password.
- Quick export locations (Desktop/Downloads) plus custom folder path.
- Import browser CSV exports into entries.
- Customizable UI colors (names or hex) with persistent settings + reset.
- Optional recovery password to unlock vaults locally if the master password is lost.

## How it Works
1. Run `VaultX.ps1` to launch the main menu.
2. Create or select a vault.
3. Set or enter the master password to unlock it.
4. Manage entries (add/view/edit/delete).
5. Log out to return to the vault list.

## Files
- `VaultX.ps1`: main script and UI.
- `Readme.md`: this overview.

## Notes
VaultX is designed for local use. If you do not set a recovery password, a lost master password cannot be recovered.
2FA secrets are stored inside the encrypted vault data and never written in plaintext to disk.
Exported vaults default to `VaultName_export.json`.
