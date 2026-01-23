# VaultX

TL;DR: A local, single-user password manager built in PowerShell. Encrypted JSON vaults live in your profile, managed through a clean terminal menu. Auto-detects new vault files dropped into the data folder. 🔐⚡

## Features
- Local-only vaults stored under your user profile (no cloud sync).
- AES encryption with per-vault salt and password-derived key.
- Menu-driven UI with fast navigation and a reliable back option.
- Add, view, edit, and delete entries for logins, URLs, and notes.
- Search plus quick clipboard copy for entry fields.
- Auto-refreshes when a new vault file is added to the data folder.
- Export and import encrypted vaults for local migration between machines.
- Optional recovery password to unlock vaults locally if the master password is lost.

## How it Works
1. Run `VaultX.ps1` to launch the main menu.
2. Create or select a vault.
3. Set or enter the master password to unlock it.
4. Manage entries (add/view/edit/delete).
5. Log out to return to the vault list.

## Files
- `VaultX.ps1`: main script and UI.
- `ExecutionPolicy.md`: guidance for allowing script execution on Windows.
- `Readme.md`: this overview.

## Notes
VaultX is designed for local use. If you do not set a recovery password, a lost master password cannot be recovered.
