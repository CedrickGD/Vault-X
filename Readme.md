# VaultX Project Overview

VaultX is a local, single-user password manager implemented as a PowerShell script. It stores account vaults in JSON files under the user profile and encrypts entry data using AES with a password-derived key. The interface is a terminal-driven menu that lets you create accounts (vaults), unlock them with a master password, and manage entries for logins, URLs, and notes.

## Features
- Local-only vaults stored under the user profile (no cloud sync).
- Master password encryption with per-vault salt and key derivation.
- Menu-driven UI to create, unlock, and delete accounts (vaults).
- Entry management for usernames, passwords, URLs, and notes.
- Optional search and quick clipboard copy for entry fields.

## How it Works
1. Run `VaultX.ps1` to launch the main menu.
2. Create or select an account (vault).
3. Set or enter the master password to unlock the vault.
4. Add, view, edit, or delete entries inside the vault.
5. Log out to return to the account selection menu.

## Files
- `VaultX.ps1`: the main script and UI.
- `ExecutionPolicy.md`: guidance for allowing script execution on Windows.
- `Readme.md`: this project overview.

## Notes
VaultX is designed for local use. Keep your master password safe: it cannot be recovered if lost.
