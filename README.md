# PasswordVault — Secure Password Manager CLI
A completely offline, cryptographically secure password manager written in Python.
Designed with memory safety in mind, single-entry decryption, and automatic clipboard wiping. Includes an integrated password generator that creates strong, truly random passwords.


## Features
- AES-128-CBC + HMAC-SHA256 encryption via Fernet
- Master key derived securely using Argon2id key derivation function 
- Master password canary instantly detects wrong password or corruption
- Atomic file saves – never lose data on crash or power loss
- 2FA Authenticator Key storage - Generates TOTP codes
- Full-text search across site, account, and notes
- Password history with timestamps (configurable)
- Copy masked passwords to clipboard, auto clears after set time.
- Secure clipboard handling with auto-clear (configurable)
- Secure password generator using `secrets` module (customizable)

## Installation
```bash
git clone https://github.com/LukeTatarsky/PasswordVault.git
cd PasswordVault
pip install -r requirements.txt
python PasswordVault_CLI.py
```
## Configuration
Uses a two-file configuration system:

- `config.py` – Default settings (committed to git)  
  Contains formatting options and security defaults.

- `config_local.py` – Your personal overrides 
  Create this file in the same directory to customize anything without affecting the main config.

Example `config_local.py`:
```python
from config import PASS_DEFAULTS

# Longer default passwords
PASS_DEFAULTS["length"] = 24
PASS_DEFAULTS["min_symbols"] = 4

# Faster clipboard clear
CLIPBOARD_TIMEOUT = 15

# Disable clipboard history wipe
WIPE_CLIPBOARD = False
```

## First Run
Create a strong master password and remember it, there is no recovery without this password.
The encrypted vault is saved as password_vault.json in the current directory.


## Exporting data
Import/Export features still in development.
 
Your vault is a single portable JSON file. Backup your vault.
Optionally export vault to plaintext json by typing export_json in main menu.

Run the program → Login → type export_json

## Importing data

### CSV

Supports csv file import. Any unsupported fields will still be stored but won't be visible until exporting the vault.

Include these fields for main functionality of the script.

site, account, password, note, totp

Run the program → Login → type import_csv → enter filename

### JSON

Supports importing a previously exported json file.

Run the program → Login → type import_json → enter filename

## Best Practice
This tool is as secure as your master password and your machine.
- Never run on a compromised or shared system.
- Use a long, unique master password
- Backup a copy of the encrypted vault regularly
