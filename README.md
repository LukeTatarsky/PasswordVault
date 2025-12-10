# PasswordVault — Secure Password Manager CLI
A completely offline, cryptographically secure password manager written in Python.
Designed with memory safety in mind (python has limitations), single-entry decryption, and automatic clipboard wiping. Includes an integrated password generator that creates strong, truly random passwords using Python’s secrets module.

**Current version: Command-line only, GUI coming later.**

### Features
- AES-128-CBC + HMAC-SHA256 encryption via Fernet
- Master key derived securely using Argon2id key derivation function 
- Master password canary instantly detects wrong password or corruption
- Atomic file saves – never lose data on crash or power loss
- Full-text search across site, account, and notes
- Password history with timestamps (configurable)
- Secure clipboard handling with auto-clear (configurable)
- Built-in cryptographically secure password generator (customizable)
- Master password rotation without data loss
- Safe handling of corrupted entries

### Security Highlights
- No plaintext ever writes to disk. *Unless user explicitly exports data*
- All sensitive data wiped from memory when no longer needed
- Crash-safe vault file
- Uses `secrets` module for password generation
- Single-entry decryption (only one password is ever in memory)
- Copy masked passwords to clipboard to prevent shoulder surfing, auto clears in 30 seconds.

### Installation
```bash
git clone https://github.com/LukeTatarsky/PasswordVault.git
cd PasswordVault
pip install -r requirements.txt
python PasswordVault_CLI.py
```
### Configuration
The application uses a two-file configuration system:

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

### First Run
Create a strong master password and remember it, there is no recovery without this password.
The encrypted vault is saved as password_vault.json in the current directory.

### Backup & Migration
Your vault is a single portable JSON file. Backup your vault.
Optionally export vault to plaintext json via hidden export_json function
Run the program → Login → type export_json

### Importing data
Import/Export features still in development.

Supports basic csv file import in the following format.
Ensure columns: site,account,password,note
Run the program → Login → type import_csv → enter filename

Supports importing the exported json file.
Run the program → Login → type import_json → enter filename

### Security Notice
This tool is as secure as your master password and your machine.
 - Never run on a compromised or shared system.
 - Use a long, unique master password
 - Backup the encrypted vault regularly
