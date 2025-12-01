# MyVault — Secure Password Manager

A fast, cryptographically secure password manager written in Python.
Designed with cold-boot resistance: no persistent plaintext cache, single-entry decryption, and automatic clipboard wiping. Only one password exists in memory at any time, and it is eligible for garbage collection immediately after use.

### Features
- AES-128-CBC + HMAC-SHA256 via **Fernet**
- Key derived with **PBKDF2-HMAC-SHA256** (1M iterations)
- Password verification via **encrypted canary**
- Secure clipboard handling with auto-clear
- Full-text search across sites, accounts, and notes
- Customizable strong password generator (special requirements)
- Master password replacement without data loss

### Security Highlights
- No plaintext ever touches disk
- All operations in memory, zero cache
- Resistant to memory dumping
- Uses `secrets` module
- Single-entry decryption (only one password is ever in memory)

### Installation
```bash
git clone https://github.com/yourname/MyVault.git
cd MyVault
pip install -r requirements.txt
python MyVault.py