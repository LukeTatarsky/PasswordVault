# config.py
"""
Configuration constants
"""
from pathlib import Path
import sys
# ==============================================================
# Vault settings
# ==============================================================
# Software version
VERSION = "2.0.0"

# Name of encrypted vault file
if getattr(sys, "frozen", False):
    # PyInstaller executable
    BASE_DIR = Path(sys.executable).resolve().parents[2]
else:
    # Normal Python run
    BASE_DIR = Path(__file__).resolve().parents[2]
    
VAULT_DIR = BASE_DIR / "vault"
VAULT_DIR.mkdir(exist_ok=True)

EXPORT_DIR = BASE_DIR / "vault_import_export"
EXPORT_DIR.mkdir(exist_ok=True)

IMPORT_DIR = BASE_DIR / "vault_import_export"
# IMPORT_DIR.mkdir(exist_ok=True)

VAULT_FILE = VAULT_DIR / "passwords.vault"

# Word lists retrieved from https://github.com/dmuth/diceware
WORD_LIST = BASE_DIR / "src/data/large_wordlist.txt"

# Canary to verify master password. Do not change once vault is created.
KEY_CHECK_STRING = "MasterKeyValidationCanary"

# Length of generated random salt
SALT_LEN = 16

# Argon2id parameters
# Changing these will invalidate existing encrypted vaults. Backup to plaintext first
ARGON_TIME = 4             # Controls CPU cost
ARGON_MEMORY = 256 * 1024  # Controls RAM cost
ARGON_PARALLELISM = 2
ARGON_HASH_LEN = 32        # Encryption key size - DO NOT CHANGE

# ChaCha20Poly1305 nonce length. 
NONCE_LEN = 12 # DO NOT CHANGE

# ==============================================================
# Password generation defaults
# ==============================================================
PASS_DEFAULTS = {
    "length": 21,                   # Default generated password length
    "max_length": 1000,               
    "min_upper": 4,
    "min_lower": 4,
    "min_digits": 4,
    "min_symbols": 4,
    "min_custom_length": 1,
    "max_consecutive": 2,            # Reject "aaaa", "1111", etc.
    "avoid_ambiguous": False,         
    "ambiguous_chars": "lI1oO08",
    "symbols_pool":   "!@#()[]|?$%^*_-+.=",
    "use_safe_symbs": False,
    "safe_symbols":   "!@#$&=_-",
    "phrase_len": 5,
    "phrase_sep": ["_", "-", ".", "!"],
    "phrase_use_nums": True,
}
PASS_DEFAULTS["min_length"] = PASS_DEFAULTS["min_upper"] \
                            + PASS_DEFAULTS["min_lower"] \
                            + PASS_DEFAULTS["min_digits"] \
                            + PASS_DEFAULTS["min_symbols"]

PASSWORD_HISTORY_LIMIT = 5        # Number of previous passwords to keep

# ==============================================================
# Clipboard security
# ==============================================================
CLIPBOARD_TIMEOUT = 30               # Seconds before auto-clear
WIPE_CLIPBOARD = True                # Enable/disable clipboard flooding
CLIPBOARD_LENGTH = 80                # Number of entries to flood

# ==============================================================
# Display & formatting
# ==============================================================
UTF8 = "utf-8"
DT_FORMAT = "MMM D, YYYY hh:mm:ss A"
DT_FORMAT_PASS_HISTORY = "YYYY-MM-DD"
DT_FORMAT_EXPORT = 'YYYY_MM_DD_HH_mm_ss'
CLEAR_SCREEN = True

# ==============================================================
# System Constants
# ==============================================================
# Length of eid
EID_LEN = 16

# Length of visible name when displaying entries
SITE_LEN = 15
ACCOUNT_LEN = 22

# Separator
SEP_LG= "="*50
SEP_SM = "-"*50

# ==============================================================
# Optional: local overrides
# Local configuration file overrides standard config values

# ==============================================================
try:
    from config.config_local import *
except ImportError:
    pass  # No local config — use defaults above