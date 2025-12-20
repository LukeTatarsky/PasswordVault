# config.py
"""
Configuration constants
"""
from pathlib import Path
# ==============================================================
# Vault settings
# ==============================================================
# Software version
VERSION = "1.3.0"

# Name of encrypted vault file
BASE_DIR = Path(__file__).resolve().parent.parent.parent
VAULT_FILE = BASE_DIR  / "password_vault.json"


# Canary to verify master password. Do not change once vault is created.
KEY_CHECK_STRING = "MasterKeyValidation"

# Length of generated random salt
SALT_LEN = 16

# Argon2id parameters
# Changing these will invalidate existing vaults. Backup plaintext first!
ARGON_TIME = 6             # Iterations - controls CPU cost
ARGON_MEMORY = 256 * 1024  # 256 MiB - controls RAM cost
ARGON_PARALLELISM = 2
ARGON_HASH_LEN = 32        # bytes - Encryption key size - DO NOT CHANGE

# ChaCha20Poly1305 nonce length. DO NOT CHANGE
NONCE_LEN = 12



# ==============================================================
# Password generation defaults (strong but practical)
# ==============================================================
PASS_DEFAULTS = {
    "length": 20,                   # Default generated password length
    "min_length": 0,                # Minimum allowed (manual or generated)
    "min_upper": 3,
    "min_lower": 3,
    "min_digits": 3,
    "min_symbols": 3,
    "max_consecutive": 3,            # Reject "aaaa", "1111", etc.
    "avoid_ambiguous": True,         
    "ambiguous_chars": "lI1oO08",
    "symbols_pool":   "!@#()[]|?$%^*_-+.=",
    "safe_symbols":   "!@#$&=_-",
}
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
DT_FORMAT_PASS_HISTORY = "MMM D, YY"
DT_FORMAT_EXPORT = 'YYYY_MM_DD_HH_mm_ss'
CLEAR_SCREEN = True

# ==============================================================
# System Constants
# ==============================================================
# length of eid
EID_LEN = 16

# length of visible name when displaying entries
SITE_LEN = 15
ACCOUNT_LEN = 22

# separator
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