# config.py
"""
Configuration constants
"""
# ──────────────────────────────────────────────────────────────
# Vault settings
# ──────────────────────────────────────────────────────────────
VAULT_FILE = "password_vault.json"        # Name of encrypted vault file
KEY_CHECK_STRING = "MasterKeyValidation"  # Canary to verify master password

# Argon2id parameters
# Changing these will invalidate existing vaults. Backup plaintext first!
ARGON_TIME = 6             # Iterations - controls CPU cost
ARGON_MEMORY = 256 * 1024  # 256 MiB - controls RAM cost
ARGON_PARALLELISM = 2
ARGON_HASH_LEN = 32        # # 32 byte - Fernet key size - DO NOT CHANGE

# ──────────────────────────────────────────────────────────────
# Password generation defaults (strong but practical)
# ──────────────────────────────────────────────────────────────
PASS_DEFAULTS = {
    "length": 20,                   # Default generated password length
    "min_length": 14,                # Minimum allowed (manual or generated)
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

# ──────────────────────────────────────────────────────────────
# Clipboard security
# ──────────────────────────────────────────────────────────────
CLIPBOARD_TIMEOUT = 30               # Seconds before auto-clear
WIPE_CLIPBOARD = True                # Enable/disable clipboard flooding
CLIPBOARD_LENGTH = 80                # Number of entries to flood

# ──────────────────────────────────────────────────────────────
# Display & formatting
# ──────────────────────────────────────────────────────────────
DT_FORMAT = "MMM D, YYYY hh:mm:ss A"
DT_FORMAT_PASS_HISTORY = "MMM D, YY"
CLEAR_SCREEN = True
# ──────────────────────────────────────────────────────────────
# Optional: local overrides
# Local configuration file overrides standard config values

# ──────────────────────────────────────────────────────────────
try:
    from config_local import *
except ImportError:
    pass  # No local config — use defaults above