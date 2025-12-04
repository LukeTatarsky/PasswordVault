# config.py
"""
Configuration constants
"""
# ──────────────────────────────────────────────────────────────
# Vault settings
# ──────────────────────────────────────────────────────────────
VAULT_FILE = "password_vault.json"        # Name of encrypted vault file
KEY_CHECK_STRING = "MasterKeyValidation"  # Canary to verify master password

# Changing iterations will invalidate existing vaults. Backup plaintext first!
ITERATIONS = 1_000_000                    # Used to generate master key

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
    "bank_safe_symbols":   "!@#$%^*_-+=",
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

# ──────────────────────────────────────────────────────────────
# Optional: local overrides (never commit this local file!)
# Local configuration file overrides standard config values — never commit this file!

# from config import PASS_DEFAULTS
# CLIPBOARD_TIMEOUT = 20
# WIPE_CLIPBOARD = False
# PASS_DEFAULTS["min_length"] = 0
# ──────────────────────────────────────────────────────────────
try:
    from config_local import *
except ImportError:
    pass  # No local config — use defaults above