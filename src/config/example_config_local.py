# Local configuration file overrides standard config values — never commit this file!
# Used for changing user defaults
from config.config_vault import PASS_DEFAULTS

ARGON_TIME = 7
CLIPBOARD_TIMEOUT = 20  
WIPE_CLIPBOARD = False
PASS_DEFAULTS["min_length"] = 0
PASS_DEFAULTS["length"] = 24  
CLEAR_SCREEN = False

# Rename this file to config_local.py to enable it