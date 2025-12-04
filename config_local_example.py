# Local configuration file overrides standard config values — never commit this file!
# Used for changing user defaults
from config import PASS_DEFAULTS

CLIPBOARD_TIMEOUT = 20  
WIPE_CLIPBOARD = False  # I dont use clipboard history
PASS_DEFAULTS["min_length"] = 0  # for debugging


# rename this file to config_local.py to use it