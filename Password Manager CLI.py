"""
MyVault Password Manager v4
Local password manager with strong encryption and random password generation.
"""
# ──────────────────────────────────────────────────────────────
# Standard imports
# ──────────────────────────────────────────────────────────────
import os
import sys
import json
import uuid
import time
import atexit
import getpass
import threading
import secrets
import string
import re
import base64
import traceback
import logging
from typing import Dict, Any, Tuple, Final

# ──────────────────────────────────────────────────────────────
# Third-party imports
# ──────────────────────────────────────────────────────────────
try:
    import pyperclip
    import pendulum
    from config import *
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as e:
    missing_package = e.name if hasattr(e, "name") else "unknown package"
    print("Missing required dependency!")
    print(f"  {missing_package} is not installed")
    print("\nInstall with:")
    print("  pip install -r requirements.txt")
    sys.exit(1)
# ──────────────────────────────────────────────────────────────
# System Constants
# ──────────────────────────────────────────────────────────────
_UTF8: Final = "utf-8"
# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="error.log",
    filemode="a",
    level=logging.ERROR,
    format="%(message)s"
)
def log_uncaught_exceptions(exctype, value, tb):
    now = pendulum.now().to_iso8601_string()

    lines = []
    for frame in traceback.extract_tb(tb):
        filename = os.path.basename(frame.filename)  # e.g. vault.py
        lines.append(f"  File \"{filename}\", line {frame.lineno}, in {frame.name}")

    trace_summary = "\n".join(reversed(lines)) if lines else "  <no traceback>"

    error_msg = f"{exctype.__name__}: {value}"

    logging.error(
        f"[{now}] Uncaught exception: {error_msg}\n"
        f"Traceback (most recent call last):\n"
        f"{trace_summary}\n"
        f"{error_msg}"
    )

    print("\nOops! Something went wrong.")
    print("Details saved to error.log\n", file=sys.stderr)

sys.excepthook = log_uncaught_exceptions

# ──────────────────────────────────────────────────────────────
# Functions
# ──────────────────────────────────────────────────────────────
def derive_key(pw: str, salt: bytes) -> bytes:
    """
    -------------------------------------------------------
    Derives a 32-byte key from a password and salt
    using PBKDF2-HMAC-SHA256 and a fixed number of iterations. 
    The key is encoded as a URL-safe base64 string 
    suitable for direct use with Fernet.
    Use: key = derive_key(password, salt)
    -------------------------------------------------------
    Parameters:
        pw   - the user password or passphrase (str)
        salt - cryptographically random salt, unique per key (bytes)
    Returns:
        bytes - URL-safe base64-encoded 32-byte key
    -------------------------------------------------------
    """
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt(text: str, key: bytes) -> str:
    """
    -------------------------------------------------------
    Encrypts a plaintext string using Fernet symmetric encryption
    and returns the encrypted token as a string.
    Use: token = encrypt("secret message", fernet_key)
    -------------------------------------------------------
    Parameters:
        text - the plaintext message to encrypt (str)
        key  - a valid Fernet key (bytes)
    Returns:
        str  - URL-safe base64 Fernet token
    -------------------------------------------------------
    """
    return Fernet(key).encrypt(text.encode(_UTF8)).decode(_UTF8)

def decrypt(token: str, key: bytes) -> str:
    """
    -------------------------------------------------------
    Decrypts a Fernet token back into the original 
    plaintext bytes using the supplied symmetric key.
    By default tokens never expire, use ttl to check.
    Use: data = decrypt(token, fernet_key)
    -------------------------------------------------------
    Parameters:
        token - encrypted Fernet token produced by encrypt() (str)
        key   - the same Fernet key used for encryption (bytes)
    Returns:
        str   - decrypted plaintext
    -------------------------------------------------------
    Raises:
        cryptography.fernet.InvalidToken - if token is invalid,
               tampered with, or the key is incorrect
    -------------------------------------------------------
    """
    return Fernet(key).decrypt(token.encode(_UTF8)).decode(_UTF8)

def get_entry_data(entries: dict[str, str], key: bytes, eid: str) -> dict[str, object]:
    """
    -------------------------------------------------------
    Retrieves and decrypts a single entry from a dictionary
    of encrypted entries. The entry value is expected to be a Fernet
    token. 
    The decrypted JSON string is parsed and returned as a dictionary.
    Use: entry = get_entry_data(password_db, fernet_key, "user123")
    -------------------------------------------------------
    Parameters:
        entries - dictionary mapping entry IDs to encrypted tokens
                  e.g. {"user123": "gAAAAAB..."} (Dict[str, str])
        key     - Fernet symmetric key used for decryption (bytes)
        eid     - entry ID (dict key) to look up and decrypt (token str)
    Returns:
        Dict[str, Any] - decrypted and parsed entry data
                         returns empty dict {} on error or if not found
    -------------------------------------------------------
    Side effects:
        Prints user-friendly messages on KeyError (not found) or
        decryption/parsing failure (corrupted/invalid).
    -------------------------------------------------------
    """
    data: Dict[str, Any] = {}
    try:
        encrypted_token: str = entries[eid]
        data = json.loads(decrypt(encrypted_token, key))
    except KeyError:
        print("Not found.")
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        print("Entry may be corrupted, cannot view.")
    except Exception as e:
        print(f"Unexpected error: {e}")
    return data

def load_vault(master_pw: str) -> Tuple[bytes, Dict[str, str], bytes]:
    """
    -------------------------------------------------------
    Loads or creates the encrypted password vault file.
    On first run: creates a new vault with a random salt and a
    canary value to verify the master password later.
    On subsequent runs: loads the vault, derives the key from the
    master password + stored salt, and verifies the password using
    the encrypted canary. Exits the program on wrong password.
    Use: key, entries, salt = load_vault("mymasterpassword")
    -------------------------------------------------------
    Parameters:
        master_pw - the master password (str)
    Returns:
        Tuple[bytes, Dict[str, str], bytes]
            - derived Fernet key (bytes)
            - dictionary of encrypted entries {eid(str): token(str)}
            - salt used for key derivation (bytes)
    -------------------------------------------------------
    Side effects:
        Creates vault file if it doesn't exist.
        Prints status messages.
    -------------------------------------------------------
    """
    # ──────────────────────────────────────────────────────────────
    # 1. Create new vault if none exists
    # ──────────────────────────────────────────────────────────────
    if not os.path.exists(VAULT_FILE):
        print("Creating new password vault...")
        salt = os.urandom(16)
        key = derive_key(master_pw, salt)

        vault = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "canary": encrypt(KEY_CHECK_STRING, key),
            "entries": {}
        }
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2)

        return key, {}, salt

    # ──────────────────────────────────────────────────────────────
    # 2. Load existing vault
    # ──────────────────────────────────────────────────────────────
    with open(VAULT_FILE, encoding="utf-8") as f:
        vault: Dict[str, Any] = json.load(f)

    # Extract and decode stored salt
    try:
        salt = base64.urlsafe_b64decode(vault["salt"])
    except (KeyError, base64.binascii.Error):
        msg = "Vault is corrupted: missing or invalid salt!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # Derive key from user password + stored salt
    key = derive_key(master_pw, salt)

    # ──────────────────────────────────────────────────────────────
    # 3. Verify master password using the canary
    # ──────────────────────────────────────────────────────────────
    if "canary" not in vault:
        msg = "Vault corrupted: missing canary!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

    try:
        decrypted_canary = decrypt(vault["canary"], key)
        if decrypted_canary != KEY_CHECK_STRING:
            msg = "Wrong master password!"
            print(msg)
            now = pendulum.now().to_iso8601_string()
            logging.error(f"[{now}] {msg}\n")
            sys.exit(1)
    except InvalidToken:
        msg = "Wrong master password or vault is corrupted!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # ──────────────────────────────────────────────────────────────
    # 4. Return decrypted entries container
    # ──────────────────────────────────────────────────────────────
    encrypted_entries: Dict[str, str] = vault.get("entries", {})

    print("Vault unlocked successfully.")
    return key, encrypted_entries, salt

def save_vault(encrypted_entries: dict[str, str], salt: bytes, key: bytes) -> None:
    """
    -------------------------------------------------------
    Securely saves the encrypted password vault to disk using
    atomic write which guarantees data integrity.
    Safe from program crashes, power fails, etc..  mid-save.
    This ensures the vault file is either 100% old or 100% new.

    The canary is re-encrypted on every save to match the 
    current master password + salt.
    Use: save_vault(encrypted_db, current_salt, fernet_key)
    -------------------------------------------------------
    Parameters:
        encrypted_entries - dict mapping entry IDs to encrypted tokens
                            e.g. {"user123": "gAAAAAB..."} (dict[str, str])
        salt              - current salt used for key derivation (bytes)
        key               - current derived Fernet key (bytes)
    Returns:
        None
    -------------------------------------------------------
    Side effects:
        Overwrites VAULT_FILE atomically with new vault data.
    -------------------------------------------------------
    """
    vault = {
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "canary": encrypt(KEY_CHECK_STRING, key),
        "entries": encrypted_entries
    }

    # Write to temporary file first.
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(vault, f, indent=2)
        f.flush()
        os.fsync(f.fileno()) # force to disk

    # Atomic replace the VAULT FILE. Then clear tmp.
    os.replace(tmp, VAULT_FILE)
    return

def display_entry(source: Dict[str, Any], key: bytes | None = None,
    eid: str | None = None,  *,
    show_pass: bool = False, show_history: bool = False) -> int: 
    # note: * enforces that everything afterwards is called by name (no positional args)
    """
    -------------------------------------------------------
    Displays a single entry in a human-readable format.
    Supports optional password masking. Used for command line output.

    1) When viewing from vault: pass encrypted_entries + key + eid
    2) When editing (in-memory): pass decrypted dict + key=None + eid=None

    Use:
        Mode 1)
        display_entry(encrypted_entries, key, "github")         # from vault

        Mode 2)
        display_entry(current_data)                             # while editing
        display_entry(current_data, show_pass=True)             # reveal pw
        display_entry(current_data, show_history=True)             # reveal pw history
    -------------------------------------------------------
    Parameters:
        source        - either:  (dict[str, Any])
                          • encrypted_entries dict {eid: token} when viewing from vault
                          • decrypted entry dict when editing/previewing
        key           - Fernet key for decryption (bytes)
                         Omit when source is already decrypted
        eid           - entry ID to look up (str)
                         Omit when source is already decrypted
        show_pass - if True, reveals plaintext password
                        if False (default), masks with asterisks (bool)
        show_history - if True, show password change history (if any)

    Returns:
        int - 0 on success
              1 if entry not found, corrupted, or invalid
    -------------------------------------------------------
    """

    # ──────────────────────────────────────────────────────────────
    # 1. Decide on input type
    # ──────────────────────────────────────────────────────────────
    if eid is not None and key is not None:
        # Mode 1: Display from encrypted vault
        data = get_entry_data(source, key, eid)
        if not data:
            return 1
    else:
        # Mode 2: Display already-decrypted in-memory dict
        data = source
        if not data:
            return 1

    print(f"\nSite         : {data.get('site', '(missing)')}")
    print(f"Account      : {data.get('account') or ''}")

    # ─── Password (masked or revealed) ────────────────────────────────────
    password = data.get('password', '') or ''
    if show_pass:
        print(f"Password     : {password}")
    else:
        masked = '*' * PASS_DEFAULTS["length"] if password else ''
        print(f"Password     : {masked}")

    # ─── Password History (only if requested and exists) ──────────────────
    if show_history and data.get('password_history'):
        history = data.get('password_history', [])
        if history:
            print(f"Pass History : ")
            print(f" - Last used :")
            for pw_entry in history:
                print(f" - {pendulum.parse(pw_entry.get('last_used','unknown date'))
                            .in_timezone('local').format(DT_FORMAT_PASS_HISTORY)} :",
                    f" {pw_entry.get('password','')}")
    
    # ─── Note ─────────────────────────────────────────────────────────────
    print("Note         :")
    note = data.get('note', '').strip()
    if note:
        print("-" * 40)
        print(note)
        print("-" * 40)
    # ─── Timestamps ───────────────────────────────────────────────────────
    try:
        created = pendulum.parse(data.get('created_date', '1970-01-01T00:00:00Z'))
        edited = pendulum.parse(data.get('edited_date', '1970-01-01T00:00:00Z'))
    except Exception:
        created = edited = pendulum.now()
    finally:
        data = None
    
    print(f"Created      : {created.in_timezone('local').format(DT_FORMAT)}")
    print(f"Last Edited  : {edited.in_timezone('local').format(DT_FORMAT)}\n")
    data = None
    return 0

def update_entry(encrypted_entries: dict[str, str], key: bytes, salt: bytes, eid: str) -> int:
    """
    -------------------------------------------------------
    Interactive command line entry editor.

    Loads and decrypts the specified entry, then presents a full-featured
    menu allowing the user to:
      • Edit site, account, password, or note
      • View current entry
      • Save changes with updated timestamp
      • Delete the entry permanently
      • Cancel and discard any changes

    Changes are written to disk only if the user explicitly confirms 
    with 's' (save) or 'del' (delete).

    Use:
        update_entry(vault_entries, fernet_key, current_salt, "github")
    -------------------------------------------------------
    Parameters:
        encrypted_entries - current in-memory dict of encrypted entries
                            {entry_id: fernet_token} (dict[str, str])
        key               - active Fernet key for decryption/encryption (bytes)
        salt              - current vault salt (used only for saving) (bytes)
        eid               - entry ID to edit (must exist in vault) (str)

    Returns:
        int - 0 on success (saved, deleted, or cancelled)
              1 if entry not found or corrupted
    -------------------------------------------------------
    Menu options:
        1. Edit Site          5. Display Entry (incl pass)
        2. Edit Account       6. Save & Exit
        3. Edit Password      7. Delete Entry
        4. Edit Note          8. Cancel (discard changes)
    -------------------------------------------------------
    Security features:
        • Requires explicit confirmation ('s' or 'del')
        • Site cannot be empty
        • Timestamp automatically updated on save
        • Maintains password history (last 10)
    -------------------------------------------------------
    """
    if eid not in encrypted_entries:
        print("ID not found")
        return 1

    # Load and decrypt the entry
    try:
        data = json.loads(decrypt(encrypted_entries[eid], key))
    except InvalidToken:
            res = delete_corrupted_entry(encrypted_entries, salt, key, eid)
            return res
    except Exception:
        print("Entry corrupted — cannot edit")
        return 1

    display_entry(data, None, None, show_pass=False)

    while True:
        print("\nWhat would you like to do?")
        print("   1. Edit Site          5. Display Entry (incl pass)")
        print("   2. Edit Account       6. Save & Exit")
        print("   3. Edit Password      7. Delete Entry")
        print("   4. Edit Note          8. Cancel (discard changes)")
        
        choice = input("\n → ").strip()

        if choice == "1":
            current = data.get('site', '')
            new_site = input(f"New site [{current}]: ").strip()
            if new_site and new_site != current:
                data["site"] = new_site
                print("   Site updated")
            else:
                print("   Site unchanged")

        elif choice == "2":
            current = data.get('account') or ''
            new_acc = input(f"New account [{current}]: ").strip()
            data["account"] = new_acc or ''
            print("   Account updated")

        elif choice == "3":
            new_pw = ask_password("New password")
            # Keep password history
            pw_history = data.get("password_history", [])
            pw_history.insert(0, {"password" : data.get("password", ""),
                                "last_used" : pendulum.now().to_iso8601_string()})
            data["password_history"] = pw_history[:PASSWORD_HISTORY_LIMIT]

            data["password"] = new_pw
            print("   Password updated")

        elif choice == "4":
            print ("\nCurrent note:")
            print("-" * 40)
            print(data.get("note", "")) 
            print("-" * 40)
            note = get_note_from_user()
            data["note"] = note
            print("   Note updated")

        elif choice == "5":
            display_entry(data, show_pass=True)

        elif choice == "6":
            if data.get("site", "").strip() == "":
                print("   Error: Site cannot be empty!")
                continue

            confirm = input(f"\nSave changes to {data.get('site', '')}? (type 's' to confirm): ")
            if confirm.strip().lower() != "s":
                print("   Save cancelled")
                continue

            # Update timestamp
            data["edited_date"] = pendulum.now().to_iso8601_string()

            # Re-encrypt and save
            blob = encrypt(json.dumps(data, separators=(',', ':')), key)
            encrypted_entries[eid] = blob
            save_vault(encrypted_entries, salt, key)
            print("\nEntry updated and saved successfully!")
            data = None
            return 0

        elif choice == "7":
            confirm = input(f"\nDelete this entry permanently? (type 'del' to confirm): ")
            if confirm.strip().lower() == "del":
                del encrypted_entries[eid]
                save_vault(encrypted_entries, salt, key)
                print("Entry deleted.")
                data = None
                return 0
            else:
                print("   Delete cancelled")
            
        elif choice == "8":
            print("All changes discarded.")
            data = None
            return 0

        else:
            print("   Invalid option — choose 1–8")


def list_entries(encrypted_entries: dict[str, str], key: bytes,
                  query: str = None) -> None:
    """
    -------------------------------------------------------
    Lists all vault entries — with optional search filtering.

    Decrypts each entry and displays site and account. 
    Undecryptable entries are marked as corrupted.

    Entries are sorted alphabetically by site, then by account.

    Use:
        list_entries(encrypted_entries, key)
        list_entries(encrypted_entries, key, query="github")
    -------------------------------------------------------
    Parameters:
        encrypted_entries - dict of encrypted entries {eid: token}
                            (dict[str, str])
        key               - Fernet key
        search            - optional search term (case-insensitive)
                            • None  = list all
                            • str   = filter results

    Returns:
        None
    -------------------------------------------------------
    Output example:
        Your entries:
                ID →              Site Account
            ----------------------------------------
            73173e6c →     [corrupted]
            b074ec2e →          github 23
            e48179d8 →           gmail user41
    -------------------------------------------------------
    Features:
        • Full-text search across site, account, and note
        • Passwords never shown
        • Corrupted entries handled gracefully
        • Sorted alphabetically by site → accountg
        • Memory-safe — temporary decrypted data cleared
    -------------------------------------------------------
    """
    if not encrypted_entries:
        print("Empty vault — no entries yet.")
        return
    
    # Temporary dict: eid → (site, account)
    display_data: dict[str, tuple[str, str]] = {}

    for eid, blob in encrypted_entries.items():
        try:
            data = json.loads(decrypt(blob, key))
            site = data.get("site", "(no site)")
            account = data.get("account", "")
            note = data.get("note", "")

            # Build searchable text
            searchable_str = " ".join([site, account, note]).lower()
            
            # Filter if searching
            if query:
                query = query.lower().strip()
                terms = query.split()
            
                # Keep entry only if ALL words appear somewhere
                if not all(term in searchable_str for term in terms):
                    continue

            display_data[eid] = (site, account)

        except Exception:
            # only show corrupted if not searching
            if not query:
                display_data[eid] = ("corrupted", "")
        finally:
            data = None

    if not display_data:
        print("  No entries found." + (" (try different term)" if query else ""))
        return
    
    # Sort by site , then account
    sorted_entries = sorted(
        display_data.items(),
        key=lambda entry: (entry[1][0].lower(), entry[1][1].lower() or "")
    )

    print("\nYour entries:")
    print (f"{'ID':>8} → {'Site':>15}  Account")
    print("-" * 40)

    for eid, (site, account) in sorted_entries:
        print(f"{eid:>8} → {site:>15}  {account}")

    # Clear temp
    data = None
    display_data = {}
    sorted_entries = {}
    return

def change_master_password() -> None:
    """
    -------------------------------------------------------
    Changes the master password of the vault.

    This function performs a complete master password rotation:
      • Verifies the current password
      • Generates a new random salt
      • Derives a new encryption key from the new password
      • Decrypts each entry with the old key
      • If any entry fails to decrypt → operation aborts immediately
      • Re-encrypts each entry with the new key
      • Atomically saves the new vault with updated salt and canary

    All old encrypted data becomes permanently unreadable after this.
    There is no "undo" — this is by design for forward secrecy.

    Use:
        main menu → "Change master password"
    -------------------------------------------------------
    Security:
        • Old password is verified before any changes
        • New salt is generated
        • Every entry is fully re-encrypted
        • Atomic save via save_vault()
        • Empty passwords rejected
        
    -------------------------------------------------------
    Returns:
        None
    -------------------------------------------------------
    """
    print("\n=== Change Master Password ===")

    old_pw = getpass.getpass("Current master password: ").strip()
    new_pw = getpass.getpass("New master password: ").strip()
    confirm = getpass.getpass("Confirm new master password: ").strip()

    if new_pw != confirm:
        print("New passwords do not match!")
        return
    if not new_pw:
        print("Master password cannot be empty!")
        return

    # 1. Try to load with the old password (this also verifies it)
    try:
        temp_key, temp_entries, _ = load_vault(old_pw)
    except SystemExit:
        print("Wrong current password!")
        return

    print("Current password verified. Re-encrypting all entries...")

    # 2. Derive a new salt and key from the new password
    new_salt = os.urandom(16)
    new_key = derive_key(new_pw, new_salt)

    # 3. Decrypt and re-encrypt every entry with the new key
    new_encrypted_entries: Dict[str, str] = {}
    for eid, old_blob in temp_entries.items():
        try:
            # Decrypt with old key
            plaintext = decrypt(old_blob, temp_key)
            # Encrypt again with new key
            new_blob = encrypt(plaintext, new_key)
            plaintext = None
            new_encrypted_entries[eid] = new_blob
        except InvalidToken:
            print(f"\nFailed to decrypt entry {eid}")
            print("Aborting password change.")
            return
        except Exception as e:
            print(f"\nFailed to re-encrypt entry {eid}: {e}")
            print("Aborting password change.")
            return
        finally:
            plaintext = None

    # 4. Save with the new salt and new encrypted blobs
    save_vault(new_encrypted_entries, new_salt, new_key)
    print("Master password changed successfully!")
    return

def delete_corrupted_entry(encrypted_entries: dict[str, str],
    salt: bytes, key: bytes, eid: str) -> int:
    """
    -------------------------------------------------------
    Helper function to remove a single corrupted entry.

    Used when an entry cannot be decrypted (e.g. damaged file, wrong key,
    or encryption corruption) it blocks operations like master pw change. 

    Use:
        Called when user tries to edit/view a corrupted entry.
    -------------------------------------------------------
    Parameters:
        encrypted_entries - current in-memory encrypted vault (dict[str, str])
        salt              - current vault salt (bytes)
        key               - current Fernet decryption key (bytes)
        eid               - ID of the corrupted entry to delete (str)

    Returns:
        int - 0 → entry successfully deleted
              1 → user cancelled or entry not present

    -------------------------------------------------------
    Security:
        • Does NOT rotate salt or key
        • Atomic save via save_vault() — crash-safe
        • Confirmation prevents accidental deletion
    """
    print(f"\nEntry '{eid}' appears to be corrupted.")
    print("It cannot be viewed or edited.")
    confirm = input("\nDelete this entry permanently? (type 'del' to confirm): ")
    if confirm.strip().lower() == "del":
        encrypted_entries.pop(eid, None)
        save_vault(encrypted_entries, salt, key)
        print("Corrupted entry removed.")
        return 0
    else:
        print("Cancelled — corrupted entry remains.")
        return 1

def max_consecutive_chars(pw: str) -> int:
    """
    -------------------------------------------------------
    Returns the length of the longest run of identical consecutive characters
    in the given password string.

    Use:
        if max_consecutive_chars(new_pw) > 3:
            print("Too many repeated characters")

    -------------------------------------------------------
    Parameters:
        pw - password string to analyze (str)

    Returns:
        int - length of the longest sequence of the same character
    -------------------------------------------------------
    """
    max_run = 1
    current_run = 1
    
    for a, b in zip(pw, pw[1:]):
        if a == b:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    
    return max_run

def get_int(prompt: str, default=None):
    """
    -------------------------------------------------------
    Repeatedly prompts the user until a valid integer is entered.

    Allows pressing Enter to accept a default value (if provided).
    Rejects any input containing non-digit characters.

    Use:
        age = get_int("Enter age: ", default=30)
        count = get_int("How many items? ")  # no default → must type a number
    -------------------------------------------------------
    Parameters:
        prompt  - text displayed to the user (str)
        default - value returned on empty input (int | None)
                  None = no default, keep asking until valid number
    Returns:
        int - a validated integer 
              or the default value if user pressed Enter
    -------------------------------------------------------
    """
    while True:
        val = input(prompt).strip()
        if val == "" and default is not None:
            return default
        if re.fullmatch(r"\d+", val):
            return int(val)
        print("   Invalid — numbers only")

def copy_to_clipboard(text: str, timeout: int = 30) -> None:
    """
    -------------------------------------------------------
    Copies sensitive text (password) to the system clipboard
    and automatically clears it after a timeout for security.

    Starts a background daemon thread that waits `timeout` seconds,
    then attempts to wipe the clipboard and its history.

    Use:
        copy_to_clipboard(password)
        copy_to_clipboard(password, timeout=15)  # faster clear
        copy_to_clipboard(password, timeout=0)   # do not clear

    -------------------------------------------------------
    Parameters:
        text     - text to copy (str)
        timeout  - seconds before auto-clear (int)
                   0 or negative = copy only, no auto-clear

    Returns:
        None

    -------------------------------------------------------
    Behavior:
        • Uses pyperclip.copy() — works on Windows/macOS/Linux
        • Spawns a daemon thread — dies cleanly when program exits
        • Calls clear_clipboard_history() after delay
    -------------------------------------------------------
    """
    if not text:
        return

    # Copy to clipboard
    pyperclip.copy(text)
    print(f"Password copied! (auto-clears in {timeout}s)", flush=True)

    if timeout <= 0:
        return

    def auto_clear():
        time.sleep(timeout)
        try:
            pyperclip.copy("")
            clear_clipboard_history()
        except Exception:
            # prevent clipboard errors from crashing program
            pass

    threading.Thread(target=auto_clear, daemon=True).start()

    return

def clear_clipboard_history(clipboard_length: int = CLIPBOARD_LENGTH):
    """
    -------------------------------------------------------
    Aggressively wipes clipboard and clipboard history by flooding it
    with random entries. 

    Use:
        Called automatically by copy_to_clipboard() after timeout
        Called on program exit
    -------------------------------------------------------
    Parameters:
        clipboard_length - number of fake entries to generate (int)

    Returns:
        None

    -------------------------------------------------------
    Behavior:
        • Generates unique, random 40+ char strings using secrets
        • Copies each one with a short delay to bypass throttling
        • Final copy: "Clipboard history cleared"
        • Respects global WIPE_CLIPBOARD toggle

    Note:
        Disabled if WIPE_CLIPBOARD = False in config
        Best effort only - Certain clipboard managers have 
         very long histories (200 - unlimited).
    -------------------------------------------------------
    """
    import pyperclip
    # Simple overwrite on exit
    pyperclip.copy("")

    if not WIPE_CLIPBOARD:
        return
    
    import secrets, string, time
    
    char_set = string.ascii_letters + string.digits + "!@#$%^&*"

    for i in range(clipboard_length):
        fake_data = ''.join(secrets.choice(char_set) for _ in range(40))
        fake_data = f"[{i:03d}] {fake_data} - {secrets.token_hex(8)}"

        pyperclip.copy(fake_data)
        
        # Defeats throttling
        time.sleep(0.07)

    pyperclip.copy("Clipboard history cleared")
    return

def get_note_from_user() -> str:
    """
    -------------------------------------------------------
    Interactively prompts the user to enter a multi-line note.

    The note ends when the user presses Enter **three times in a row**.
    Pressing Enter once at the very beginning leaves the note empty.

    Use:
        Called when editing an entry's note field

    -------------------------------------------------------
    Parameters:
        None

    Returns:
        str - the complete note text with preserved line breaks
              (trailing newline stripped, empty string if no input)

    -------------------------------------------------------
    """
    print("Enter note (Enter 3x to end note or 1x to leave empty):")
    note = ""
    consecutive_empty = 0

    while True:
        line = input()
        if line == "":
            consecutive_empty += 1
            if consecutive_empty >= 3 or (consecutive_empty == 1 and note == ""):
                break
        else:
            consecutive_empty = 0
            note += line + "\n"

    return note.strip()

def random_password(length: int = PASS_DEFAULTS["length"],
    min_upper: int = PASS_DEFAULTS["min_upper"],
    min_lower: int = PASS_DEFAULTS["min_lower"],
    min_nums: int = PASS_DEFAULTS["min_digits"],
    min_syms: int = PASS_DEFAULTS["min_symbols"], 
    avoid_ambig = PASS_DEFAULTS["avoid_ambiguous"]) -> str:
    """
    -------------------------------------------------------
    Generates a strong, cryptographically secure random password
    that meets configurable complexity requirements.

    Use:
        pw = random_password()                     # system defaults
        pw = random_password(length=20, min_syms=4) # custom

    -------------------------------------------------------
    Parameters:
        length      - total password length (int)
        min_upper   - minimum uppercase letters (int)
        min_lower   - minimum lowercase letters (int)
        min_nums    - minimum digits (int)
        min_syms    - minimum symbols (int)
        avoid_ambig - if True, 
                    removes easily confused chars (l, I, 1, O, 0 etc.)

    Returns:
        str - generated password meeting all requirements

    -------------------------------------------------------
    Security features:
        • Cryptographically secure via secrets module
        • Enforces minimum character class requirements
        • Optional exclusion of ambiguous characters
        • Reshuffles if too many consecutive identical chars
        • No predictable patterns — shuffled randomly

    Raises:
        ValueError - if length is too short to satisfy minimum requirements

    Example:
        random_password(length=16) → "K7$mPx!vN9qL2wE8"
    -------------------------------------------------------
    """
    if length < (min_upper + min_lower + min_nums + min_syms):
        raise ValueError(
        f"Password length {length} is too short!\n"
        f"  Need at least {min_upper + min_lower + min_nums + min_syms} characters "
        f"for your requirements:\n"
        f"  • {min_upper} uppercase\n"
        f"  • {min_lower} lowercase\n"
        f"  • {min_nums} numbers\n"
        f"  • {min_syms} symbols"
    )

    # Define character pools
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    nums  = string.digits
    syms  = PASS_DEFAULTS["symbols_pool"]

    # Remove ambiguous chars
    if avoid_ambig:
        exclude = PASS_DEFAULTS["ambiguous_chars"]
        lower = ''.join(c for c in lower if c not in exclude)
        upper = ''.join(c for c in upper if c not in exclude)
        nums  = ''.join(c for c in nums  if c not in exclude)

    all_chars = lower + upper + nums + syms

    # Step 1: Guarantee minimums
    password = []
    password.extend(secrets.choice(upper) for _ in range(min_upper))
    password.extend(secrets.choice(lower) for _ in range(min_lower))
    password.extend(secrets.choice(nums)  for _ in range(min_nums))
    password.extend(secrets.choice(syms)  for _ in range(min_syms))

    # Step 2: Fill the rest randomly
    remaining = length - len(password)
    password.extend(secrets.choice(all_chars) for _ in range(remaining))

    # Step 3: Shuffle all the characters 
    secrets.SystemRandom().shuffle(password)
    pw = ''.join(password)

    # Step 4: Ensure no excessive consecutive identical chars, reshuffle if needed
    while max_consecutive_chars(pw) > PASS_DEFAULTS["max_consecutive"]:
        secrets.SystemRandom().shuffle(password)
        pw = ''.join(password)

    return pw

def ask_password(prompt: str = "Password:") -> str:
    """
    Asks user for password with three easy options:
      [Enter]     → type your own (min 8 chars)
      g           → generate strong random one
      c           → generate custom password
    """
    while True:
        print(f"\n{prompt}:")
        print("  • Type 'g' → generate strong 20-char password")
        print("  • Type 'c' → generate customizable random password")
        print("  • Press Enter to type your own")
        choice = input(" → ").strip().lower()

        if choice == "":
            pw = getpass.getpass(
                f"Enter password (min length = {PASS_DEFAULTS['min_length']}): "
                ).strip()
            if len(pw) < PASS_DEFAULTS["min_length"]:
                print(f"  Password too short (minimum {PASS_DEFAULTS['min_length']} characters)")
                continue
            return pw

        elif choice == "g":
            pw = random_password()
            print(f" Generated: {pw}")
            if input("\n Accept this password? (y/n): ").strip().lower() != "y":
                continue
            if input(" Copy to clipboard? (y/n): ").strip().lower() == "y":
                copy_to_clipboard(pw, timeout=CLIPBOARD_TIMEOUT)
            return pw

        elif choice == "c":
            pw_len = get_int(
                f"\n  Enter desired length (minimum {PASS_DEFAULTS['min_length']}, "
                f"Enter for default of {PASS_DEFAULTS['length']}): ", 
                default=PASS_DEFAULTS["length"]
                )
            if pw_len < PASS_DEFAULTS['min_length']:
                print(f"  Length too short, using {PASS_DEFAULTS['length']}.")
                pw_len = PASS_DEFAULTS['length']
            min_upper = get_int("  Minimum upper case (Enter for default): ", 
                                default=PASS_DEFAULTS["min_upper"])
            min_nums = get_int("  Minimum numbers (Enter for default): ", 
                               default=PASS_DEFAULTS["min_digits"])
            min_syms = get_int("  Minimum symbols (Enter for default): ", 
                               default=PASS_DEFAULTS["min_symbols"])

            try:
                pw = random_password(length = pw_len,
                                      min_upper = min_upper,
                                        min_nums = min_nums,
                                          min_syms = min_syms)
            except ValueError as e:
                print (f"\n  {e}")
                continue

            print(f"\n Generated: {pw}")
            if input("\n Accept this password? (y/n): ").strip().lower() != "y":
                continue
            if input(" Copy to clipboard? (y/n): ").strip().lower() == "y":
                copy_to_clipboard(pw, timeout=CLIPBOARD_TIMEOUT)
            return pw
        else:
            print("Invalid — press Enter, 'g', or 's'")


def export_json(filepath, key, encrypted_entries, salt):
    """
    Function to export the entire vault to a JSON file in decrypted form.
    Entries are sorted by site and account.
    """

    try:
        # Temporary list to hold decrypted entries
        decrypted_items = []

        # Decrypt each entry first
        for eid, blob in encrypted_entries.items():
            try:
                decrypted_json = decrypt(blob, key)
                data = json.loads(decrypted_json)
                # store tuple (eid, data) for sorting later
                decrypted_items.append((eid, data))

            except Exception as ex:
                print(f"Failed to decrypt entry {eid}: {ex}")

        # Sort entries by site then account (case-insensitive)
        decrypted_items.sort(
            key=lambda item: (
                item[1].get("site", "").lower(),
                item[1].get("account", "").lower()
            )
        )

        # Build final vault structure
        vault = {
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "canary": encrypt(KEY_CHECK_STRING, key),
            "date_exported": pendulum.now().in_timezone('local').format(DT_FORMAT),
            "entries": {}
        }

        # Write sorted entries into the dict
        for eid, data in decrypted_items:
            vault["entries"][eid] = data

        # Save to file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=4)

        print("Vault exported successfully.")

    except Exception as e:
        print(f"Failed to export vault: {e}")

    finally:
        decrypted_items = []
        data = None

    return

def import_exported_json(filepath, encrypted_entries, key, salt):
    """
    Function to import entries from an exported JSON file into the vault.
    """
    try:
        # Load JSON file
        with open(filepath, "r", encoding="utf-8") as f:
            vault = json.load(f)

        imported_count = 0

        # Loop plaintext entries
        for old_eid, entry_obj in vault.get("entries", {}).items():

            # Convert entry dict -> JSON plaintext string
            plaintext_json = json.dumps(entry_obj)

            # Encrypt with *current* master key
            encrypted_blob = encrypt(plaintext_json, key)

            # Generate a new unique ID
            new_eid = secrets.token_hex(4)
            while new_eid in encrypted_entries:
                new_eid = secrets.token_hex(4)

            # Append into current vault
            encrypted_entries[new_eid] = encrypted_blob
            imported_count += 1
        save_vault(encrypted_entries,salt,key)
        print(f"Imported {imported_count} entries from JSON.")
        return True

    except Exception as e:
        print(f"Failed to import exported JSON: {e}")
        return False
    finally:
        vault = None
        entry_obj = None
    
def import_csv(filepath, encrypted_entries, key, salt):
    """
    Function to import entries from a CSV file into the vault.
    Used to migrate from other password managers.
    """

    import csv
    with open(filepath, "r", encoding="utf-8") as f:
        delimiter = ','
        print (f"Importing from CSV... Delimiter = '{delimiter}'")
        reader = csv.DictReader(f, delimiter=delimiter)

        # Ensure CSV contains required columns
        required = {"site", "account", "password", "note"}
        if not required.issubset(reader.fieldnames):
            raise ValueError("CSV must contain: site, account, password, note")

        imported_count = 0

        for row in reader:
            # Clean values
            site = row.get("site", "") or ""
            account = row.get("account", "") or ""
            password = row.get("password", "") or ""
            note = row.get("note", "") or ""

            # Build plaintext entry object
            entry_obj = {
                "site": site.strip(),
                "account": account.strip(),
                "password": password.strip(),
                "note": note.strip(),
                "created_date": pendulum.now().to_iso8601_string(),
                "edited_date": pendulum.now().to_iso8601_string()
            }

            plaintext = json.dumps(entry_obj)

            # Encrypt using master key
            encrypted_blob = encrypt(plaintext, key)

            # Generate unique entry ID
            eid = secrets.token_hex(4)   # 8 hex chars
            while eid in encrypted_entries:
                eid = secrets.token_hex(4)

            # Save into vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1
    save_vault(encrypted_entries,salt,key)
    print(f"Imported {imported_count} entries from CSV.")
    return True



# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────
def main():
    print("- Ultimate Password Manager —\n")
    master_pw = getpass.getpass("Master password: ").strip()
    key, encrypted_entries, salt = load_vault(master_pw)
    # clears clipboard on exit
    atexit.register(clear_clipboard_history)

    while True:
        print("\n1. Add   2. Get   3. Edit   4. List Sites   5. Search  6. Change Master PW   7. Quit")
        choice = input("> ").strip()

        # ── ADD ENTRY ─────────────────────────────────────
        if choice == "1":
            # Get info
            site = input("Site (required): ").strip()
            if not site:
                print("Site name cannot be empty!")
                continue
            account = input("Account: ").strip()

            note = get_note_from_user()

            password = ask_password("New password")

            created_date = pendulum.now().to_iso8601_string()

            # create the blob
            entry = json.dumps({"site": site,
                                "account": account,
                                "password": password,
                                "note": note,
                                "created_date": created_date,
                                "edited_date": created_date,
                                "password_history": []}, separators=(',', ':'),
                                )
            
            encrypted_blob = encrypt(entry, key)
            entry = None
            entry_id = str(uuid.uuid4())[:8]

            encrypted_entries[entry_id] = encrypted_blob
            save_vault(encrypted_entries, salt, key)
            print(f"Saved → ID: {entry_id}")

        # ── GET ENTRY ───────────────────────────────────────
        elif choice == "2":
            eid = input("Enter ID: ").strip().lower()

            res = display_entry(encrypted_entries, key, eid)
            if res != 0:
                continue

            password_shown = False
            history_shown = False

            while True:
                if not password_shown and not history_shown:
                    action = "(C)opy password  (S)how password (H)istory  (Enter) skip"
                elif history_shown and not password_shown:
                    action = "(C)opy password  (S)how password (Enter) continue"
                elif password_shown and not history_shown:
                    action = "(C)opy password  (H)istory (Enter) continue"
                else:
                    action = "(C)opy password  (Enter) continue"

                print(f"{action}\n", end="> ", flush=True)
                choice_2 = input().strip().lower()

                if choice_2 == "c":
                    entry_data = get_entry_data(encrypted_entries, key, eid)
                    pw = entry_data.get("password", "") if entry_data else ""
                    copy_to_clipboard(pw, timeout=CLIPBOARD_TIMEOUT)
                    pw = None
                    entry_data = None
                    break

                elif choice_2 == "s" and not password_shown:
                    res = display_entry(encrypted_entries,
                        key,
                        eid,
                        show_pass=True,
                        show_history=False
                    )
                    if res != 0:
                        continue
                    password_shown = True

                elif choice_2 == "h" and not history_shown:
                    res = display_entry(
                        encrypted_entries,
                        key,
                        eid,
                        show_pass=False,
                        show_history=True
                    )
                    if res != 0:
                        continue
                    history_shown = True

                elif choice_2 in {"", "enter", "q"}:
                    break

                else:
                    print("\rInvalid — use C, S, H or Enter", flush=True)
                    time.sleep(0.5)
        
        # ── EDIT ENTRY ───────────────────────────────────────
        elif choice == "3":
            eid = input("Enter ID: ").strip().lower()
            update_entry(encrypted_entries, key, salt, eid)

        # ── LIST SITES ─────────────────────────────────────────
        elif choice == "4":
            list_entries(encrypted_entries, key)

        # ── SEARCH ─────────────────────────────────────────────
        elif choice == "5":
            query = input("Enter search term: ").strip().lower()
            list_entries(encrypted_entries, key, query)

        # ── CHANGE MASTER PW ───────────────────────────────────
        elif choice == "6":
            change_master_password()

        # ── QUIT ───────────────────────────────────────────────
        elif choice == "7":
            print("Goodbye!")
            sys.exit(0)

        # in development
        elif choice == "export_json":
            timestamp = pendulum.now().format('YYYY_MM_DD_HH_mm_ss')
            export_json(f"vault_export_{timestamp}.json", key,encrypted_entries,salt)
        elif choice == "import_csv":
            filename = input("Enter CSV filename to import: ").strip()
            import_csv(f"{filename}.csv", encrypted_entries, key, salt)
        elif choice == "import_json":
            filename = input("Enter JSON filename to import: ").strip()
            import_exported_json(f"{filename}.json", encrypted_entries, key, salt)


if __name__ == "__main__":
    main()