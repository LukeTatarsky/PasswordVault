import os
import json
import time
import logging
import sys
import secrets
import getpass

import pendulum
from typing import Dict, Any, Tuple
from cryptography.fernet import InvalidToken

from config import *
from .crypto_utils import *
salt = b''

def load_vault(master_pw: str) -> Tuple[bytes, Dict[str, str], bytes]:
    """
    Load or create the encrypted password vault.

    On first run, this function creates a new vault file containing a
    randomly generated salt and an encrypted canary value used for
    later master password verification.

    On subsequent runs, the vault is loaded from disk, a key is derived
    from the provided master password and stored salt, and the password
    is verified by decrypting the canary value. The program exits if
    verification fails.

    Args:
        master_pw: Master password provided by the user.

    Returns:
        A tuple containing:
            - Derived Fernet key.
            - Dictionary of encrypted entries mapping entry IDs to tokens.
            - Salt used for key derivation.

    Raises:
        SystemExit: If the vault is corrupted or the master password is incorrect.
    """
    global salt
    # ==============================================================
    # 1. Create new vault if none exists
    # ==============================================================
    if not os.path.exists(VAULT_FILE):
        print("Creating new password vault...")
        salt = os.urandom(16)
        key = derive_key(master_pw, salt)

        vault = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "canary": encrypt(KEY_CHECK_STRING, key),
            "entries": {}
        }
        with open(VAULT_FILE, "w", encoding=UTF8) as f:
            json.dump(vault, f, indent=2)

        return key, {}, salt

    # ==============================================================
    # 2. Load existing vault
    # ==============================================================
    try:
        with open(VAULT_FILE, encoding=UTF8) as f:
            vault: Dict[str, Any] = json.load(f)
    except json.JSONDecodeError:
        msg = "Vault file is not valid JSON or is corrupted!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        time.sleep(2) 
        sys.exit(1)

    # Extract and decode stored salt
    try:
        salt = base64.urlsafe_b64decode(vault["salt"])
    except (KeyError, base64.binascii.Error):
        msg = "Vault is corrupted: missing or invalid salt!"
        print(msg)
        time.sleep(3)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # Derive key from user password + stored salt
    key = derive_key(master_pw, salt)

    # ==============================================================
    # 3. Verify master password using the canary
    # ==============================================================
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
            time.sleep(3)
            sys.exit(1)
    except InvalidToken:
        msg = "Wrong master password or vault is corrupted!"
        print(msg)
        time.sleep(3)
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # ==============================================================
    # 4. Return decrypted entries container
    # ==============================================================
    encrypted_entries: Dict[str, str] = vault.get("entries", {})

    print("Vault unlocked successfully.")
    return key, encrypted_entries, salt

def save_vault(encrypted_entries: dict[str, str], key: bytes) -> None:
    """
    Securely save the encrypted password vault to disk.

    Writes the vault data using an atomic replace operation to ensure
    data integrity. The canary value is re-encrypted on every save.

    Args:
        encrypted_entries: Mapping of entry IDs to encrypted tokens.
        key: Derived Fernet key used for encryption.
        salt: Salt used for key derivation.

    Side Effects:
        Atomically overwrites the vault file on disk.
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


def get_entry_data(entries: dict[str, str], key: bytes, eid: str) -> dict[str, object]:
    """
    Retrieve and decrypt a single vault entry.

    Looks up an encrypted entry by ID, decrypts its Fernet token,
    parses the resulting JSON, and returns the decrypted data.

    If the entry cannot be found, decrypted, or parsed, an empty
    dictionary is returned and a user-facing message is printed.

    Args:
        entries: Mapping of entry IDs to encrypted tokens.
        key: Fernet key used for decryption.
        eid: Entry ID to retrieve.

    Returns:
        Decrypted entry data as a dictionary, or an empty dictionary
        if the entry cannot be retrieved.

    Side Effects:
        Offers corrupted entry deletion when detected.
    """
    data: Dict[str, Any] = {}
    try:
        encrypted_token: str = entries[eid]
        data = json.loads(decrypt(encrypted_token, key))
    except KeyError:
        print("Not found.")
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        print("Entry may be corrupted, cannot view.")
        delete_corrupted_entry(entries, key, eid, salt)
    except Exception as e:
        print(f"Unexpected error: {e}")
    return data


def display_entry(source: Dict[str, Any], 
    key: bytes | None = None,
    eid: str | None = None,  *,
    show_pass: bool = False, 
    show_history: bool = False, 
    show_all: bool = False) -> int: 
    """
    Display a password vault entry in a human-readable format.

    Supports two modes of operation:
    1) Vault mode: decrypts and displays an entry from the encrypted vault.
    2) In-memory mode: displays an already-decrypted entry dictionary.

    Output can optionally reveal passwords, password history, or
    additional sensitive fields.

    Args:
        source: Either the encrypted vault entries dictionary or a
            decrypted entry dictionary.
        key: Fernet key used for decryption when operating in vault mode.
        eid: Entry ID to retrieve when operating in vault mode.
        show_pass: If True, reveal the plaintext password.
        show_history: If True, display password history.
        show_all: If True, display all available fields.

    Returns:
        0 if the entry is displayed successfully.
        1 if the entry is missing, corrupted, or invalid.

    Side Effects:
        Prints formatted entry data to stdout.
        Scrubs sensitive data from memory where possible.
    """

    # ==============================================================
    # 1. Decide on input type
    # ==============================================================
    if eid is not None and key is not None:
        # Mode 1: Display from encrypted vault
        data = get_entry_data(source, key, eid)
        if not data:
            return 1
    else:
        # Mode 2: Display already-decrypted in-memory dict
        data = source
        source = secrets.token_bytes(len(source))
        del source
        if not data:
            return 1

    print(f"\n{SEP_LG}")
    print(f"Site         : {data.get('site', '(missing)')}")
    # === Account ==========================================================
    account = data.get('account') or ''
    if account:
        print(f"Account      : {account}")
    account = secrets.token_bytes(len(account))
    del account

    # === Password (masked or revealed) ====================================
    password = data.get('password', '') or ''
    if show_pass or show_all:
        print(f"Password     : {password}")
    elif password:
        masked = '*' * PASS_DEFAULTS["length"]
        print(f"Password     : {masked}")
    password = secrets.token_bytes(len(password))
    del password
    # === Password History (only if requested and exists) ==================
    if show_history or show_all: 
        history = data.get('password_history', [])
        if history:
            print(f"Pass History : ")
            print(f" - Last Used :")
            for pw_entry in history:
                print(f" - {pendulum.parse(pw_entry.get('last_used','unknown date'))
                            .in_timezone('local').format(DT_FORMAT_PASS_HISTORY)} :",
                    f" {pw_entry.get('password','')}")
                pw_entry.clear()
                del pw_entry
            history.clear()
            del history
            print(SEP_SM)
    # === Note =============================================================
    note = data.get('note', '').strip()
    if note:
        print("Note")
        print(f"{SEP_SM}\n{note}\n{SEP_SM}")
        del note
    # === Recovery Keys =====================================================
    keys = data.get('keys', '')
    if show_all and keys:
        print("Keys")
        print(f"{SEP_SM}\n{keys}\n{SEP_SM}")
    elif keys:
            print(f"Keys         : {"*" * 10}")
    keys = secrets.token_bytes(len(keys))
    del keys
    # === TOTP Key ==========================================================
    totp = data.get('totp', '')
    if show_all and totp:
        print(f"TOTP         : {totp}")
    elif totp:
        print(f"TOTP         : {"*" * 10}")
    totp = secrets.token_bytes(len(totp))
    del totp
    # === Timestamps =======================================================
    try:
        created = pendulum.parse(data.get('created_date', '1970-01-01T00:00:00Z'))
        edited = pendulum.parse(data.get('edited_date', '1970-01-01T00:00:00Z'))
    except Exception:
        created = edited = pendulum.now()

    
    print(f"Created      : {created.in_timezone('local').format(DT_FORMAT)}")
    print(f"Last Edited  : {edited.in_timezone('local').format(DT_FORMAT)}")
    print(SEP_LG)
    return 0

def delete_corrupted_entry(encrypted_entries: dict[str, str],
                            key: bytes, eid: str) -> int:
    """
    Remove a corrupted vault entry after user confirmation.

    This helper is invoked when an entry cannot be decrypted or parsed.
    Corrupted entries block certain operations (such as master password
    changes) and may be safely removed after confirmation.

    Args:
        encrypted_entries: Current in-memory encrypted vault entries.
        key: Fernet key used for vault encryption.
        eid: ID of the corrupted entry to remove.

    Returns:
        0 if the entry was successfully deleted.
        1 if the user cancelled or the entry was not present.

    Security Notes:
        - Does not rotate the salt or master key.
        - Vault is saved atomically to prevent data loss.
        - Explicit confirmation prevents accidental deletion.
    """
    print(f"\nEntry '{eid}' appears to be corrupted.")
    print("It cannot be viewed or edited.")
    confirm = input("\nDelete this entry permanently? (type 'del' to confirm): ")
    if confirm.strip().lower() == "del":
        encrypted_entries.pop(eid, None)
        save_vault(encrypted_entries, key, salt)
        print("Corrupted entry removed.")
        return 0
    else:
        print("Cancelled — corrupted entry remains.")
        return 1
    
def change_master_password() -> None:
    """
    Change the master password for the vault.

    Performs a full master password rotation by verifying the current
    password, deriving a new encryption key with a new salt, decrypting
    all entries, and re-encrypting them with the new key. The operation
    aborts immediately if any entry fails to decrypt.

    Returns:
        None

    Side Effects:
        Prompts for passwords via stdin.
        Rewrites the vault file with new encryption parameters.
        Exits the program upon completion.

    Security Notes:
        - Current password must be verified before changes occur.
        - A new random salt is generated.
        - All entries are fully re-encrypted atomically.
        - Empty passwords are rejected.
        - Sensitive password material is wiped from memory when possible.
    """
    global salt
    print("\n=== Change Master Password ===")

    old_pw = getpass.getpass("Current master password: ").encode(UTF8)
    new_pw = getpass.getpass("Enter New master password: ").encode(UTF8)
    confirm = getpass.getpass("Confirm new master password: ").encode(UTF8)
    try:
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
            return

        print("Current password verified. Re-encrypting all entries...")

        # 2. Derive a new salt and key from the new password
        salt = os.urandom(16)
        new_key = derive_key(new_pw, salt)

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
        save_vault(new_encrypted_entries, new_key)
        print("Master password changed successfully!")
    except Exception as e:
        print (f"Error: {e}")
        logging.error(f"Error while changing password. {e}")
    finally:
        old_pw = secrets.token_bytes(len(old_pw))
        new_pw = secrets.token_bytes(len(new_pw))
        confirm = secrets.token_bytes(len(confirm))
        del old_pw, new_pw, confirm
        print("Exiting...")
        time.sleep(2)
        sys.exit(0)
    return