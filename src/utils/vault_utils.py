import os
import json
import time
import logging
import sys
import secrets
import getpass
import gc

import pendulum
from typing import Dict, Any, Tuple
from cryptography.exceptions import InvalidTag

from config.config_vault import *
from .crypto_utils import *
from .tpm_utils import create_tpm_key, tpm_decrypt, tpm_encrypt

logger = logging.getLogger(__name__)

# globals
salt = b''
sealed_pepper = b''
canary_id = '' # str


def create_vault() -> Tuple[bytes, Dict[str, str], bytes]:
    """
    Create a new encrypted password vault.

    Prompts the user to choose to use TPM-protected mode,
    derives a master key from the user's password, initializes a canary value,
    and writes the new vault to disk.

    In TPM mode, a random pepper is generated, sealed using the TPM, and later
    combined with the master password during key derivation. The initialized
    vault is written to disk before returning.

    Returns:
        A tuple containing:
            - Derived encryption key.
            - Empty dictionary for encrypted vault entries.
            - Salt used for key derivation.

    Raises:
        SystemExit: If TPM pepper sealing fails.
    """
    global salt, sealed_pepper, canary_id

    print ("\n Would you like to enable TPM protection? (Vault becomes bound to this device.)")
    choice = input(" (y/n): ").strip()

    # Build the vault
    salt = secrets.token_bytes(SALT_LEN)
    canary_id = bytes_to_str(secrets.token_bytes(EID_LEN))
    vault = {
            "vault_version": VERSION,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "canary_id": canary_id,
            "entries": {}
        }

    # Get a master password from user and derive the key used for encryption.
    master_pw = getpass.getpass("Master password: ").encode(UTF8)
    confirm_pw = getpass.getpass("Confirm master password: ").encode(UTF8)
    if master_pw != confirm_pw:
        print("Passwords do not match.")
        sys.exit(1)
    del confirm_pw

    # Create portable mode vault
    if choice == "n":
        # Get a key using only the master password
        key = derive_key(master_pw, salt)
        del master_pw

        # Add the encrypted canary
        vault["canary"] = encrypt(KEY_CHECK_STRING, key, canary_id)

    # Create TPM enabled vault
    elif choice == "y":
        # Try to create the TPM key. Required on first run. 
        # If it has been created before, failure is expected.
        # True errors will be caught by tpm_encrypt()
        try:
            create_tpm_key()
        except Exception:
            pass

        # Try to encrypt the pepper, this will access the TPM key.
        # If it fails, then most likely the key was unable to be created above.
        try:
            pepper = secrets.token_bytes(SALT_LEN)
            vault["sealed_pepper"] = bytes_to_str(tpm_encrypt(pepper))
        except Exception as e:
            msg = f"Error accessing TPM key. Could not create TPM vault. {e}"
            print(msg)
            now = pendulum.now().to_iso8601_string()
            logger.error(f"[{now}] {msg}\n")
            time.sleep(2)
            sys.exit(1)

        peppered_pw = pepper_pw(master_pw, pepper)
        del pepper, master_pw

        key = derive_key(peppered_pw, salt)

        # Add the encrypted canary and sealed pepper
        vault["canary"] = encrypt(KEY_CHECK_STRING, key, canary_id)
        
    
    else:
        print("Invalid choice. Please enter 'y' or 'n'.")
        sys.exit(1)

    # Sanity check before writing the file
    if "canary" not in vault:
        print("Vault creation failed.")
        sys.exit(1)

    # Save the vault to disk
    with VAULT_FILE.open("w", encoding=UTF8) as f:
        json.dump(vault, f, indent=2)

    # Save the global
    sealed_pepper = vault["sealed_pepper"] if choice == "y" else b''

    return key, {}, salt

def load_vault(master_pw=None) -> Tuple[bytes, Dict[str, str], bytes]:
    """
    Loads the encrypted password vault.

    If the vault file does not exist, a new vault is created and initialized.
    If the vault exists, it is loaded from disk, the stored salt is extracted,
    and a master key is derived from the provided (or prompted) master password.

    If TPM mode is enabled, a sealed pepper is decrypted using the TPM and
    combined with the master password before key derivation. The master
    password is verified by decrypting a canary value stored in the vault.
    The program exits if verification fails or the vault is corrupted.

    Args:
        master_pw: Optional master password provided by the caller. If not
            provided, the user is prompted interactively.

    Returns:
        A tuple containing:
            - Derived encryption key.
            - Dictionary of encrypted vault entries.
            - Salt used for key derivation.

    Raises:
        SystemExit: If the vault is corrupted, unreadable, or the master
            password verification fails.
    """
    global salt, canary_id, sealed_pepper
    # ==============================================================
    # 1. Create new vault if none exists
    # ==============================================================
    if not VAULT_FILE.exists():
        print ("\n No Vault found. Creating new vault.")
        return create_vault()

    # ==============================================================
    # 2. Load existing vault
    # ==============================================================
    # Open the vault file
    try:
        with VAULT_FILE.open("r", encoding=UTF8) as f:
            vault: Dict[str, Any] = json.load(f)
    except json.JSONDecodeError:
        msg = "Vault file is not valid JSON or is corrupted!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        time.sleep(2)
        sys.exit(1)

    # Extract stored salt
    try:
        salt = base64.urlsafe_b64decode(vault["salt"])

    except Exception as e:
        msg = f"Vault is corrupted: missing or invalid salt! \n {e}"
        print(msg)
        time.sleep(1)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # During vault export, master password is provided
    if master_pw is None:
        # Prompt user for password
        master_pw = getpass.getpass("Master password: ").encode(UTF8)

    # If vault is saved with TPM mode
    if "sealed_pepper" in vault:
        # Extract and decrypt the sealed pepper
        try:
            sealed_pepper = str_to_bytes(vault["sealed_pepper"])
            pepper = tpm_decrypt(sealed_pepper)

            peppered_pw = pepper_pw(master_pw, pepper)
            del master_pw, pepper
        except Exception as e:
            msg = f"Error: error occured while decrpyting sealed pepper. \n{e}"
            print(msg)
            time.sleep(1)
            now = pendulum.now().to_iso8601_string()
            logger.error(f"[{now}] {msg}\n")
            sys.exit(1)

        key = derive_key(peppered_pw, salt)
        del peppered_pw

    # Vault is saved in Portable Mode
    else:
        key = derive_key(master_pw, salt)
        del master_pw

    # ==============================================================
    # 3. Verify master password using the canary
    # ==============================================================
    if "canary" not in vault or "canary_id" not in vault:
        msg = "Vault corrupted: missing canary!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(1)

    try:
        canary_id = vault["canary_id"]
        decrypted_canary = decrypt(vault["canary"], key, canary_id)

        if decrypted_canary != KEY_CHECK_STRING:
            msg = "Wrong master password!"
            print(msg)
            now = pendulum.now().to_iso8601_string()
            logger.error(f"[{now}] {msg}\n")
            time.sleep(2)
            sys.exit(1)

    except InvalidTag:
        msg = "Wrong master password or vault is corrupted!"
        print(msg)
        time.sleep(2)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(1)

    # ==============================================================
    # 4. Return entries container
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
        key: Derived master key used for encryption.

    Side Effects:
        Atomically overwrites the vault file on disk.
        Uses global vault metadata (salt, canary_id, sealed_pepper).
    """
    vault = {
        "vault_version": VERSION,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "canary_id": canary_id,
        "canary": encrypt(KEY_CHECK_STRING, key, canary_id)
    }
    if sealed_pepper != b'':
        vault["sealed_pepper"] = bytes_to_str(sealed_pepper)
    vault["entries"] = dict(encrypted_entries)

    # Write to temporary file first.
    tmp = VAULT_FILE.with_suffix(VAULT_FILE.suffix + ".tmp")
    with open(tmp, "w", encoding=UTF8) as f:
        json.dump(vault, f, indent=2)
        f.flush()
        os.fsync(f.fileno()) # force to disk

    # Atomic replace the VAULT FILE. Then clear tmp.
    os.replace(tmp, VAULT_FILE)
    return

def list_entries(encrypted_entries: dict[str, str], key: bytes,
                  query: str = None) -> list[str]:
    """
    List vault entries with optional search filtering.

    Each entry is decrypted to extract display metadata. Entries are
    sorted alphabetically by site and then by account. Corrupted or
    undecryptable entries are handled gracefully.

    Args:
        encrypted_entries: Mapping of entry IDs to encrypted tokens.
        key: master key used for decryption.
        query: Optional case-insensitive search string. If provided,
            only entries matching all search terms are included.

    Returns:
        A list of entry IDs in the order displayed. Returns an empty
        list if no entries are found.

    Side Effects:
        Prints formatted entry listings to stdout.

    Security Notes:
        - Passwords are never displayed.
        - Decrypted data is kept in memory only briefly.
        - Corrupted entries are not decrypted and are clearly marked.
    """
    if not encrypted_entries:
        print("Empty vault — no entries yet.")
        time.sleep(0.5)
        return []
    
    # Temporary dict: eid → (site, account)
    display_data: dict[str, tuple[str, str]] = {}
    
    if query:
        query = query.lower().strip()
        terms = query.split()

    for eid, blob in encrypted_entries.items():
        try:
            data = json.loads(decrypt(blob, key, eid))
            site = data.get("site", "")
            account = data.get("account", "")
            note = data.get("note", "")
            del data

            # Build searchable text
            searchable_str = " ".join([site, account, note]).lower()
            
            # Filter if searching
            if query:
                # Keep entry only if ALL words appear somewhere
                if not all(term in searchable_str for term in terms):
                    continue
    
            display_data[eid] = (site, account)
            del searchable_str, note, account, site

        except Exception as e:
            # only show corrupted if not searching
            if not query:
                display_data[eid] = ("corrupted", "")
                logger.error(f"[{pendulum.now().to_iso8601_string()}] corrupted entry {eid}: {e}\n")

    if not display_data:
        print("  No entries found.")
        return []
    
    # Sort by site , then account
    sorted_entries = sorted(
        display_data.items(),
        key=lambda entry: (entry[1][0].lower(), entry[1][1].lower())
    )
    del display_data

    print(SEP_SM)
    print (f" {'Entry':>5}   → {'Site':^{SITE_LEN}}  {'Account':^{ACCOUNT_LEN}}")
    print(SEP_SM)

    eid_list: list[str] = []

    for i, (eid, (site, account)) in enumerate(sorted_entries):
        site = site if len(site) <= SITE_LEN else site[:SITE_LEN-3] + "..."
        account = account if len(account) <= ACCOUNT_LEN else account[:ACCOUNT_LEN-3] + "..."
        # Print starting at 1 for ease of use. Subtract 1 when calling display
        print(f"{i+1:>6}   → {site:^{SITE_LEN}}  {account:^{ACCOUNT_LEN}}")
        # Only return a list of eid's
        eid_list.append(eid)

        del site, account

    return eid_list

def get_entry_data(entries: dict[str, str], key: bytes, eid: str) -> dict[str, object]:
    """
    Retrieve and decrypt a single vault entry.

    Looks up an encrypted entry by ID, decrypts its token,
    parses the resulting JSON, and returns the decrypted data.

    If the entry cannot be found, decrypted, or parsed, an empty
    dictionary is returned and a user-facing message is printed.

    Args:
        entries: Mapping of entry IDs to encrypted tokens.
        key: Master key used for decryption.
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
        data = json.loads(decrypt(encrypted_token, key, eid))
    except KeyError:
        print("Not found.")
    except (InvalidTag, json.JSONDecodeError, UnicodeDecodeError):
        print("Entry may be corrupted, cannot view.")
        delete_corrupted_entry(entries, key, eid)
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
        key: Master key used for decryption when operating in vault mode.
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
    password = None
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
    if show_all:
        keys = data.get('keys', '')
        if show_all and keys:
            print("Keys")
            print(f"{SEP_SM}\n{keys}\n{SEP_SM}")
        elif keys:
                print(f"Keys         : {"*" * 10}")
        keys = None
        del keys

    # === TOTP Key ==========================================================
    if show_all:
        totp = data.get('totp', '')
        if totp:
            print(f"TOTP         : **protected**")
        elif totp:
            print(f"TOTP         : {"*" * 10}")
        totp = None
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
        key: Master key used for vault encryption.
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
        encrypted_entries.get(eid, None)
        save_vault(encrypted_entries, key)
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
    global salt, canary_id, sealed_pepper
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

        # Try to load with the old password (this also verifies it)
        try:
            temp_key, temp_entries, _ = load_vault(old_pw)
        except SystemExit:
            return

        print("Current password verified. Re-encrypting all entries...")

        # Derive a new salt and key from the new password
        salt = secrets.token_bytes(SALT_LEN)

        # Pepper the password with new random bits
        pepper = secrets.token_bytes(SALT_LEN)
        
        sealed_pepper = tpm_encrypt(pepper)

        peppered_pw = pepper_pw(new_pw, pepper)
        
        new_key = derive_key(peppered_pw, salt)

        # Generate a new canary ID
        canary_id = bytes_to_str(secrets.token_bytes(EID_LEN))

        # Decrypt and re-encrypt every entry with the new key
        new_encrypted_entries: Dict[str, str] = {}
        for eid, old_blob in temp_entries.items():
            try:
                # Decrypt with old key
                plaintext = decrypt(old_blob, temp_key, eid)
                # Encrypt again with new key
                new_blob = encrypt(plaintext, new_key, eid)
                del plaintext
                new_encrypted_entries[eid] = new_blob
            except InvalidTag:
                print(f"\nFailed to decrypt entry {eid}")
                print("Aborting password change.")
                logger.error(f"[{pendulum.now().to_iso8601_string()}] corrupted entry {eid}. Aborting password change")
                return
            except Exception as e:
                print(f"\nFailed to re-encrypt entry {eid}: {e}")
                print("Aborting password change.")
                logger.error(f"[{pendulum.now().to_iso8601_string()}] corrupted entry {eid}. Aborting password change")
                return
            
        # Save with the new salt and new encrypted blobs
        save_vault(new_encrypted_entries, new_key)
        print("Master password changed successfully!")
    except Exception as e:
        print (f"Error: {e}")
        logger.error(f"[{pendulum.now().to_iso8601_string()}] Error while changing password. {e}")
    finally:
        old_pw = secrets.token_bytes(len(old_pw))
        new_pw = secrets.token_bytes(len(new_pw))
        confirm = secrets.token_bytes(len(confirm))
        del old_pw, new_pw, confirm
        gc.collect()
        print("Exiting...")
        time.sleep(2)
        sys.exit(0)
    return


