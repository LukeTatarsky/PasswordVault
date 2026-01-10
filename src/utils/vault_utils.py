import os
import json
import time
import logging
import sys
import secrets
import getpass
import gc
import base64
import pendulum
from typing import Dict, Any, Tuple
from cryptography.exceptions import InvalidTag

from config.config_vault import *
from .crypto_utils import encrypt, decrypt, derive_root_key, derive_key, decrypt_entry, encrypt_entry
from .tpm_utils import create_tpm_key, tpm_decrypt, tpm_encrypt
from .Entry import Entry, print_bytearray, bytes_to_str, str_to_bytes

logger = logging.getLogger(__name__)

# globals
vault_salt = b''
sealed_pepper = b''
canary_id = '' # str
tpm_enabled = True

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
    global vault_salt, sealed_pepper, canary_id, tpm_enabled

    print("\n Would you like to enable TPM protection? \n (Vault becomes bound to this device.)")
    choice = input(" (y/n): ").strip()

    # Build the vault
    vault_salt = secrets.token_bytes(SALT_LEN)
    canary_id = bytes_to_str(secrets.token_bytes(EID_LEN))
    vault = {
            "vault_version": VERSION,
            "argon_params": {"time": ARGON_TIME,"lanes":ARGON_PARALLELISM, "memory":ARGON_MEMORY},
            "salt": base64.urlsafe_b64encode(vault_salt).decode(),
            "canary_id": canary_id,
            "entries": {}
        }

    # Get a master password from user and derive the key used for encryption.
    master_pw = getpass.getpass("Master password: ").encode(UTF8)
    confirm_pw = getpass.getpass("Confirm master password: ").encode(UTF8)
    if master_pw != confirm_pw:
        print("Passwords do not match.")
        sys.exit(0)
    del confirm_pw

    root_key = derive_root_key(master_pw, vault_salt)
    del master_pw

    # Create portable mode vault
    if choice == "n":
        # Get a key using only the master password
        vault_key = derive_key(root_key, salt = vault_salt)
        del root_key
        # Set tpm flag
        tpm_enabled = False

        # Add the encrypted canary
        vault["canary"] = encrypt(KEY_CHECK_STRING, vault_key, canary_id)

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
            sys.exit(0)

        tpm_enabled = True
        vault_key = derive_key(root_key, salt = pepper)
        del pepper

        # Add the encrypted canary and sealed pepper
        vault["canary"] = encrypt(KEY_CHECK_STRING, vault_key, canary_id)
        
    
    else:
        print("Invalid choice. Please enter 'y' or 'n'.")
        sys.exit(0)

    # Sanity check before writing the file
    if "canary" not in vault:
        print("Vault creation failed.")
        sys.exit(0)

    # Save the vault to disk
    with VAULT_FILE.open("w", encoding=UTF8) as f:
        json.dump(vault, f, indent=2)

    # Save the global
    sealed_pepper = vault["sealed_pepper"] if choice == "y" else b''

    return vault_key, {}, vault_salt

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
            - Derived vault key.
            - Dictionary of encrypted vault entries.
            - Salt used for key derivation.

    Raises:
        SystemExit: If the vault is corrupted, unreadable, or the master
            password verification fails.
    """
    global vault_salt, canary_id, sealed_pepper, tpm_enabled
    # ==============================================================
    # 1. Create new vault if none exists
    # ==============================================================
    if not VAULT_FILE.exists():
        print("\n No Vault found. Creating new vault.")
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
        sys.exit(0)

    # Extract stored salt
    try:
        vault_salt = base64.urlsafe_b64decode(vault["salt"])

    except Exception as e:
        msg = f"Vault is corrupted: missing or invalid salt! \n {e}"
        print(msg)
        time.sleep(1)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(0)

    # During vault export, master password is provided
    if master_pw is None:
        # Prompt user for password
        master_pw = getpass.getpass("Master password: ").encode(UTF8)

    root_key = derive_root_key(master_pw, vault_salt)
    del master_pw

    # If vault is saved with TPM mode
    if "sealed_pepper" in vault:
        # Extract and decrypt the sealed pepper
        try:
            sealed_pepper = str_to_bytes(vault["sealed_pepper"])
            pepper = tpm_decrypt(sealed_pepper)
            vault_key = derive_key(root_key, salt = pepper)
            del root_key
            tpm_enabled = True
        except Exception as e:
            msg = f"Error: error occured while decrpyting sealed pepper. \n{e}"
            print(msg)
            time.sleep(1)
            now = pendulum.now().to_iso8601_string()
            logger.error(f"[{now}] {msg}\n")
            sys.exit(0)

    # Vault is saved in Portable Mode
    else:
        tpm_enabled = False
        vault_key = derive_key(root_key, salt = vault_salt)
        del root_key

    # ==============================================================
    # 3. Verify master password using the canary
    # ==============================================================
    if "canary" not in vault or "canary_id" not in vault:
        msg = "Vault corrupted: missing canary!"
        print(msg)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(0)

    try:
        canary_id = vault["canary_id"]
        decrypted_canary = decrypt(vault["canary"], vault_key, canary_id)

        if decrypted_canary != KEY_CHECK_STRING:
            msg = "Wrong master password!"
            print(msg)
            now = pendulum.now().to_iso8601_string()
            logger.error(f"[{now}] {msg}\n")
            time.sleep(2)
            sys.exit(0)

    except InvalidTag:
        msg = "Wrong master password or vault is corrupted!"
        print(msg)
        time.sleep(2)
        now = pendulum.now().to_iso8601_string()
        logger.error(f"[{now}] {msg}\n")
        sys.exit(0)

    # ==============================================================
    # 4. Return entries container
    # ==============================================================
    encrypted_entries: Dict[str, str] = vault.get("entries", {})

    print("Vault unlocked successfully.")
    return vault_key, encrypted_entries, vault_salt

def save_vault(encrypted_entries: dict[str, str], vault_key: bytes) -> None:
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
        "argon_params": {"time": ARGON_TIME,"lanes":ARGON_PARALLELISM, "memory":ARGON_MEMORY},
        "salt": base64.urlsafe_b64encode(vault_salt).decode("ascii"),
        "canary_id": canary_id,
        "canary": encrypt(KEY_CHECK_STRING, vault_key, canary_id)
    }
    if sealed_pepper:
        if isinstance(sealed_pepper, bytes):
            vault["sealed_pepper"] = bytes_to_str(sealed_pepper)
        else:
            vault["sealed_pepper"] = sealed_pepper
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

def list_entries(encrypted_entries: dict[str, str], vault_key: bytes,
                  query: str = '') -> list[str]:
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
            entry_key = derive_key(vault_key, info = str_to_bytes(eid))
            entry = decrypt_entry(str_to_bytes(blob), entry_key, eid)

            if entry is None:
                display_data[eid] = ("corrupted", "entry")
                continue

            # Build searchable text
            searchable_str = " ".join([entry.site, entry.account, entry.note]).lower()
            
            # Filter if searching
            if query:
                # Keep entry only if ALL words appear somewhere
                if not all(term in searchable_str for term in terms):
                    continue
    
            display_data[eid] = (entry.site, entry.account)
            del searchable_str
            del entry

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
        key=lambda e: (e[1][0].lower(), e[1][1].lower())
    )
    del display_data

    print(SEP_SM)
    print(f" {'Entry':>5}   → {'Site':^{SITE_LEN}}  {'Account':^{ACCOUNT_LEN}}")
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

def display_entry(e: Entry, entry_key: bytes, *,
    show_pass: bool = False, 
    show_pw_hist: bool = False, 
    show_all: bool = False) -> None: 
    """
    Display a vault entry in a readable format.

    Output can optionally reveal passwords, password history, or
    additional sensitive fields.

    Args:
        entry: Decrypted entry
        show_pass: If True, reveal the plaintext password.
        show_history: If True, display password history.
        show_all: If True, display all available fields.

    Side Effects:
        Prints formatted entry data to stdout.
    """

    print(f"\n{SEP_LG}")
    print(f"Site         : {e.site}")

    # === Account ==========================================================
    if e.account:
        print(f"Account      : {e.account}")

    # === Password (masked or revealed) ====================================
    if e.field_exists("password"):
        if show_pass or show_all:
            print("Password     :", end=" ", flush=True)
            with e.get_password(entry_key) as pw:
                    print_bytearray(pw)
        else:
            print(f"Password     : {'*' * PASS_DEFAULTS["length"]}")

    # === Password History (only if requested and exists) ==================
    if show_pw_hist or show_all: 
        if e.pw_hist:
            print(f"Pass History : ")
            print(f" - Last Used :")
            for pw_entry in e.pw_hist:
                print(f" - {pendulum.from_format(pw_entry[0], DT_FORMAT_PASS_HISTORY)
                            .in_timezone('local').format(DT_FORMAT_PASS_HISTORY)} :", # type: ignore
                    f" {pw_entry[1]}")
                del pw_entry
            print(SEP_SM)

    # === Note =============================================================
    if e.note:
        print("Note      :")
        print(f"{SEP_SM}\n{e.note}\n{SEP_SM}")

    # === Recovery Keys =====================================================
    if show_all and e.field_exists("rec_keys"):
        print("Keys      :")
        print(f"{SEP_SM}")
        with e.get_rec_keys(entry_key) as rec_key:
            print_bytearray(rec_key)
        print(f"{SEP_SM}")
    elif e.field_exists("rec_keys"):
            print(f"Keys         : {"*" * 10}")

    # === TOTP Key ==========================================================
    if show_all and e.field_exists("totp"):
        print(f"TOTP         : **protected**")

    # === Timestamps =======================================================
    print(f"Created      : {pendulum.parse(e.created).in_timezone('local').format(DT_FORMAT)}") # type: ignore
    print(f"Last Edited  : {pendulum.parse(e.edited).in_timezone('local').format(DT_FORMAT)}") # type: ignore
    print(SEP_LG)
    return

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
    global vault_salt, canary_id, sealed_pepper
    print("\n=== Change Master Password ===")

    old_pw = getpass.getpass("Current master password: ").encode(UTF8)
    # Try to load with the old password (this also verifies it)
    try:
        old_vault_key, temp_entries, _ = load_vault(old_pw)
    except SystemExit:
        sys.exit(0)
    finally:
        del old_pw
        
    try:
        print()
        new_pw = getpass.getpass("Enter new master password: ").encode(UTF8)
        confirm = getpass.getpass("Confirm new master password: ").encode(UTF8)
        if new_pw != confirm:
            print("New passwords do not match!")
            return
        if not new_pw:
            print("Master password cannot be empty!")
            return
        
        print("\nCurrent password verified. Re-encrypting all entries...")

        # Derive a new salt and key from the new password
        vault_salt = secrets.token_bytes(SALT_LEN)

        # Derive new root and vault key
        root_key = derive_root_key(new_pw, vault_salt)
        del new_pw

        if tpm_enabled:
            new_pepper = secrets.token_bytes(SALT_LEN)
            sealed_pepper = tpm_encrypt(new_pepper)
            new_vault_key = derive_key(root_key, salt = new_pepper)
            del new_pepper
        else:
            new_vault_key = derive_key(root_key, salt = vault_salt)
        
        # Generate a new canary ID
        canary_id = bytes_to_str(secrets.token_bytes(EID_LEN))

        # Decrypt and re-encrypt every entry with the new key
        new_encrypted_entries: Dict[str, str] = {}
        for eid, old_blob in temp_entries.items():
            try:
                # Decrypt with old key
                old_entry_key = derive_key(old_vault_key, info=str_to_bytes(eid))
                entry = decrypt_entry(str_to_bytes(old_blob), old_entry_key, eid)
                del old_entry_key

                # Encrypt again with new key
                new_entry_key = derive_key(new_vault_key, info=str_to_bytes(eid))
                new_blob = encrypt_entry(entry, new_entry_key)
                del entry, new_entry_key
                new_encrypted_entries[eid] = bytes_to_str(new_blob)

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
        save_vault(new_encrypted_entries, new_vault_key)
        print("Master password changed successfully!")

    except Exception as e:
        print (f"Error: {e}")
        logger.error(f"[{pendulum.now().to_iso8601_string()}] Error while changing password. {e}")
    finally:
        gc.collect()
        print("Exiting...")
        time.sleep(2)
        sys.exit(0)
    return


