import secrets
import getpass
import csv
import logging

from config.config_vault import *
from .crypto_utils import *
from .vault_utils import *

logger = logging.getLogger(__name__)
"""
Under development
"""

def export_portable():
    """
    Export the vault to a portable (non-TPM) format.

    Verifies the master password, prompts to use a new password,
    decrypts all entries, and re-encrypts them using a new salt 
    and key without TPM protection. The exported vault is
    written to a new file on disk.

    Returns:
        True if the vault was exported successfully.

    Raises:
        SystemExit: If the master password verification fails.
    """
    try:
        # Verify master password
        master_pw = getpass.getpass("Confirm master password: ").encode(UTF8)
        
        try:
            temp_key, temp_entries, _ = load_vault(master_pw)
        except:
            # Lock if wrong password entered
            print("Incorrect password. Exiting.")
            return False

        print(" Current password verified.")

        # Ask if user wants to use a different password
        c = input("\n Would you like to use a different password for this export? (y/n): ").strip()
        if c == "y":
            # Get new password 
            master_pw = getpass.getpass("Enter new master password: ").encode(UTF8)
            confirm_pw = getpass.getpass("Confirm new master password: ").encode(UTF8)
            if master_pw != confirm_pw:
                print (" New passwords did not match. Returning to main menu.")
                return False
        print(" Re-encrypting all entries...")

        # Derive a new key
        new_salt = secrets.token_bytes(SALT_LEN)

        new_key = derive_key(master_pw, new_salt)
        master_pw = secrets.token_bytes(len(master_pw))
        del master_pw

        # Generate a new canary ID
        new_canary_id = bytes_to_str(secrets.token_bytes(EID_LEN))

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
            except InvalidTag as e:
                msg = f"Failed to decrypt entry {eid}: {e}"
                print(msg)
                logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")

            except Exception as e:
                msg = f"Failed to re-encrypt entry {eid}: {e}"
                print(msg)
                logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
        
        
        # Save with the new salt and new encrypted blobs
        vault = {
            "date_exported": pendulum.now().in_timezone('local').format(DT_FORMAT),
            "vault_version": VERSION,
            "salt": base64.urlsafe_b64encode(new_salt).decode("ascii"),
            "canary_id": new_canary_id,
            "canary": encrypt(KEY_CHECK_STRING, new_key, new_canary_id),
            "entries": new_encrypted_entries
        }

        del new_key

        # Save to file
        timestamp = pendulum.now().format(DT_FORMAT_EXPORT)
        file_name = f"password_vault_portable_{timestamp}.json"


        with open(EXPORT_DIR / file_name, "w") as f:
            json.dump(vault, f, indent=2)
            f.flush()
            os.fsync(f.fileno()) # force to disk

        missing = len(temp_entries) - len(new_encrypted_entries)
        if missing:
            msg = f"Vault export failed: missing {missing} entries."
            print(msg)
            logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
            return False

        print("Vault exported successfully!")
        
    except Exception as e:
        print (f"Error: {e}")
        logger.error(f"Error occured while exporting vault:\n {e}")
        return False
    
    return True
    
    
def export_json():
    """
    Export the vault to a decrypted JSON file.

    Verifies the master password, decrypts all vault entries, and writes them
    to a plaintext JSON file sorted for readability.

    Returns:
        True if entries were imported successfully.

    Raises:
        SystemExit: If master password verification fails.
    """
    print("\nWARNING: This will export ALL passwords and data in plain text!!!\n")

    # Verify master password
    master_pw = getpass.getpass("Confirm master password: ").encode(UTF8)
    
    try:
        key, encrypted_entries, _ = load_vault(master_pw)
    except:
        # Lock if wrong password entered
        print("Incorrect password. Exiting.")
        return False

    print("Current password verified. Re-encrypting all entries...")

    try:
        # Temporary list to hold decrypted entries
        decrypted_items = []

        # Decrypt each entry first
        for eid, blob in encrypted_entries.items():
            try:
                decrypted_json = decrypt(blob, key, eid)
                data = json.loads(decrypted_json)
                # store tuple (eid, data) for sorting later
                decrypted_items.append((eid, data))

            except Exception as e:
                print(f"Failed to decrypt entry {eid}: {e}")

        # Sort entries by site then account (case-insensitive)
        decrypted_items.sort(
            key=lambda item: (
                item[1].get("site", "").lower(),
                item[1].get("account", "").lower()
            )
        )

        # Build final vault structure
        vault = {
            "date_exported": pendulum.now().in_timezone('local').format(DT_FORMAT),
            "entries": {}
        }

        # Define json order.
        json_order = ["site", "account", "password", "note", "totp", "created_date", "edited_date"]

        # Write sorted entries into the dict
        for eid, data in decrypted_items:

            # Force same order for all entries
            ordered_entry = {k: data[k] for k in json_order if k in data}

            # Order doesnt matter for remaining keys
            for k, v in data.items():
                if k not in json_order:
                    ordered_entry[k] = v

            vault["entries"][eid] = ordered_entry
            del data

        
        # Save to file
        timestamp = pendulum.now().format(DT_FORMAT_EXPORT)
        file_name = f"password_vault_export_{timestamp}.json"

        
        with open(EXPORT_DIR / file_name, "w", encoding=UTF8) as f:
            json.dump(vault, f, indent=2)
            f.flush()
            os.fsync(f.fileno()) # force to disk

        # Error / Success message 
        if len(decrypted_items) != len(encrypted_entries):
            print (" Error Exporting all entries. Check for corrupted entries.")
        else:
            print (" Vault exported successfully.")

    except Exception as e:
        print(f"Failed to export vault: {e}")
        return False

    finally:
        decrypted_items = []

    return True

def import_json(filepath, encrypted_entries, key):
    """
    Import entries from a previously exported plaintext JSON file.

    Reads a JSON file created by `export_json`, encrypts each entry using the
    current master key, assigns new unique entry IDs, and appends them to the
    active vault.

    Args:
        filepath: Path to the exported JSON file.
        encrypted_entries: In-memory encrypted vault entries.
        key: Active master key.

    Returns:
        True if entries were imported successfully, False otherwise.

    Side Effects:
        - Modifies the in-memory vault entries.
        - Persists changes to disk using `save_vault()`.
    """
    try:
        # Load JSON file
        with open(IMPORT_DIR / filepath, "r", encoding=UTF8) as f:
            vault = json.load(f)

        # Perform intersection of cannot exist and vault keys, as sets.
        #  If any of them are there, its not a plain text vault
        cannot_exist = {"salt", "canary", "canary_id", "sealed_pepper"}
        if cannot_exist & vault.keys():
            print("Error: this is an encrypted vault")
            return False

        imported_count = 0

        # Loop plaintext entries
        for _, entry_obj in vault.get("entries", {}).items():

            # Convert entry dict -> JSON plaintext string
            plaintext_json = json.dumps(entry_obj)

            # Generate a new unique ID
            eid = bytes_to_str(secrets.token_bytes(EID_LEN))
            while eid in encrypted_entries:
                eid = bytes_to_str(secrets.token_bytes(EID_LEN))
            
            # Encrypt with *current* master key
            encrypted_blob = encrypt(plaintext_json, key, eid)

            # Append into current vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1
            del entry_obj

        save_vault(encrypted_entries, key)
        print(f"Imported {imported_count} entries from JSON.")
        
    except Exception as e:
        print(f"Failed to import exported JSON: {e}")
        return False

    return True

def import_portable(filepath, encrypted_entries, key):
    """
    Import entries from a portable (non-TPM) vault file.

    Verifies the portable vault password, decrypts each entry, re-encrypts it
    with the current vault key, and adds it to the active vault.

    Args:
        filepath: Path to the portable vault JSON file.
        encrypted_entries: Current vault entries to append imported items to.
        key: Active vault encryption key.

    Returns:
        True if entries were imported successfully.

    Raises:
        SystemExit: If the portable vault is invalid or password verification fails.
    """
    try:
        # Load JSON file
        with open(IMPORT_DIR / filepath, "r", encoding=UTF8) as f:
            vault = json.load(f)

        required = {"salt", "canary", "canary_id", "entries"}
        if not required.issubset(vault):
            print("Error: this is not a valid vault")
            return False
        
        imported_count = 0

        # Verify master password
        vault_pw = getpass.getpass("Enter Vault Password: ").encode(UTF8)
        vault_salt = str_to_bytes(vault.get("salt", ""))
        vault_key = derive_key(vault_pw, vault_salt)
        del vault_pw

        try:
            canary_id = vault["canary_id"]
            decrypted_canary = decrypt(vault["canary"], vault_key, canary_id)

            if decrypted_canary != KEY_CHECK_STRING:
                msg = "Wrong master password!"
                print(msg)
                logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
                return False

        except InvalidTag:
            msg = "Wrong master password or vault is corrupted!"
            print(msg)
            logger.error(f"[{pendulum.now().to_iso8601_string()}] {msg}\n")
            return False

        # load entries
        for old_eid, blob in vault.get("entries", {}).items():
            try:
                entry_data = decrypt(blob, vault_key, old_eid)

                # Generate a new unique ID
                new_eid = secrets.token_bytes(EID_LEN)
                while new_eid in encrypted_entries:
                    new_eid = secrets.token_bytes(EID_LEN)

                # Convert eid bytes to string
                new_eid = bytes_to_str(new_eid)
                
                # Encrypt with *current* master key
                encrypted_blob = encrypt(entry_data, key, new_eid)
                del entry_data

                # Append into current vault
                encrypted_entries[new_eid] = encrypted_blob
                imported_count += 1
            except (InvalidTag, KeyError, ValueError):
                print(f" Error: entry {old_eid} corrupted")


        save_vault(encrypted_entries, key)
        print(f"Imported {imported_count} entries from JSON.")

    except Exception as e:
        print(f"Failed to import exported JSON: {e}")
        logger.error(f"[{pendulum.now().to_iso8601_string()}] {e}\n")
        return False
    finally:
        del vault_key, vault

    return True
    
def import_csv(filepath, encrypted_entries, key):
    """
    Import vault entries from a CSV file.

    Used to migrate passwords from other password managers (e.g., Bitwarden,
    browser exports). CSV fields are mapped to internal vault field names,
    encrypted with the current master key, and stored with new unique IDs.

    Args:
        filepath: Path to the CSV file to import.
        encrypted_entries: In-memory encrypted vault entries.
        key: Active master key.

    Returns:
        True if the import completed successfully.

    Side Effects:
        - Reads plaintext credentials from disk.
        - Encrypts and appends entries to the vault.
        - Writes updated vault data to disk via `save_vault()`.

    Notes:
        - Field mappings are currently hardcoded for known exporters.
        - All imported entries receive new timestamps and IDs.
    """
    try:
        with open(IMPORT_DIR / filepath, "r", encoding=UTF8) as f:
            delimiter = ','
    except:
        print( " File not found")
        return False
    
    with open(IMPORT_DIR / filepath, "r", encoding=UTF8) as f:
        delimiter = ','
        print (f"Importing from CSV... Delimiter = '{delimiter}'")
        csv_reader = csv.DictReader(f, delimiter=delimiter)
        imported_count = 0

        # Map other export field names to field names used by PasswordVault_CLI.
        # Case sensitive
        bitwarden_map = {"name": "site",
                   "login_username": "account",
                   "login_password": "password",
                   "notes": "note",
                   "login_totp": "totp"
                   }
        chrome_map = {"name": "site",
                   "username": "account",
                   "password": "password",
                    "note": "note",
                   }
        firefox_map = {"url": "site",
                   "username": "account",
                   "password": "password",
                   }
        mapping = chrome_map
        
        for row in csv_reader:
            entry_obj = {}

            for field in csv_reader.fieldnames:
                field = field
                value = row.get(field, "")
                if value:
                        # If we have a mapping, use that 
                    if field in mapping:
                        entry_obj[mapping[field]] = value
                    else:
                        # Get whatever else is stored
                        entry_obj[field] = value

            # firefox
            # created =pendulum.from_timestamp(int(row.get("timeCreated", ""))//1000).to_date_string()
            # last_used = pendulum.from_timestamp(int(row.get("timeLastUsed", ""))//1000).to_date_string()
            # last_changed = pendulum.from_timestamp(int(row.get("timePasswordChanged", ""))//1000).to_date_string()
            # date_str = f"Date created  {created}\nLast_used {last_used}\nLast Changed {last_changed}"
            # entry_obj["note"] = date_str

            # entry_obj["site"] = entry_obj["site"].removeprefix("https://")
            # entry_obj["site"] = entry_obj["site"].removeprefix("www.")

            entry_obj["created_date"] = pendulum.now().to_iso8601_string()
            entry_obj["edited_date"] = pendulum.now().to_iso8601_string()
            entry_obj["imported_from"] = filepath

            plaintext = json.dumps(entry_obj)
            entry_obj.clear()
            del entry_obj

            # Generate unique entry ID
            eid = secrets.token_bytes(EID_LEN)
            while eid in encrypted_entries:
                eid = secrets.token_bytes(EID_LEN)

            # Convert eid bytes to string
            eid = bytes_to_str(eid)

            # Encrypt using master key
            encrypted_blob = encrypt(plaintext, key, eid)
            del plaintext

            
            # Save into vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1

    save_vault(encrypted_entries, key)
    print(f"Imported {imported_count} entries from CSV.")
    return True