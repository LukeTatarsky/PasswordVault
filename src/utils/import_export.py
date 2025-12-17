import secrets
import getpass
import csv
from config.config_vault import *
from .crypto_utils import *
from .vault_utils import *

"""
Under development
"""

def export_json(filepath, key, encrypted_entries, salt):
    """
    Export the entire vault to a decrypted JSON file.

    Prompts for the master password to verify authorization, decrypts all
    vault entries, sorts them by site and account, and writes the data to a
    plaintext JSON file.

    WARNING:
        This operation exports all passwords in plaintext. The resulting
        file must be protected appropriately.

    Args:
        filepath: Destination path for the exported JSON file.
        key: Master key for the current vault session.
        encrypted_entries: Dictionary mapping entry IDs to encrypted tokens.
        salt: Salt used for key derivation verification.

    Returns:
        None

    Raises:
        SystemExit: If the provided master password is invalid.

    Side Effects:
        - Prompts the user for the master password.
        - Writes a plaintext JSON file to disk.
        - Logs failed authentication attempts.
    """
    print("\nWARNING: This will export ALL passwords and data in plain text!!!\n")
    master_pw = getpass.getpass("Master password: ").encode(UTF8)
    generated_key = derive_key(master_pw, salt)
    del master_pw

    if generated_key != key:
        print ("Error: Invalid Password. Export cancelled. Exiting.")
        msg = (f"Invalid password entered during export")
        now = pendulum.now().to_iso8601_string()
        logging.error(f"[{now}] {msg}\n")
        sys.exit(1)

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
            "date_exported": pendulum.now().in_timezone('local').format(DT_FORMAT),
            "entries": {}
        }

        # Write sorted entries into the dict
        for eid, data in decrypted_items:

            # Force same order for all entries
            json_order = ["site", "account", "password", "note", "totp", "created_date", "edited_date"]
            ordered_entry = {k: data[k] for k in json_order if k in data}

            # Order doesnt matter for remaining keys
            for k, v in data.items():
                if k not in json_order:
                    ordered_entry[k] = v

            vault["entries"][eid] = ordered_entry

        # Save to file
        with open(filepath, "w", encoding=UTF8) as f:
            json.dump(vault, f, indent=4)

        # Error / Success message 
        if len(decrypted_items) != len(encrypted_entries):
            print (" Error Exporting entries.")
        else:
            print (" Vault exported successfully.")

    except Exception as e:
        print(f"Failed to export vault: {e}")

    finally:
        decrypted_items = []
        data = None

    return

def import_exported_json(filepath, encrypted_entries, key, salt):
    """
    Import entries from a previously exported plaintext JSON file.

    Reads a JSON file created by `export_json`, encrypts each entry using the
    current master key, assigns new unique entry IDs, and appends them to the
    active vault.

    Args:
        filepath: Path to the exported JSON file.
        encrypted_entries: In-memory encrypted vault entries.
        key: Active master key.
        salt: Current vault salt (unused but required for interface symmetry).

    Returns:
        True if entries were imported successfully, False otherwise.

    Side Effects:
        - Modifies the in-memory vault entries.
        - Persists changes to disk using `save_vault()`.
    """
    try:
        # Load JSON file
        with open(filepath, "r", encoding=UTF8) as f:
            vault = json.load(f)

        imported_count = 0

        # Loop plaintext entries
        for old_eid, entry_obj in vault.get("entries", {}).items():

            # Convert entry dict -> JSON plaintext string
            plaintext_json = json.dumps(entry_obj)

            # Generate a new unique ID
            eid = secrets.token_bytes(EID_LEN)
            while eid in encrypted_entries:
                eid = secrets.token_bytes(EID_LEN)

            # Convert eid bytes to string
            eid = bytes_to_str(eid)
            
            # Encrypt with *current* master key
            encrypted_blob = encrypt(plaintext_json, key, eid)

            # Append into current vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1

        save_vault(encrypted_entries, key)
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
    Import vault entries from a CSV file.

    Used to migrate passwords from other password managers (e.g., Bitwarden,
    browser exports). CSV fields are mapped to internal vault field names,
    encrypted with the current master key, and stored with new unique IDs.

    Args:
        filepath: Path to the CSV file to import.
        encrypted_entries: In-memory encrypted vault entries.
        key: Active master key.
        salt: Current vault salt (unused but retained for consistency).

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
    with open(filepath, "r", encoding=UTF8) as f:
        delimiter = ','
        print (f"Importing from CSV... Delimiter = '{delimiter}'")
        csv_reader = csv.DictReader(f, delimiter=delimiter)
        curr_time = pendulum.now().to_iso8601_string()
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
        mapping = bitwarden_map
        
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

            entry_obj["created_date"] = curr_time
            entry_obj["edited_date"] = curr_time
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