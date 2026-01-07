import secrets
import getpass
import csv
import json
import os
import logging
import base64
import pendulum

from typing import Dict
from cryptography.exceptions import InvalidTag

from config.config_vault import *
from utils.Entry import Entry, bytes_to_str, str_to_bytes
from utils.crypto_utils import encrypt_entry, encrypt, decrypt_entry, decrypt, derive_key
from utils.vault_utils import load_vault, save_vault
from utils.user_input import get_int


logger = logging.getLogger(__name__)

# Mapping different field names to the field names used by PasswordVault
# Potential issue when two mappings are the same but one has an extra matched field.
# Proton export can potentially be detected as and edge export.
# Ask user to validate schema
SCHEMAS = {
        "bitwarden" : {"name": "site",
                    "login_username": "account",
                    "login_password": "password",
                    "notes": "note",
                    "login_totp": "totp"
                    },
        "proton" : {"name" : "site",
                    "username": "account",
                    "password": "password",
                    "note": "note"
                    },
        "chrome" : {"name": "site",
                    "username": "account",
                    "password": "password",
                    "note": "note",
                    },
        "firefox" : {"url": "site",
                    "username": "account",
                    "password": "password",
                    },
        "opera" : {"name" : "site",
                    "username": "account",
                    "password": "password",
                    "note": "note"
                    },
        "edge" : {"name" : "site",
                    "username": "account",
                    "password": "password",
                    "note": "note"
                    },
        "password_vault" : {"site" : "site",
                    "account": "account",
                    "password": "password",
                    "note": "note",
                    "totp": "totp",
                    "rec_keys": "rec_keys",
                    },
    }

# These come as integers, convert them for dates before storing.
FIREFOX_TIME_FIELDS = {
    "timecreated",
    "timelastused",
    "timepasswordchanged",
}
PROTON_TIME_FIELDS = {
    "createtime",
    "modifytime",
}

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
                entry = decrypt_entry(old_blob, temp_key, eid)
                # Encrypt again with new key
                new_blob = encrypt_entry(entry, new_key, eid)
                entry.wipe()
                del entry
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
        file_name = f"password_vault_portable_{timestamp}.vault"


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
                entry = decrypt_entry(blob, key, eid)
                # store tuple (eid, data) for sorting later
                decrypted_items.append((eid, entry.to_dict_export()))
                entry.wipe()
                del entry

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
            "vault_version": VERSION,
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

        decrypted_items.clear()
        del decrypted_items

    except Exception as e:
        msg = f"Failed to export vault: {e}"
        print(msg)
        logging.error(f"{pendulum.now().to_iso8601_string()} Error occured while exporting {msg}")
        return False

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
        for _, entry_obj in vault.get("entries", {}).items(): #TODO check for duplicates, use dates + manual verificaiton to decide which to keep.

            # Convert entry dict -> JSON plaintext string
            entry = Entry.from_dict_export(entry_obj)

            # Generate a new unique ID
            eid = bytes_to_str(secrets.token_bytes(EID_LEN))
            while eid in encrypted_entries:
                eid = bytes_to_str(secrets.token_bytes(EID_LEN))
            
            # Encrypt with *current* master key
            encrypted_blob = encrypt_entry(entry, key, eid)
            entry.wipe()
            del entry
            
            # Append into current vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1
            del entry_obj

        save_vault(encrypted_entries, key)
        print(f"Imported {imported_count} entries from JSON.")
        
    except Exception as e:
        msg = f"Failed to export vault: {e}"
        print(msg)
        logging.error(f"{pendulum.now().to_iso8601_string()} Error occured while exporting {msg}")
        sys.exit(1)
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
                entry = decrypt_entry(blob, vault_key, old_eid)

                # Generate a new unique ID
                new_eid = secrets.token_bytes(EID_LEN)
                while new_eid in encrypted_entries:
                    new_eid = secrets.token_bytes(EID_LEN)

                # Convert eid bytes to string
                new_eid = bytes_to_str(new_eid)
                
                # Encrypt with *current* master key
                encrypted_blob = encrypt_entry(entry, key, new_eid)
                entry.wipe()
                del entry

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

    Notes:
        - Field mappings are currently hardcoded for known exporters.
        - All imported entries receive new timestamps and IDs.
        - Any additional data not in mapping is saved in entry.other
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

        vault_attributes = vars(Entry("temp"))
        clean_fields = [f.strip() for f in csv_reader.fieldnames]

        # Try to match schema to one of the presets.
        schema_name = detect_schema(set(clean_fields))

        # Ask user to confirm
        ask = input(f"\n Detected [{schema_name.capitalize()}] file. Is this correct? (y/n): ").strip()

        # If its not correct, select the correct one manually.
        if ask == 'n':
            print("\nSelect schema from list")
            schema_list = list(SCHEMAS.keys())
            for i in range(len(schema_list)):
                print(f" {i} - {schema_list[i]}")
            c = get_int(": ")
            if c is None:
                return
            schema_name = schema_list[c]
        
        schema = SCHEMAS.get(schema_name, {})

        for row in csv_reader:
            entry = Entry("temp_import_site")
            
            clean_row = {f.strip().lower(): clean_val(v) for f, v in row.items()}

            for csv_field, value in clean_row.items():
                # values can be none
                if not value:
                    continue

                value = normalize_newlines(clean_row.get(csv_field, ""))

                # Entry has this field
                if csv_field in vault_attributes:
                    # convert to byte array if required
                    if isinstance(vault_attributes.get(csv_field),bytearray):
                        setattr(entry, csv_field, bytearray(value, UTF8))
                    else:
                        setattr(entry, csv_field, value)
                
                # else if we have a schema mapping, use that
                elif csv_field in schema:
                    csv_field = schema[csv_field]
                    # convert to byte array if required
                    if isinstance(vault_attributes.get(csv_field),bytearray):
                        setattr(entry, csv_field, bytearray(value, UTF8))
                    else:
                        setattr(entry, csv_field, value)
                
                # store anything else in "other"
                else:
                    # convert the firefox timestamps to pendulum date string.
                    if schema_name == "firefox" and csv_field in FIREFOX_TIME_FIELDS:
                        firefox_process_timestamp(entry, clean_row, csv_field)
                    
                    # convert the proton pass timestamps to pendulum date string.
                    elif schema_name == "proton" and csv_field in PROTON_TIME_FIELDS:
                        proton_process_timestamp(entry, clean_row, csv_field)

                    # Deal with bitwardens custom fields
                    elif schema_name == "bitwarden" and csv_field == "fields":
                        # bitwarden exports custom fields like 'secret field: other password\nother field: atestt'
                        # split on newline then on colon
                        for line in value.splitlines():
                            if ":" not in line:
                                continue
                            field_key, value = line.split(":")
                            # Store it in other
                            entry.other[field_key] = clean_val(value)

                    else:
                        entry.other[csv_field] = value

            # Remove the following prefixes from all entries
            entry.site = entry.site.removeprefix("https://")
            entry.site = entry.site.removeprefix("www.")

            entry.other["imported_from"] = filepath

            # Generate unique entry ID
            eid = secrets.token_bytes(EID_LEN)
            while eid in encrypted_entries:
                eid = secrets.token_bytes(EID_LEN)

            # Convert eid bytes to string
            eid = bytes_to_str(eid)

            # Encrypt using master key
            if entry.site == "temp_import_site":
                msg = f"Error occured while importing data from {filepath}."\
                    f"Please check for correct field mapping."
                logging.error(msg)
            encrypted_blob = encrypt_entry(entry, key, eid)
            entry.wipe()
            del entry
            
            # Save into vault
            encrypted_entries[eid] = encrypted_blob
            imported_count += 1

    save_vault(encrypted_entries, key)
    print(f"Imported {imported_count} entries from CSV.")
    return True

def export_csv():
    """
    Export the vault to a decrypted csv file.

    Verifies the master password, decrypts all vault entries, and writes them
    to a plaintext csv file sorted for readability.

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
        del master_pw
    except:
        # Lock if wrong password entered
        logging.error(f"{pendulum.now().to_iso8601_string()} Incorrect password entered while exporting json")
        sys.exit(0)

    try:
        # Temporary list to hold decrypted entries
        decrypted_items = []
        normal_fields = set()
        normal_fields.update(["site", "account", "note", "pw_hist", "created", "edited", "password", "rec_keys", "totp", "created", "edited"])
        # secret_fields = set()
        # other_fields = set()

        # Decrypt each entry first
        for eid, blob in encrypted_entries.items():
            try:
                entry = decrypt_entry(blob, key, eid)
                # store tuple (eid, data) for sorting later
                decrypted_items.append((eid, entry.to_dict_export()))

            except Exception as e:
                print(f"Failed to decrypt entry {eid}: {e}")

        # Sort entries by site then account (case-insensitive)
        decrypted_items.sort(
            key=lambda item: (
                item[1].get("site", "").lower(),
                item[1].get("account", "").lower(),
                item[1].get("created", "")
            )
        )

        normal_fields = sorted(normal_fields)
        # secret_fields = sorted(secret_fields)
        # other_fields = sorted(other_fields)
        all_fields = normal_fields #+secret_fields+other_fields

        # Remove the prefix before trying to access these fields later
        # secret_fields = [f.split('.')[1] for f in secret_fields]
        # other_fields = [f.split('.')[1] for f in other_fields]

        timestamp = pendulum.now().format(DT_FORMAT_EXPORT)
        file_name = f"password_vault_export_{timestamp}.csv"

        with open(EXPORT_DIR / file_name, "w", newline="", encoding="utf-8") as f:

            writer = csv.DictWriter(f, fieldnames=all_fields,extrasaction="raise")
            writer.writeheader()

            # Write sorted entries into the dict
            for eid, data in decrypted_items:
                row = {}
                for field in normal_fields:
                    x = data.get(field, "")
                    print (x)
                # Normal fields
                row.update({
                            field: data.get(field, "")
                            for field in normal_fields
                        })
                # # secret _fields
                # row.update({
                #         f"_fields.{field}": data.get("_fields", {}).get(field, "") for field in secret_fields
                #         })
                # # Other fields
                # row.update({
                #         f"other.{field}": data.get("other", {}).get(field, "") for field in other_fields
                #         })
                writer.writerow(row)

        # Error / Success message 
        if len(decrypted_items) != len(encrypted_entries):
            print (" Error Exporting all entries. Check for corrupted entries.")
        else:
            print (" Vault exported successfully.")

        decrypted_items.clear()
        del decrypted_items

    except Exception as e:
        msg = f"Failed to export vault: {e}"
        print(msg)
        logging.error(f"{pendulum.now().to_iso8601_string()} Error occured while exporting {msg}")
        return False

    return True
def clean_val(v):
    """
    Normalize a value to a stripped string.

    Returns an empty string for None values.

    Args:
        v: Input value.

    Returns:
        Cleaned string value.
    """
    return v.strip() if v is not None else ""

def normalize_newlines(s: str) -> str:
    """
    Normalize escaped newlines in a string.

    Converts literal CRLF and LF escape sequences to newline characters.

    Args:
        s: Input string.

    Returns:
        String with normalized newlines.
    """
    return s.replace("\\r\\n", "\n").replace("\\n", "\n")

def detect_schema(headers: set[str]) -> str | None:
    """
    Detect the best-matching import schema.

    Selects the schema with the highest overlap with the provided
    header set.

    Args:
        headers: CSV header names.

    Returns:
        Schema name if detected, otherwise None.
    """
    best_match = None
    best_score = 0

    for browser, schema in SCHEMAS.items():
        score = len(headers & schema.keys())
        if score > best_score:
            best_score = score
            best_match = browser

    return best_match if best_score >= 2 else None

def firefox_process_timestamp(entry: Entry, row: dict[str, str], field: str) -> None:
    """
    Process a Firefox timestamp field.

    Converts a millisecond Unix timestamp to a date string and stores
    it on the entry.

    Args:
        entry: Vault entry to update.
        row: Source data row.
        field: Timestamp field name.

    Side Effects:
        Updates entry metadata.
    """
    ts = row.get(field)
    if ts and ts.isdigit():
        entry.other[field] = (
            pendulum.from_timestamp(int(ts) // 1000)
            .to_date_string()
        )
    return

def proton_process_timestamp(entry: Entry, row: dict[str, str], field: str) -> None:
    """
    Process a Proton timestamp field.

    Converts a Unix timestamp to a date string and stores it on
    the entry.

    Args:
        entry: Vault entry to update.
        row: Source data row.
        field: Timestamp field name.

    Side Effects:
        Updates entry metadata.
    """
    ts = row.get(field)
    if ts and ts.isdigit():
        entry.other[field] = (
            pendulum.from_timestamp(int(ts))
            .to_date_string()
        )
    return
