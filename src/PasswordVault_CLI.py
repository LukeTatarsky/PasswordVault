"""
PasswordVault - a secure offline password manager
"""
# ==============================================================
# Standard imports
# ==============================================================
import os
import sys
import json
import time
import atexit
import getpass
import threading
import secrets
import string
import gc
import logging

# ==============================================================
# Third-party imports
# ==============================================================
from config.config_vault import *
from config.logging_config import setup_logging
from utils.crypto_utils import *
from utils.totp_qr_code import *
from utils.password_utils import *
from utils.vault_utils import *
from utils.import_export import *
from utils.user_input import *
from utils.password_generator import *

try:
    import pyperclip
    import pendulum
    
except ImportError as e:
    missing_package = e.name if hasattr(e, "name") else "unknown package"
    print("Missing required dependency!")
    print(f"  {missing_package} is not installed")
    logging.error(f"  {missing_package} is not installed")
    print("\nInstall with:")
    print("  pip install -r requirements.txt")
    time.sleep(2)
    sys.exit(1)

# ==============================================================
# Functions
# ==============================================================


def update_entry(encrypted_entries: dict[str, str], key: bytes, eid: str) -> int:
    """
    Interactively edit a password vault entry via the command line.

    Loads and decrypts the specified entry, then presents a menu that
    allows the user to edit fields, view the entry, save changes,
    delete the entry, or cancel without saving.

    Changes are written to disk only after explicit confirmation.
    Deletions also require explicit confirmation.

    Args:
        encrypted_entries: In-memory mapping of entry IDs to encrypted tokens.
        key: key used for decryption and encryption.
        eid: Entry ID to edit.

    Returns:
        0 if changes were saved or the operation was cancelled.
        1 if the entry was deleted or an error occurred.

    Side Effects:
        Prompts for user input.
        Prints status and error messages.
        Writes updated vault data to disk on save or delete.

    Security Notes:
        - Requires explicit confirmation before saving or deleting.
        - Enforces non-empty site names.
        - Automatically updates edit timestamps on save.
        - Maintains password history according to configuration.
    """
    if eid not in encrypted_entries:
        print("ID not found")
        return 1

    # Load and decrypt the entry
    try:
        data = json.loads(decrypt(encrypted_entries[eid], key, eid))
    except InvalidTag:
            res = delete_corrupted_entry(encrypted_entries, key, eid)
            return res
    except Exception:
        print("Entry corrupted — cannot edit")
        return 1
    
    choice = 0

    while True:
        gc.collect()
        if choice != '5':
            display_entry(data, None, None, show_pass=False)
        print(
            f"\n--- Editing Menu --- \n"
            f"   1. Edit Site          5. Display Entry (shows all) \n"
            f"   2. Edit Account       6. Save & Exit \n"
            f"   3. Edit Password      7. Delete Entry \n"
            f"   4. Edit Note          8. Cancel (discard changes) \n"
            f"   9. Edit Recovery Keys \n"
            f"   0. Edit TOTP Key"
            )
        
        choice = input("\n → ").strip()

        if choice == "1":
            current = data.get('site', '')
            new_site = input(f"New site [{current}]: ").strip()
            if new_site and new_site != current:
                data["site"] = new_site
                print("   Site updated")
            else:
                print("   Site unchanged")
            del new_site

        elif choice == "2":
            current = data.get('account') or ''
            new_acc = input(f"New account [{current}]: ").strip()
            data["account"] = new_acc or ''
            del new_acc
            print("   Account updated")

        elif choice == "3":
            new_pw = ask_password("New password:")
            if new_pw is None:
                continue

            # Keep password history
            pw_history = data.get("password_history", [])
            pw_history.insert(0, {"password" : data.get("password", ""),
                                "last_used" : pendulum.now().to_iso8601_string()})
            data["password_history"] = pw_history[:PASSWORD_HISTORY_LIMIT]
            data["password"] = new_pw
            pw_history.clear()
            del pw_history
            new_pw = None
            del new_pw
            print("   Password updated")

        elif choice == "4":
            print ("\nCurrent note:")
            print(SEP_SM)
            print(data.get("note", "")) 
            print(SEP_SM)
            note = get_note_from_user()
            data["note"] = note
            note = None
            del note
            print("   Note updated")

        elif choice == "5":
            display_entry(data, show_all=True)

        elif choice == "6":
            if data.get("site", "").strip() == "":
                print("   Error: Site cannot be empty!")
                continue

            confirm = input(f"\nSave changes to {data.get('site', '')}? (type 's' to confirm): ")
            if confirm.strip().lower() != "s":
                print("   Save cancelled")
                continue

            # Update timestamp5
            data["edited_date"] = pendulum.now().to_iso8601_string()

            # Re-encrypt and save
            blob = encrypt(json.dumps(data, separators=(',', ':')), key, eid)
            encrypted_entries[eid] = blob
            save_vault(encrypted_entries, key)
            print("\nEntry updated and saved successfully!")
            data.clear()
            data = None
            del data
            return 0

        elif choice == "7":
            confirm = input(f"\nDelete this entry permanently? (type 'del' to confirm): ")
            if confirm.strip().lower() == "del":
                del encrypted_entries[eid]
                save_vault(encrypted_entries, key)
                print("Entry deleted.")
                data.clear()
                data = None
                del data
                return 1
            else:
                print("   Delete cancelled")
            
        elif choice == "8":
            print("All changes discarded.")
            data.clear()
            data = None
            del data
            return 0
        
        elif choice == "9":
            print ("\nCurrent Keys:")
            print(SEP_SM)
            print(data.get("keys", "")) 
            print(SEP_SM)
            keys = get_note_from_user(prompt="Enter Recovery Keys:")
            data["keys"] = keys
            keys = None
            del keys
            print("   Keys updated")

        elif choice == "0":
            print ("\nCurrent TOTP code:")
            print(SEP_SM)
            print(data.get("totp", "")) 
            print(SEP_SM)
            totp = input("Enter TOTP Generator Key: ").strip()
            data["totp"] = totp
            totp = None
            print("   TOTP updated")

        else:
            print("   Invalid option — choose 0-9")
        

def entry_menu(encrypted_entries: dict[str, str], key: bytes, eid: str) -> int:
    """
    Display and handle the interactive menu for a single vault entry.

    Presents actions for viewing, copying, editing, and managing a
    decrypted vault entry, including password, account, history, and
    TOTP-related operations.

    Args:
        encrypted_entries: Mapping of entry IDs to encrypted tokens.
        key: key used to decrypt entry data.
        eid: Entry ID to operate on.

    Returns:
        0 if the user exits normally.
        1 if the entry cannot be displayed or an error occurs.

    Side Effects:
        Prompts for user input.
        Copies sensitive data to the clipboard.
        Prints entry information and status messages.

    Security Notes:
        - Clipboard copies may auto-clear after a timeout.
        - Sensitive data is cleared from memory where possible.
        - Passwords are not displayed unless explicitly requested.
    """
    res = display_entry(encrypted_entries, key, eid)
    if res != 0:
        return 1

    while True:
        
        print(f"\n--- Entry Menu ---\n"
                f"(C) Copy Password    (U) Copy Account\n"
                f"(S) Show Password    (H) Password History \n"
                f"(A) Show All         (T) Get TOTP Code \n"
                f"(E) Edit Entry       (QR) Show TOTP QR code \n"
                f"(Enter) Main Menu "
                ,end="\n > ")
        choice_2 = input().strip().lower()

        # == COPY PASSWORD ===================================
        if choice_2 == "u":
            entry_data = get_entry_data(encrypted_entries, key, eid)
            user = entry_data.get("account", "") if entry_data else ""
            copy_to_clipboard(user, timeout=0, prompt=False)
            user = None
            entry_data = None
            del entry_data
            continue

        # == COPY PASSWORD ===================================
        if choice_2 == "c":
            entry_data = get_entry_data(encrypted_entries, key, eid)
            pw = entry_data.get("password", "") if entry_data else ""
            copy_to_clipboard(pw, timeout=CLIPBOARD_TIMEOUT, prompt=False)
            pw = None
            entry_data = None
            continue
        
        # == SHOW PASSWORD ===================================
        elif choice_2 == "s":
            res = display_entry(encrypted_entries,
                key,
                eid,
                show_pass=True,
                show_history=False
            )
            if res != 0:
                continue

        # == SHOW PASSWORD HISTORY ============================
        elif choice_2 == "h":
            res = display_entry(
                encrypted_entries,
                key,
                eid,
                show_pass=False,
                show_history=True
            )
            if res != 0:
                continue

        # == SHOW COMPLETE ENTRY ==============================
        elif choice_2 == "a":
            res = display_entry(
                encrypted_entries,
                key,
                eid,
                show_all=True
            )
            if res != 0:
                continue
        
        # == GET TOTP CODE ==============================
        elif choice_2 == "t":
            totp_key = get_entry_data(encrypted_entries, key, eid).get("totp")
            if totp_key:
                show_totp_code(totp_key)
                totp_key = b"\x00" * len(totp_key)
            else:
                print("No TOTP key available.")
            del totp_key

        # == EDIT ENTRY =======================================
        elif choice_2 == "e":
            res = update_entry(encrypted_entries, key, eid)
            if res == 1:
                # error, back to main
                break
            # show entry after update
            display_entry(encrypted_entries, key, eid)
            
        elif choice_2 in {"", "enter", "q"}:
            break
        
        elif choice_2 == "qr":
            
            secret=get_entry_data(encrypted_entries, key, eid).get("totp")
            if secret:
                issuer=get_entry_data(encrypted_entries, key, eid).get("site")
                label=get_entry_data(encrypted_entries, key, eid).get("account")
                show_totp_qr(secret, label, issuer)
            else:
                print("No TOTP key available")
            secret = b"\x00" * len(secret)
            del secret

        else:
            print("\rInvalid Choice\n", flush=True)

    return 0


def copy_to_clipboard(text: str,
                       timeout: int = CLIPBOARD_TIMEOUT,
                         prompt = True) -> None:
    """
    Copy sensitive text to the system clipboard with optional auto-clear.

    Optionally prompts the user before copying. If a timeout is
    specified, a background daemon thread clears the clipboard after
    the delay to reduce exposure of sensitive data.

    Args:
        text: Text to copy to the clipboard.
        timeout: Number of seconds before the clipboard is cleared.
            A value of 0 or less disables auto-clear.
        prompt: If True, prompt the user before copying. If False,
            copy immediately.

    Returns:
        None

    Side Effects:
        Copies data to the system clipboard.
        Spawns a background daemon thread if auto-clear is enabled.

    Security Notes:
        - Clipboard is cleared after the timeout when enabled.
        - Clipboard history may be wiped depending on configuration.
        - Errors during clipboard operations are suppressed to avoid
          crashing the application.
    """
    if not text:
        print(" Nothing to copy.")
        return
    
    if prompt and input(" Copy to clipboard? (y/n):").strip().lower() != "y":
        return
    
    # Copy to clipboard
    pyperclip.copy(text)
    text = " Copied!" + (f"(auto-clears in {timeout}s)" if timeout > 0 else "")
    print(text, flush=True)

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
    Attempt to wipe clipboard history by flooding it with random data.

    Overwrites the clipboard repeatedly with randomly generated strings
    in an effort to evict sensitive entries from clipboard history.
    Behavior depends on platform and clipboard manager capabilities.

    Args:
        clipboard_length: Number of random clipboard entries to generate.

    Returns:
        None

    Side Effects:
        Overwrites the system clipboard multiple times.
        Introduces small delays to avoid clipboard throttling.

    Security Notes:
        - Disabled if WIPE_CLIPBOARD is False in configuration.
        - Best-effort only; some clipboard managers retain long histories.
        - Final clipboard content is a non-sensitive placeholder string.
    """
    # Simple overwrite on exit
    pyperclip.copy("")

    if not WIPE_CLIPBOARD:
        return
    
    char_set = string.ascii_letters + string.digits + "!@#$%^&*"

    for i in range(clipboard_length):
        fake_data = ''.join(secrets.choice(char_set) for _ in range(40))
        fake_data = f"[{i:03d}] {fake_data} - {secrets.token_hex(EID_LEN)}"

        pyperclip.copy(fake_data)
        
        # Defeats throttling
        time.sleep(0.07)

    pyperclip.copy("Clipboard history cleared")
    return


def wipe_terminal():
    """
    Clear the terminal screen.

    Returns:
        None

    Side Effects:
        Executes a system command to clear the terminal window.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

# ==============================================================
# MAIN
# ==============================================================
def main():
    global salt
    print("- Password Manager —\n")
    master_pw = getpass.getpass("Master password: ").encode(UTF8)

    key, encrypted_entries, salt = load_vault(master_pw)

    # Best effort to clear Strings. Python Strings are imutable.
    master_pw = b"\x00" * len(master_pw)
    del master_pw
    
    # clears clipboard on exit
    atexit.register(clear_clipboard_history)
    choice = ''

    while True:
        gc.collect()

        if CLEAR_SCREEN and choice != "9":
            time.sleep(0.4)
            wipe_terminal()

        print("\n--- Main Menu ---")
        print("\n 1) New Entry    2) Get Entry     7) Quit   9) More Options")
        choice = input(" > ").strip()
        print()

        # == ADD ENTRY =====================================
        if choice == "1":
            # Get info
            site = input("Site (required): ").strip()
            if not site:
                print("Site name cannot be empty!")
                continue
            account = input("Account: ").strip()

            note = get_note_from_user()

            password = ask_password("New password")
            if password is None:
                continue
            if password:
                copy_to_clipboard(password)

            created_date = pendulum.now().to_iso8601_string()

            # create the blob
            entry = json.dumps({"site": site,
                                "account": account,
                                "password": password,
                                "note": note,
                                "keys": "",
                                "created_date": created_date,
                                "edited_date": created_date,
                                "password_history": [],
                                "totp": ""}, separators=(',', ':'),
                                )
            
            # Generate unique entry identifier
            eid = secrets.token_bytes(EID_LEN)
            while eid in encrypted_entries:
                eid = secrets.token_bytes(EID_LEN)

            # Convert eid bytes to string
            eid = bytes_to_str(eid)

            # Encrypt data
            encrypted_blob = encrypt(entry, key, eid)

            # Remove references
            del entry, note, password, site, account

            # Save
            encrypted_entries[eid] = encrypted_blob
            save_vault(encrypted_entries, key)

            print(f"Entry added to vault")


        # == GET ENTRY =======================================
        elif choice == "2":
            print(f"Retrieve a list of entries that match query. " 
                f"Press Enter to show all entries.")
            query = input("\n Enter search query: ").strip().lower()
            entries = list_entries(encrypted_entries, key, query)

            if not entries:
                continue 
            while (True):
                prompt = "\n Select entry: "

                selection = get_int(prompt, default=0)

                # Quit back to main
                if selection is None:
                    break

                # If invalid selection, try again
                if selection > len(entries) or selection < 1:
                    print (f"   Invalid. Select 1 - {len(entries)} or (q) to quit")
                    continue
                 
                # Valid, go to entry menu
                else:
                    eid = entries[selection - 1]
                    entry_menu(encrypted_entries, key, eid)
                    break

        # == QUIT ===============================================
        elif choice == "7":
            print("Goodbye!")
            sys.exit(0)

        # == OPTIONS ===============================================
        elif choice == "9":
            print()
            print(f"  change_pass - Changes master password and Re-encrypts all entries.")
            print(f"  audit_vault - Performs an audit on all passwords contained in vault.")
            print(f"  export_json - Exports vault in plaintext for backup.")
            print(f"  import_json - Imports previously exported vault from backup.")
            print(f"  import_csv  - Imports data from other password managers.")    

        # == CHANGE MASTER PW ===================================
        elif choice == "change_pass":
            change_master_password()

        # == AUDIT VAULT ===================================
        elif choice == "audit_vault":
            t_exposure = input("\n Would you like to check for exposed passwords? (y/n): ").strip()
            t_exposure = 1 if t_exposure == "y" else 0

            t_strength = input(" Would you like to test password strength? (y/n): ").strip()
            t_strength = 0 if t_strength == "n" else 1

            t_reuse = input(" Would you like to check for password re-use? (y/n): ").strip()
            t_reuse = 0 if t_reuse == "n" else 1

            confirm = input("\n Type 'audit' to confirm: ").strip()
            if confirm != "audit":
                continue
            
            audit_vault(encrypted_entries, key,
                         test_exposure=t_exposure, 
                         test_strength=t_strength, 
                         test_reuse=t_reuse)

        # == IMPORT/EXPORT ===================================
        # In development
        elif choice == "export_json":
            timestamp = pendulum.now().format(DT_FORMAT_EXPORT)
            export_json(f"vault_export_{timestamp}.json", key, encrypted_entries, salt)

        elif choice == "import_csv":
            print("Used to populate the vault.")
            filename = input("Enter CSV filename to import: ").strip()
            import_csv(f"{filename}.csv", encrypted_entries, key, salt)

        elif choice == "import_json":
            filename = input("Enter JSON filename to import: ").strip()
            import_exported_json(f"{filename}.json", encrypted_entries, key, salt)

        else:
            print("Invalid Choice")

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)

    main()