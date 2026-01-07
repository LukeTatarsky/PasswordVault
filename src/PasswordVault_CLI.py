"""
PasswordVault - a secure offline password manager
"""
# ==============================================================
# Standard imports
# ==============================================================
import os
import sys
import time
import atexit
import secrets
import gc
import logging
import getpass

# ==============================================================
# Other imports
# ==============================================================
from config.config_vault import *
from config.logging_config import setup_logging
from utils.Entry import Entry, bytes_to_str, str_to_bytes, wipe_bytes, print_bytearray
from utils.crypto_utils import decrypt_entry, encrypt_entry, derive_key
from utils.clipboard_utils import copy_to_clipboard, clear_clipboard_history
from utils.vault_utils import load_vault, save_vault, list_entries, display_entry, change_master_password
from utils.user_input import get_note_from_user, get_int, get_keys_from_user, get_totp_from_user
from utils.password_generator import ask_password
from utils.totp_qr_code import show_totp_code, show_totp_qr
from utils.password_utils import audit_entry, audit_vault
from utils.import_export import export_json, export_portable, import_json, import_portable, import_csv, export_csv

try:
    import pendulum


    # from utils.vault_utils import display_entry, save_vault, load_vault, list_entries, change_master_password
    
    # from utils.password_generator import ask_password
    # from utils.user_input import get_note_from_user, get_int
    # from utils.clipboard_utils import copy_to_clipboard, clear_clipboard_history
    # from utils.totp_qr_code import show_totp_code, show_totp_qr
    # from utils.password_utils import audit_entry, audit_vault
    # from utils.import_export import import_csv, import_json, import_portable, export_json, export_portable

    
except ImportError as e:
    missing_package = e.name if hasattr(e, "name") else "unknown package"
    print("Missing required dependency!")
    print(f"  {missing_package} is not installed")
    logging.error(f"  {missing_package} is not installed. See requirements.txt")
    print("\nInstall with:")
    print("  pip install -r requirements.txt")
    time.sleep(2)
    sys.exit(0)

# ==============================================================
# Functions
# ==============================================================

def update_entry(encrypted_entries: dict[str, str], e: Entry, entry_key: bytes, eid: str, vault_key: bytes) -> Entry | None:
    """
    Display an interactive menu for editing a single vault entry.

    Allows updating site, account, password, note, TOTP key, and recovery keys.
    Handles password history, encryption, and deletion.

    Args:
        encrypted_entries: Mapping of entry IDs to encrypted tokens.
        entry: The Entry object to edit.
        key: Symmetric key used for encryption/decryption.
        eid: Entry ID used as associated data in encryption.

    Returns:
        Updated Entry object if changes are saved.
        None if the entry was deleted.
        Entry object restored from vault if changes were discarded.

    Side Effects:
        - Prompts for user input.
        - Modifies terminal display.
        - Copies sensitive data to clipboard when updating passwords.
        - Updates vault file via `save_vault`.

    Security Notes:
        - Clipboard contents are sensitive; respect auto-clear policies.
        - Password history is maintained.
        - Entry object is wiped from memory upon deletion or discard.
    """
    choice = ''

    while True:
        gc.collect()

        wipe_terminal()

        if choice == '5':
            # Show all info
            display_entry(e, entry_key=entry_key, show_all=True)
        else:
            # Show basic info
            display_entry(e, entry_key=entry_key)

        print(
            f"\n--- Editing Menu --- \n"
            f"   1. Edit Site          5. Display Entry (shows all) \n"
            f"   2. Edit Account       6. Save Entry \n"
            f"   3. Edit Password      7. Delete Entry \n"
            f"   4. Edit Note          8. Cancel (discard changes) \n"
            f"   9. Edit Recovery Keys \n"
            f"   0. Edit TOTP Key"
)

        choice = input(" > ").strip()

        if choice == "1":
            new_site = input(f"New site [{e.site}]: ").strip()
            if new_site:
                e.site = new_site
                del new_site
                print("   Site updated")

        elif choice == "2":
            new_acc = input(f"New account [{e.account}]: ").strip()
            if new_acc:
                e.account = new_acc
                del new_acc
                print("   Account updated")

        elif choice == "3":
            new_pw = ask_password("New password:")

            if new_pw is None:
                # User quits
                continue
            
            # Keep password history
            if e.field_exists('password'):
                with e.get_password(entry_key) as pw:
                    e.pw_hist.insert(0, (pendulum.now().format(DT_FORMAT_PASS_HISTORY), pw.decode(UTF8, errors="replace")))
                e.pw_hist = e.pw_hist[:PASSWORD_HISTORY_LIMIT]

            if new_pw == bytearray(b''):
                # Delete the password
                e.rm_password()
            else:
                # Set new password
                e.set_password(new_pw, entry_key)
                with e.get_password(entry_key) as new_pw:
                    copy_to_clipboard(new_pw, prompt=True)
            
            wipe_bytes(new_pw)
            del new_pw
            print("   Password updated")

        elif choice == "4":
            if e.note:
                print ("\nCurrent note:")
                print(SEP_SM)
                print(e.note) 
                print(SEP_SM)
            new_note = get_note_from_user()
            if new_note is not None:
                e.note = new_note

            print("   Note updated")

        elif choice == "5":
            continue

        elif choice == "6":
            confirm = input(f"\nSave changes to {e.site}? (type 's' to confirm): ")
            if confirm.strip().lower() != "s":
                print("   Save cancelled")
                continue

            # Update timestamp
            e.edited = pendulum.now().to_iso8601_string()

            # Re-encrypt and save
            blob = encrypt_entry(e, entry_key)
            encrypted_entries[eid] = bytes_to_str(blob)
            save_vault(encrypted_entries, vault_key)
            wipe_terminal()
            print("\nEntry updated and saved successfully!")
            return e

        elif choice == "7":
            confirm = input(f"\nDelete this entry permanently? (type 'del' to confirm): ")
            if confirm.strip().lower() == "del":
                del e
                del encrypted_entries[eid]
                save_vault(encrypted_entries, vault_key)
                wipe_terminal()
                print("\nEntry deleted.")
                return None
            
        elif choice == "8":
            wipe_terminal()
            print("All changes discarded.")
            del e
            blob = str_to_bytes(encrypted_entries[eid])
            return decrypt_entry(blob, entry_key, eid)
        
        elif choice == "9":
            if e.field_exists('rec_keys'):
                print ("\nCurrent Keys:")
                print(SEP_SM)
                with e.get_rec_keys(entry_key) as rec_keys:
                    print_bytearray(rec_keys)
                print(SEP_SM)
            new_keys = get_keys_from_user()
            if new_keys is not None:
                if new_keys == bytearray(b''):
                    # Delete the recovery keys
                    e.rm_rec_keys()
                else:
                    # Set new recovery keys
                    e.set_rec_keys(new_keys, entry_key)
                wipe_bytes(new_keys)
            del new_keys
            print("   Keys updated")

        elif choice == "0":
            if e.field_exists('totp'):
                print ("\nCurrent TOTP code:")
                print(SEP_SM)
                with e.get_totp(entry_key) as totp:
                    print_bytearray(totp)
                print(SEP_SM)
            new_totp = get_totp_from_user(prompt="Enter new TOTP Key")
            if new_totp is not None:
                if new_totp == bytearray(b''):
                    # Delete
                    e.rm_totp()
                else:
                    # Set new key
                    e.set_totp(new_totp, entry_key)
                wipe_bytes(new_totp)
            del new_totp
            print("   TOTP updated")

        else:
            print("   Invalid option — choose 0-9")

def entry_menu(encrypted_entries: dict[str, str], vault_key: bytes, eid: str) -> int:
    """
    Display the interactive menu for a single vault entry.

    Provides actions for viewing, copying, editing, auditing, and managing
    a decrypted vault entry, including password, account, TOTP, and history.

    Args:
        encrypted_entries: Mapping of entry IDs to encrypted tokens.
        key: Symmetric key used for encryption/decryption.
        eid: Entry ID to operate on.

    Returns:
        0 if the user exits normally.
        1 if the entry cannot be decrypted or an error occurs.

    Side Effects:
        - Prompts for user input.
        - Copies sensitive data to the clipboard.
        - Prints entry information and status messages.
        - Can trigger `update_entry` and audit functions.

    Security Notes:
        - Clipboard copies may auto-clear after a timeout.
        - Sensitive data is cleared from memory where possible.
        - Passwords and TOTP codes are displayed only when explicitly requested.
    """
    choice_2 = ''
    blob = encrypted_entries.get(eid)
    if blob is None:
        # error, back to main
        logging.error(f"{pendulum.now().to_iso8601_string()} Error retrieving entry {eid}")
        return 1
    entry_key = derive_key(vault_key, info = str_to_bytes(eid))
    e = decrypt_entry(str_to_bytes(blob), entry_key, eid)

    if e is None:
        # error, back to main
        logging.error(f"{pendulum.now().to_iso8601_string()} Error decrypting entry {eid}")
        return 1
    
    wipe_terminal()

    while True:
        gc.collect()
        # Show basic info
        if choice_2 == '':
            display_entry(e, entry_key)

        print(f"\n--- Entry Menu ---\n"
                f"(C) Copy Password    (U) Copy Account\n"
                f"(S) Show Password    (H) Password History \n"
                f"(A) Show All         (T) Get TOTP Code \n"
                f"(E) Edit Entry       (QR) Show TOTP QR code \n"
                f"(Enter) Main Menu    (AUD) Audit Entry"
                ,end="\n > ")
        choice_2 = input().strip().lower()

        wipe_terminal()

        # == COPY PASSWORD ===================================
        if choice_2 == "u":
            copy_to_clipboard(e.account, timeout=0, prompt=False)
            choice_2 = ''
            continue

        # == COPY PASSWORD ===================================
        if choice_2 == "c":
            with e.get_password(entry_key) as pw:
                copy_to_clipboard(pw, timeout=CLIPBOARD_TIMEOUT, prompt=False)
            choice_2 = ''
            continue
        
        # == SHOW PASSWORD ===================================
        elif choice_2 == "s":
            display_entry(e, entry_key=entry_key, show_pass=True)

        # == SHOW PASSWORD HISTORY ============================
        elif choice_2 == "h":
            display_entry(e, entry_key=entry_key, show_pw_hist=True)

        # == SHOW COMPLETE ENTRY ==============================
        elif choice_2 == "a":
            display_entry(e, entry_key=entry_key, show_all=True)
        
        # == GET TOTP CODE ==============================
        elif choice_2 == "t":
            if e.field_exists('totp'):
                res = show_totp_code(e, entry_key=entry_key)
                if res == 0:
                    wipe_terminal()
                else:
                    print("Could not generate TOTP code.")
            else:
                print("No TOTP key available.")
            choice_2 = ""

        # == EDIT ENTRY =======================================
        elif choice_2 == "e":
            e = update_entry(encrypted_entries, e, entry_key, eid, vault_key)
            if e is None:
                return 0
            choice_2 = ''
            
        # == Authenticator QR code =============================   
        elif choice_2 == "qr":
            if e.field_exists("totp"):
                show_totp_qr(e, entry_key)
            else:
                print("No TOTP key available")
            choice_2 = ''

        # == AUDIT ENTRY ===================================
        elif choice_2 == "aud":
            t_exposure = input("\n Would you like to check for exposed passwords? (y/n): ").strip()
            t_exposure = True if t_exposure == "y" else False

            confirm = input("\n Type 'aud' to confirm: ").strip()
            if confirm != "aud":
                continue
            display_entry(e, entry_key, show_pass=True)
            audit_entry(e,
                        encrypted_entries,
                        vault_key,
                         test_exposure=t_exposure, 
                         test_strength=True, 
                         test_reuse=True)

        elif choice_2 in {"", "enter", "q"}:
            break

        else:
            print("\rInvalid Choice\n", flush=True)
            choice_2 = ''

    return 0

def wipe_terminal(force=False):
    """
    Clears the terminal screen if CLEAR_SCREEN set to True.
    Args:
        force: Bypasses CLEAR_SCREEN.

    Returns:
        None

    Side Effects:
        Executes a system command to clear the terminal window.
    """
    if CLEAR_SCREEN and force == False:
        os.system('cls' if os.name == 'nt' else 'clear')

# ==============================================================
# MAIN
# ==============================================================
def main():
    global vault_salt
    print("- Password Manager —\n")

    # Main Entry point

    vault_key, encrypted_entries, vault_salt = load_vault()

    # clears clipboard on exit
    atexit.register(clear_clipboard_history)
    choice = ''

    while True:
        gc.collect()

        if choice != "9":
            time.sleep(.1)
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

            # Generate unique entry identifier
            eid = secrets.token_bytes(EID_LEN)
            while eid in encrypted_entries:
                eid = secrets.token_bytes(EID_LEN)
            # Convert eid bytes to string
            eid_s = bytes_to_str(eid)

            entry_key = derive_key(vault_key, info = eid)
            entry = Entry(site, eid_s)
            
            entry.account = input("Account: ").strip()

            note = get_note_from_user()
            if note is not None:
                entry.note = note

            pw = ask_password("New password") 
            
            if pw:
                entry.set_password(pw, entry_key=entry_key)
                wipe_bytes(pw)
                del pw
                with entry.get_password(entry_key) as pw:
                    copy_to_clipboard(pw)

            # Encrypt and save
            encrypted_entries[eid_s] = bytes_to_str(encrypt_entry(entry, entry_key = entry_key))
            del entry, site
            
            save_vault(encrypted_entries, vault_key)

            # Go straight to entry menu
            entry_menu(encrypted_entries, vault_key, eid_s)


        # == GET ENTRY =======================================
        elif choice == "2":
            print(f"Retrieve a list of entries that match query. " 
                f"Press Enter to show all entries.")
            query = input("\n Enter search query: ").strip().lower()
            entries = list_entries(encrypted_entries, vault_key, query)

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
                    entry_menu(encrypted_entries, vault_key, eid)
                    break

        # == QUIT ===============================================
        elif choice == "7":
            print("Goodbye!")
            sys.exit(0)

        # == OPTIONS ===============================================
        elif choice == "9":
            print()
            print(f"  change_pass      - Changes master password and re-encrypts all entries.")
            print(f"  audit_vault      - Performs an audit on all passwords contained in vault.")
            print()
            print(f"  export_json      - Exports vault in plaintext json for backup.")
            print(f"  export_csv       - Exports vault in plaintext csv for backup.")
            print(f"  export_portable  - Exports vault in portable mode.")
            print()
            print(f"  import_json      - Imports previously exported vault from backup.")
            print(f"  import_csv       - Imports data from other password managers.") 
            print(f"  import_portable  - Imports a portable mode vault.")
               

        # == CHANGE MASTER PW ===================================
        elif choice == "change_pass":
            change_master_password()

        # == AUDIT VAULT ===================================
        elif choice == "audit_vault":
            t_exposure = input("\n Would you like to check for exposed passwords? (y/n): ").strip()
            t_exposure = True if t_exposure == "y" else False

            t_strength = input(" Would you like to test password strength? (y/n): ").strip()
            t_strength = False if t_strength == "n" else True

            t_reuse = input(" Would you like to check for password re-use? (y/n): ").strip()
            t_reuse = False if t_reuse == "n" else True

            confirm = input("\n Type 'audit' to confirm: ").strip()
            if confirm != "audit":
                continue
            
            audit_vault(encrypted_entries, vault_key,
                         test_exposure=t_exposure, 
                         test_strength=t_strength, 
                         test_reuse=t_reuse)

        # == IMPORT/EXPORT ===================================
        elif choice == "export_json":
            export_json()
        
        elif choice == "export_csv":
            export_csv()

        elif choice == "export_portable":
            export_portable()

        elif choice == "import_csv":
            filename = input("Enter CSV filename to import: ").strip()
            import_csv(f"{filename}.csv", encrypted_entries, vault_key)

        elif choice == "import_json":
            filename = input("Enter JSON filename to import: ").strip()
            import_json(f"{filename}.json", encrypted_entries, vault_key)

        elif choice == "import_portable":
            filename = input("Enter vault filename to import: ").strip()
            import_portable(f"{filename}.vault", encrypted_entries, vault_key)

        else:
            print("Invalid Choice")

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)

    main()