# Password Manager v3 — Zero Cache
import os, json, getpass, base64, uuid, pendulum, time, threading, pyperclip, atexit
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "passwords3.json"
ITERATIONS = 1_000_000
KEY_CHECK_STRING = "MasterKeyValidation"
DT_FORMAT = "MMM D, YYYY hh:mm:ss A"

def derive_key(pw: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt(text: str, key: bytes) -> str:
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt(token: str, key: bytes) -> bytes:
    return Fernet(key).decrypt(token.encode())

def get_entry_data(entries: dict, key: bytes, eid: str):
    data = {}
    try:
        data = json.loads(decrypt(entries[eid], key).decode()) 
    except KeyError:
        print("Not found.")
    except:
        print("Entry may be corrupted, cannot view.")

    return data 
    
def display_entry(entries: dict, key: bytes, eid: str, show_password: bool = False) -> int:
    data = get_entry_data(entries, key, eid)
    if data == {}:
        return 1

    print(f"Site         : {data['site']}")
    print(f"Account      : {data.get('account') or ''}")
    if show_password:
        print(f"Password     : {data.get('password') or ''}")
    else:
        print(f"Password     : {'*' * len(data['password']) if data['password'] else ''}")
    print(f"Note         :")
    note = data.get('note', '')
    if note:
        print("-" * 40)
        print(note)
        note = ''
        print("-" * 40)
    print(f"Created      : {pendulum.parse(data['created_date']).format(DT_FORMAT)}")
    print(f"Last Edited  : {pendulum.parse(data['edited_date']).format(DT_FORMAT)}\n")
    data = None
    return 0

def copy_to_clipboard(text: str, timeout: int = 30) -> None:
    """
    Copies text to clipboard and auto-clears after `timeout` seconds
    if the clipboard still contains the original text.
    """
    if not text:
        return

    # Copy to clipboard
    pyperclip.copy(text)
    print(f"Password copied! (auto-clears in {timeout}s)", flush=True)

    if timeout <= 0:
        return

    # Store original text for comparison
    original_text = text

    def auto_clear():
        time.sleep(timeout)
        try:
            # Re-import in thread to avoid issues
            import pyperclip as clippy
            current = clippy.paste()
            if current == original_text:
                pyperclip.copy(40 * "-")
                time.sleep(0.05)
                pyperclip.copy("")
        except Exception:
            # prevent clipboard errors from crashing program
            pass

    # Starts a new thread to clear clipboard. Dies when main program exits
    threading.Thread(target=auto_clear, daemon=True).start()
    return

def force_clear_on_exit():
    try:
        pyperclip.copy(40 * "-")
        time.sleep(0.05)
        pyperclip.copy("")
    except:
        pass

def load_vault(master_pw: str):
    # Create new passwords file if it doesn't exist
    if not os.path.exists(VAULT_FILE):
        print("Creating new password vault...")
        salt = os.urandom(16)
        key = derive_key(master_pw, salt)
        vault = {
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "canary": encrypt(KEY_CHECK_STRING, key),
        "entries": {}
    }

        # Write the new passwords file to disk
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2)

        return key, {}, salt
    
    # Load existing passwords file
    with open(VAULT_FILE, encoding="utf-8") as f:
        vault = json.load(f)

    # Get the current salt and master key
    salt = base64.urlsafe_b64decode(vault["salt"])
    key = derive_key(master_pw, salt)

    # Verify password using the canary (works even if entries is empty)
    if "canary" in vault:
        try:
            if decrypt(vault["canary"], key).decode() != KEY_CHECK_STRING:
                print("Wrong master password!")
                exit()
        except:
            print("Wrong master password!")
            exit()

    encrypted_entries = vault.get("entries", {})

    return key, encrypted_entries, salt

def save_vault(encrypted_entries: dict, salt: bytes, key: bytes):
    vault = {
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "canary": encrypt(KEY_CHECK_STRING, key),
        "entries": encrypted_entries
    }

    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)

    return

def list_entries(encrypted_entries: dict, key: bytes):
    if not encrypted_entries:
        print("Empty vault")
        return
    print("\nYour entries:")
    entries = {}

    for eid, blob in encrypted_entries.items():
        try:
            data = json.loads(decrypt(blob, key).decode())
            entries[eid] = (data['site'], data.get("account", ""))
        except:
            print(f"  {eid} → [corrupted]")
    data = None

    # Sort by site name, then account
    sorted_entries = sorted(
        entries.items(),
        key=lambda entry: (entry[1][0].lower(), entry[1][1].lower())
    )
    for eid, (site, account) in sorted_entries:
        print(f"{eid:>3} → {site:>10} {account}")

    # Clear temp
    entries = {}
    sorted_entries = {}
    return

def search_entries(encrypted_entries: dict, key: bytes):
    if not encrypted_entries:
        print("Empty vault")
        return
    query = input("Enter search term: ").strip().lower()
    if not query:
        print("Empty search — cancelled")
        return
    
    print("\nYour entries:")
    matches = {}

    for eid, blob in encrypted_entries.items():
        try:
            data = json.loads(decrypt(blob, key).decode())
            text = " ".join([
                data.get("site", ""),
                data.get("account", ""),
                data.get("note", ""),
            ]).lower()
            if query in text:
                matches[eid] = (data['site'], data.get("account", ""))
        except:
            print(f"  {eid} → [corrupted]")

    data = None

    # Sort by site name, then account
    sorted_entries = sorted(
        matches.items(),
        key=lambda entry: (entry[1][0].lower(), entry[1][1].lower())
    )
    for eid, (site, account) in sorted_entries:
        print(f"{eid:>3} → {site:>10} {account}")

    # Clear temp
    entries = {}
    sorted_entries = {}
    return

def change_master_password():
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

    # 2. Derive a completely new salt and new key from the new password
    new_salt = os.urandom(16)
    new_key = derive_key(new_pw, new_salt)

    # 3. Re-encrypt every single blob with the new key
    new_encrypted_entries = {}
    for eid, old_blob in temp_entries.items():
        # Decrypt with old key
        plaintext = decrypt(old_blob, temp_key).decode()

        # Encrypt again with new key
        new_blob = encrypt(plaintext, new_key)
        new_encrypted_entries[eid] = new_blob

    # 4. Save with the new salt and new encrypted blobs
    save_vault(new_encrypted_entries, new_salt, new_key)
    print("Master password changed successfully!")

# ── MAIN PROGRAM ─────────────────────────────────────────
def main():
    print("- Ultimate Password Manager —\n")
    master_pw = getpass.getpass("Master password: ").strip()
    key, encrypted_entries, salt = load_vault(master_pw)
    # clears clipboard on exit
    atexit.register(force_clear_on_exit)

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

            password = getpass.getpass("Password: ").strip()

            print("Enter note (press Enter 3x to finish):")
            note = ""
            while True:
                line = input()
                if line == "" and note.endswith("\n\n"):  # two enters in a row
                    break
                note += line + "\n"
            note = note.strip()

            created_date = pendulum.now().to_iso8601_string()

            # create the blob
            entry = json.dumps({"site": site,
                                "account": account,
                                "password": password,
                                "note": note,
                                "created_date": created_date,
                                "edited_date": created_date}, separators=(',', ':'))
            
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

            # ── PRESS C TO COPY ──
            password_shown = False

            while True:
                if not password_shown:
                    action = "(C)opy password  (S)how password  (Enter) skip"
                else:
                    action = "(C)opy password  (Enter) continue"

                print(f"{action}\n", end="> ", flush=True)
                choice_2 = input().strip().lower()

                if choice_2 == "c":
                    pw = get_entry_data(encrypted_entries, key, eid).get("password") or ""
                    copy_to_clipboard(pw, timeout=30)
                    pw = None
                    break

                elif choice_2 == "s" and not password_shown:
                    print(f"ID: {eid}")
                    res = display_entry(encrypted_entries, key, eid, show_password=True)
                    if res != 0:
                        continue
                    password_shown = True

                elif choice_2 in {"", "q", "enter"}:
                    break

                else:
                    print("\rInvalid — press C, S, or Enter           ", end="", flush=True)
                    time.sleep(0.5)
        
        # ── EDIT ENTRY ───────────────────────────────────────
        elif choice == "3":
            eid = input("Enter ID: ").strip().lower()

            res = display_entry(encrypted_entries, key, eid)
            if res != 0:
                continue

            # Ask what to edit
            print("What do you want to update?")
            print("  1. Site")
            print("  2. Account")
            print("  3. Password")
            print("  4. Note")
            print("  5. Everything")
            print("  6. Delete")
            print("  7. Cancel")
            sub = input("> ").strip()

            if sub == "7":
                print("Edit cancelled.")
                continue
            if sub not in ["1", "2", "3", "4", "5", "6"]:
                print("Invalid choice.")
                continue

            data =  get_entry_data(encrypted_entries, key, eid)

            # Delete entry
            if sub == "6":
                confirm = input(f"Are you sure you want to delete entry '{data['site']}'? (y/N): ").strip().lower()
                if confirm == "y":
                    del encrypted_entries[eid]
                    save_vault(encrypted_entries, salt, key)
                    print("Entry deleted.")
                else:
                    print("Delete cancelled.")
                data = None
                continue

            # Get new values
            new_site = data['site']
            new_account = data.get('account') or ''
            new_password = data.get('password') or ''

            if sub in ["1", "5"]:
                new_site = input(f"New site [{new_site}]: ").strip()
                if not new_site:
                    print("Site name cannot be empty!")
                    continue
            if sub in ["2", "5"]:
                new_account = input(f"New account [{new_account or '(none)'}]: ").strip()
            if sub in ["3", "5"]:
                new_password = getpass.getpass("New password: ").strip()
            if sub in ["4", "5"]:
                print("Enter new note (press Enter 3x to finish):")
                note = ""
                while True:
                    line = input()
                    if line == "" and note.endswith("\n\n"):  # three enters in a row
                        break
                    note += line + "\n"
                note = note.strip()
                data['note'] = note
            
            # Update timestamps
            now_iso = pendulum.now().to_iso8601_string()
            data.update({
                "site": new_site,
                "account": new_account,
                "password": new_password,
                "edited_date": now_iso
            })

            # Re-encrypt and save
            new_blob = encrypt(json.dumps(data, separators=(',', ':')), key)
            encrypted_entries[eid] = new_blob
            save_vault(encrypted_entries, salt, key)
            data = None

            print(f"\nUpdated successfully!")

        # ── LIST SITES ─────────────────────────────────────────
        elif choice == "4":
            list_entries(encrypted_entries, key)

        # ── SEARCH ───────────────────────────────────────────────
        elif choice == "5":
            search_entries(encrypted_entries, key)

        # ── CHANGE MASTER PW ───────────────────────────────────────────────
        elif choice == "6":
            change_master_password()

        # ── QUIT ───────────────────────────────────────────────
        elif choice == "7":
            pyperclip.copy("")
            print("Goodbye!")
            break

if __name__ == "__main__":
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        os.system("pip install --quiet cryptography")
        from cryptography.fernet import Fernet
    main()