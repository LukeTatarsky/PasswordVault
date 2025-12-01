# MyVault Password Manager v3
# Local password manager with strong encryption and random password generation.
import os, json, getpass, base64, uuid, pendulum, time, threading, pyperclip, atexit
import string, secrets, re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "password_vault.json"
ITERATIONS = 1_000_000
KEY_CHECK_STRING = "MasterKeyValidation"
DT_FORMAT = "MMM D, YYYY hh:mm:ss A"

# Industry standard password defaults
PASS_DEFAULTS = {
        "length":          20,
        "min_lower":       4,
        "min_upper":       3,
        "min_digits":      3,
        "min_symbols":     3,
        "avoid_ambiguous": True,
        "max_consecutive": 1,   # no more than x same chars in a row
        "ambiguous_chars": "lI1O08",
        "symbols_pool":   "!@#()[]|?$%^*_-+.,=",
        "bank_safe_symbols":   "!@#$%^*_-+=",
    }

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

def max_consecutive_chars(pw: str) -> int:
    """
    Check to see if there are too many consecutive identical characters.
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
    Ensures user inputs a valid integer.
    """
    while True:
        val = input(prompt).strip()
        if val == "" and default is not None:
            return default
        if re.fullmatch(r"\d+", val):
            return int(val)
        print("   Invalid — numbers only")

def random_password(length: int = PASS_DEFAULTS["length"],
    min_upper: int = PASS_DEFAULTS["min_upper"],
    min_lower: int = PASS_DEFAULTS["min_lower"],
    min_nums: int = PASS_DEFAULTS["min_digits"],
    min_syms: int = PASS_DEFAULTS["min_symbols"], 
    avoid_ambig = PASS_DEFAULTS["avoid_ambiguous"]) -> str:
    """
    Generate a strong random password.
    Uses secrets module → cryptographically secure.
    """
    if length < (min_upper + min_lower + min_nums + min_syms):
        raise ValueError(f"Length {length} too short for requirements")

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

    # Add a bit more weight to lower case letter and create a pool 
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

    # Step 3: Shuffle so required chars aren't clumped at start
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
        print("   • Type 'g' → generate strong 20-char password")
        print("   • Type 'c' → generate customizable random password")
        print("   • Press Enter to type your own")
        choice = input(" → ").strip().lower()

        if choice == "":
            pw = getpass.getpass("Enter password (min length = 8): ").strip()
            if len(pw) < 8:
                print("   Password too short, try again.")
                continue
            return pw

        elif choice in {"g", "gen", "generate"}:
            pw = random_password(20)
            print(f"   Generated: {pw} \a")

            accept = input("\n   Accept this password? (y/n): ").strip().lower()
            if accept != "y":
                pw = ''
                continue

            copy = input("   Copy to clipboard? (y/n): ").strip().lower()
            if copy == "y":
                copy_to_clipboard(pw, timeout=60)

            return pw

        elif choice in {"c", "custom", "customizable"}:
            pw_len = get_int("\n   Enter desired length (minimum 14, default 20): ")
            if pw_len < 14:
                print("   Length too short, using 20.")
                pw_len = 20
            min_upper = get_int("\n   Minimum upper case: ")
            min_nums = get_int("\n   Minimum numbers: ")
            min_symb = get_int("\n   Minimum symbols: ")

            if pw_len < (min_upper + min_nums + min_symb):
                print("   Requirements exceed length, try again.")
                continue
            pw = random_password(pw_len, min_upper, min_nums, min_symb)
            print(f"\n   Generated: {pw}")

            accept = input("\n   Accept this password? (y/n): ").strip().lower()
            if accept != "y":
                pw = ''
                continue

            copy = input("   Copy to clipboard? (y/n): ").strip().lower()
            if copy == "y":
                copy_to_clipboard(pw, timeout=30)

            return pw
        else:
            print("Invalid — press Enter, 'g', or 's'")
    

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
    matches = {}
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

            password = ask_password("New password")

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