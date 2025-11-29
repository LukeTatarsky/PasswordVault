# Password Manager v3 — Zero Cache
import os, json, getpass, base64, uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "passwords3.json"
ITERATIONS = 1_000_000

def derive_key(pw: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt(text: str, key: bytes) -> str:
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt(token: str, key: bytes) -> bytes:
    return Fernet(key).decrypt(token.encode())

def load_vault(master_pw: str):
    if not os.path.exists(VAULT_FILE):
        print("Creating new vault...")
        salt = os.urandom(16)
        key = derive_key(master_pw, salt)
        vault = {"salt": base64.urlsafe_b64encode(salt).decode(), "entries": {}}
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2)
        try: os.chmod(VAULT_FILE, 0o600)
        except: pass
        return key, {}, salt

    with open(VAULT_FILE, encoding="utf-8") as f:
        vault = json.load(f)

    salt = base64.urlsafe_b64decode(vault["salt"])
    key = derive_key(master_pw, salt)

    entries = vault.get("entries", {})
    if entries:
        sample = next(iter(entries.values()))
        try:
            decrypt(sample, key)  # test one decryption
        except:
            print("Wrong master password!")
            exit()

    return key, entries, salt

def save_vault(entries: dict, salt: bytes):
    vault = {"salt": base64.urlsafe_b64encode(salt).decode(), "entries": entries}
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)
    try: os.chmod(VAULT_FILE, 0o600)
    except: pass

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

    # 2. Derive a completely NEW salt and NEW key from the new password
    new_salt = os.urandom(16)
    new_key = derive_key(new_pw, new_salt)

    # 3. Re-encrypt every single blob with the new key
    new_entries = {}
    for eid, old_blob in temp_entries.items():
        # Decrypt with old key
        plaintext = decrypt(old_blob, temp_key).decode()
        # Encrypt again with new key
        new_blob = encrypt(plaintext, new_key)
        new_entries[eid] = new_blob

    # 4. Save with the new salt and new encrypted blobs
    save_vault(new_entries, new_salt)
    print("Master password changed successfully!")

def main():
    print("- Ultimate Password Manager —\n")
    master_pw = getpass.getpass("Master password: ").strip()
    key, encrypted_entries, salt = load_vault(master_pw)

    while True:
        print("\n1. Add/Update   2. Get   3. List Sites   4. Delete   5. Change Master PW   6. Quit")
        choice = input("> ").strip()

        # ── ADD / UPDATE ─────────────────────────────────────
        if choice == "1":
            site = input("Site: ").strip()
            if not site:
                print("Site name cannot be empty!")
                continue
            account = input("Account (optional): ").strip()

            # Look for existing entry with same site + account
            for eid, blob in encrypted_entries.items():
                try:
                    data = json.loads(decrypt(blob, key).decode())
                    if (data["site"].lower() == site.lower() and
                        data.get("account", "") == account):
                        existing_id = eid
                        existing_site_display = data["site"]
                        if account:
                            existing_site_display += f" ({account})"
                        break
                except:
                    continue
            if existing_id:
                print(f"\nEntry already exists, overwrite? (y/n):")
                overwrite = input("> ").strip().lower()
                if overwrite != "y":
                    continue

            password = getpass.getpass("Password: ").strip()
            if not password:
                print("Password cannot be empty!")
                continue
            

            entry = json.dumps({"site": site, "account": account, "password": password}, separators=(',', ':'))
            encrypted_blob = encrypt(entry, key)
            entry_id = str(uuid.uuid4())[:8]

            encrypted_entries[entry_id] = encrypted_blob
            save_vault(encrypted_entries, salt)
            print(f"Saved → ID: {entry_id}")

        # ── GET PASSWORD ───────────────────────────────────────
        elif choice == "2":
            query = input("Enter ID: ").strip().lower()
            found = False
            corrupted = False
            for eid, blob in encrypted_entries.items():
                try:
                    plain = decrypt(blob, key).decode()
                    data = json.loads(plain)     
                except:
                    # print(f"  [corrupted entry] → {eid}")
                    corrupted = True
                    continue

                if query == eid:
                    print(f"\nID: {eid}")
                    print(f"Site   : {data['site']}")
                    print(f"Account  : {data.get('account') or '(none)'}")
                    print(f"Password → {data['password']}")
                    found = True
            data = None
            if not found and not corrupted:
                print("Not found")
            elif not found and corrupted:
                print("may be corrupted")

        # ── LIST SITES ─────────────────────────────────────────
        elif choice == "3":
            if not encrypted_entries:
                print("Empty vault")
                continue
            print("\nYour entries:")
            entries = {}

            for eid, blob in encrypted_entries.items():
                try:
                    data = json.loads(decrypt(blob, key).decode())
                    account = f" ({data.get('account')})" if data.get('account') else ""
                    entries[eid] = (data['site'], account)
                    # print(f"  {eid} → {data['site']}{account}")
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

        # ── DELETE ─────────────────────────────────────────────
        elif choice == "4":
            eid = input("Enter ID to delete: ").strip()
            if eid in encrypted_entries:
                # Optional: show what we're deleting
                try:
                    plain = decrypt(encrypted_entries[eid], key).decode()
                    data = json.loads(plain)
                except:
                    site = "(unknown)"
                del encrypted_entries[eid]
                save_vault(encrypted_entries, salt)
                print(f"Deleted → {data['site'], data['account']}")
                data = None
            else:
                print("ID not found")

        # ── CHANGE MASTER PW ───────────────────────────────────────────────
        elif choice == "5":
            change_master_password()

        # ── QUIT ───────────────────────────────────────────────
        elif choice == "6":
            print("Goodbye!")
            break

if __name__ == "__main__":
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        os.system("pip install --quiet cryptography")
        from cryptography.fernet import Fernet
    main()