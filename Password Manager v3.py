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

def main():
    print("- Ultimate Password Manager —\n")
    master_pw = getpass.getpass("Master password: ").strip()
    key, encrypted_entries, salt = load_vault(master_pw)

    while True:
        print("\n1. Add/Update   2. Get   3. List Sites   4. Delete   5. Quit")
        choice = input("> ").strip()

        # ── ADD / UPDATE ─────────────────────────────────────
        if choice == "1":
            site = input("Site: ").strip()
            account = input("Account (optional): ").strip()
            password = getpass.getpass("Password: ").strip()

            entry = json.dumps({"site": site, "account": account, "password": password}, separators=(',', ':'))
            encrypted_blob = encrypt(entry, key)
            entry_id = str(uuid.uuid4())[:8]

            encrypted_entries[entry_id] = encrypted_blob
            save_vault(encrypted_entries, salt)
            print(f"Saved → ID: {entry_id}")

        # ── GET PASSWORD ───────────────────────────────────────
        elif choice == "2":
            query = input("Search by site name or ID: ").strip().lower()
            found = False
            for eid, blob in encrypted_entries.items():
                try:
                    plain = decrypt(blob, key).decode()
                    data = json.loads(plain)
                except:
                    print(f"  [corrupted] → {eid}")
                    continue  # corrupted entry

                if query == eid or query in data["site"].lower():
                    print(f"\nID: {eid}")
                    print(f"Site   : {data['site']}")
                    print(f"Account  : {data.get('account') or '(none)'}")
                    print(f"Password → {data['password']}")
                    found = True
                    
            if not found:
                print("Not found")

        # ── LIST SITES ─────────────────────────────────────────
        elif choice == "3":
            if not encrypted_entries:
                print("Vault is empty.")
                continue

            print("\nYour accounts:")
            for eid, blob in encrypted_entries.items():
                try:
                    plain = decrypt(blob, key).decode()
                    data = json.loads(plain)
                except:
                    print(f"  [corrupted] → {eid}")
                    continue

                account = f" ({data.get('account')})" if data.get('account') else ""
                print(f"  • {data['site']}{account} → ID: {eid}")

        # ── DELETE ─────────────────────────────────────────────
        elif choice == "4":
            eid = input("Enter ID to delete: ").strip()
            if eid in encrypted_entries:
                # Optional: show what we're deleting
                try:
                    plain = decrypt(encrypted_entries[eid], key).decode()
                    site = json.loads(plain)["site"]
                except:
                    site = "(unknown)"
                del encrypted_entries[eid]
                save_vault(encrypted_entries, salt)
                print(f"Deleted → {site}")
            else:
                print("ID not found")

        # ── QUIT ───────────────────────────────────────────────
        elif choice == "5":
            print("Goodbye!")
            break

if __name__ == "__main__":
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        os.system("pip install --quiet cryptography")
        from cryptography.fernet import Fernet
    main()