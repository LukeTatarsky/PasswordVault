# Lazy Password Manager
# A simple command-line password manager with encryption.
import os, json, getpass, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "passwords.json"
ITERATIONS = 1_000_000

def derive_key(pw: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def encrypt(text: str, key: bytes) -> str:
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()

def load_vault(master_pw: str):
    if not os.path.exists(VAULT_FILE):
        print("Creating new vault...")
        salt = os.urandom(16)
        key = derive_key(master_pw, salt)
        vault = {"salt": base64.urlsafe_b64encode(salt).decode(), "data": {}}
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2)
        try: os.chmod(VAULT_FILE, 0o600)
        except: pass
        return key, {}, salt

    with open(VAULT_FILE) as f:
        vault = json.load(f)
        print(vault)

    salt = base64.urlsafe_b64decode(vault["salt"])
    key = derive_key(master_pw, salt)

    if vault["data"]:
        try: decrypt(next(iter(vault["data"].values())), key)
        except: print("Wrong master password!"); exit()

    return key, vault["data"], salt

def save_vault(data: dict, salt: bytes):
    vault = {"salt": base64.urlsafe_b64encode(salt).decode(), "data": data}
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2)
    try: os.chmod(VAULT_FILE, 0o600)
    except: pass

def deterministic_tag(data: str, key: bytes) -> str:
    # HMAC-SHA256 is deterministic and safe to use as a lookup tag
    import hmac, hashlib
    return base64.urlsafe_b64encode(hmac.new(key, data.encode(), hashlib.sha256).digest()).decode()

def main():
    print("-Ultimate Password Manager-\n")
    master_pw = getpass.getpass("Master password: ").strip()

    key, encrypted_data, salt = load_vault(master_pw)

    while True:
        print("\n1. Add/Update  2. Get  3. List  4. Delete  5. Quit")
        c = input("> ").strip()

        if c == "1":
            site = input("Site: ").strip()
            if site in encrypted_data:
                print("Password exists, Would you like to update it? (y/n)")
                if input("> ").strip().lower() != "y":
                    continue

            pw = getpass.getpass("Password: ")
            encrypted_data[site] = encrypt(pw, key)
            save_vault(encrypted_data, salt)
            print("Saved")

        elif c == "2":
            site = input("Site: ").strip()
            if site in encrypted_data:
                print(f"Password → {decrypt(encrypted_data[site], key)}")
            else:
                print("Not found")

        elif c == "3":
            sites = sorted(encrypted_data.keys())
            print("Sites:", ", ".join(sites) if sites else "none")

        elif c == "4":
            site = input("Site to delete: ").strip()
            if site in encrypted_data:
                del encrypted_data[site]
                save_vault(encrypted_data, salt)
                print("Deleted")
            else:
                print("Not found")

        elif c == "5":
            print("Goodbye!")
            break

if __name__ == "__main__":
    try: from cryptography.fernet import Fernet
    except ImportError:
        os.system("pip install --quiet cryptography")
    main()