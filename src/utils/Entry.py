import secrets
import sys
import pendulum
import base64
from dataclasses import dataclass, field
from contextlib import contextmanager
from typing import Dict, Iterator, List, Tuple, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA3_512
from config.config_vault import SALT_LEN, NONCE_LEN



# -----------------------------
# Field crypto helpers
# -----------------------------
def decrypt_field(enc: Dict[str, bytes], field_key: bytes, entry_id: str, field_name: str) -> bytearray:
    aad = f"entry:{entry_id}:field:{field_name}:v1".encode()
    aead = ChaCha20Poly1305(field_key)
    plaintext = aead.decrypt(enc["nonce"], enc["ciphertext"], aad)
    return bytearray(plaintext)


def wipe_bytes(b: bytearray):
    for i in range(len(b)):
        b[i] = 0

# -----------------------------
# Dataclass
# -----------------------------
@dataclass
class Entry:
    """
    Represents a single vault entry.

    Stores account metadata, secrets, password history, and auxiliary fields
    associated with a site.
    """
    site: str
    entry_id: str

    account: str = ''
    note: str = ''

    # Encrypted fields
    _fields: Dict[str, Dict[str, bytes]] = field(default_factory=dict)
    test_attr: Any = ''
    pw_hist: List[Tuple[str, str]] = field(default_factory=list)

    # Other is used to save any other fields when importing data into password vault.
    other: Dict[str, str] = field(default_factory=dict)
    
    # Timestamps
    created: str = field(default_factory=lambda: pendulum.now().to_iso8601_string())
    edited: str = field(default_factory=lambda: pendulum.now().to_iso8601_string())

    def __post_init__(self): # logic after the built-in __init__ method has been called.
        """
        Validate and normalize required fields.

        Ensures the site field is a non-empty string.
        """
        if not isinstance(self.site, str):
            raise TypeError("Site must be a string")
        
        self.site = self.site.strip()
        if not self.site:
            raise ValueError("Site cannot be empty")
        
    def __repr__(self):
        return (
            f"Entry(site={self.site}, "
            f"account={self.account}, "
            f"pw=<hidden>, "
            f"pw_hist_len={len(self.pw_hist)}, "
            f"created={self.created}, "
            f"edited={self.edited})"
        )
    def __del__(self):
        """
        Best-effort cleanup of sensitive data.
        """
        try:
            if hasattr(self, "_fields"):
                self._fields.clear()
                del self._fields
            if hasattr(self, "pw_hist"):
                self.pw_hist.clear()
                del self.pw_hist
            if hasattr(self, "other"):
                self.other.clear()
                del self.other
            for attr in ["site", "entry_id", "account", "note", "created", "edited"]:
                if hasattr(self, attr):
                    setattr(self, attr, None)
        except Exception:
            # no errors in __del__ allowed
            pass
    # -------------------
    # Field key derivation
    # -------------------
    def _derive_field_key(self, entry_key: bytes, field_name: str, salt: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=SHA3_512(),
            length=32,
            salt=salt,
            info=f"field key:{field_name}".encode(),
        )
        return hkdf.derive(entry_key)

    # -------------------
    # Generic field access
    # -------------------
    # Set a field (encrypt and store)
    def set_field(self, field_name: str, value: bytearray, entry_key: bytes, new_eid: str = ''):
        if not isinstance(value, bytearray):
            raise TypeError("Field value must be a bytearray")
        salt = secrets.token_bytes(SALT_LEN)
        field_key = self._derive_field_key(entry_key, field_name, salt)
        nonce = secrets.token_bytes(NONCE_LEN)
        if new_eid:
            aad = f"entry:{new_eid}:field:{field_name}:v1".encode()
        else:
            aad = f"entry:{self.entry_id}:field:{field_name}:v1".encode()
        aead = ChaCha20Poly1305(field_key)
        ciphertext = aead.encrypt(nonce, value, aad)
        wipe_bytes(value)
        self._fields[field_name] = {"nonce": nonce, "ciphertext": ciphertext, "salt": salt}

    # Ephemeral decrypt: yields a bytearray and wipes it automatically
    @contextmanager
    def get_field(self, field_name: str, entry_key: bytes, old_entry_id: str = '') -> Iterator[bytearray]:
        if field_name not in self._fields:
            raise KeyError(f"Field {field_name} does not exist")
        data = self._fields[field_name]
        field_key = self._derive_field_key(entry_key, field_name, data["salt"])
        if old_entry_id != '':
            # used when changing password
            decrypted = decrypt_field(self._fields[field_name], field_key, old_entry_id, field_name)
        else: 
            decrypted = decrypt_field(self._fields[field_name], field_key, self.entry_id, field_name)
        try:
            yield decrypted
        finally:
            wipe_bytes(decrypted)

    def field_exists(self, field_name: str):
        '''
        Checks to see if fiel_name exists in _fields
        '''
        if field_name not in self._fields:
            return False
        return True

    # Convenience methods
    def set_password(self, value: bytearray, entry_key: bytes):
        self.set_field("password", value, entry_key)
    
    def rm_password(self):
        self._fields.pop('password')

    @contextmanager
    def get_password(self, entry_key: bytes) -> Iterator[bytearray]:
        with self.get_field("password", entry_key) as pw:
            yield pw

    def set_totp(self, value: bytearray, entry_key: bytes):
        self.set_field("totp", value, entry_key)
    
    def rm_totp(self):
        self._fields.pop('totp')

    @contextmanager
    def get_totp(self, entry_key: bytes) -> Iterator[bytearray]:
        with self.get_field("totp", entry_key) as totp:
            yield totp

    def set_rec_keys(self, value: bytearray, entry_key: bytes):
        self.set_field("rec_keys", value, entry_key)

    def rm_rec_keys(self):
        self._fields.pop('rec_keys')

    @contextmanager
    def get_rec_keys(self, entry_key: bytes) -> Iterator[bytearray]:
        with self.get_field("rec_keys", entry_key) as rec_keys:
            yield rec_keys

    def to_dict(self) -> dict:
        """
        Custom serialization:
        - Converts all bytes in _fields to base64 strings
        """
        serialized_fields = {}
        for fname, data in self._fields.items():
            serialized_fields[fname] = {
                "nonce": base64.b64encode(data["nonce"]).decode("ascii"),
                "ciphertext": base64.b64encode(data["ciphertext"]).decode("ascii"),
                "salt": base64.b64encode(data["salt"]).decode("ascii")
            }

        return {
            "entry_id": self.entry_id,
            "site": self.site,
            "note": self.note,
            "account": self.account,
            "_fields": serialized_fields,
            "pw_hist": self.pw_hist,
            "other": self.other,
            "created": self.created,
            "edited": self.edited
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        """
        Reconstruct an Entry object from a dictionary produced by to_dict().

        - Decodes base64-encoded bytes in _fields
        - Does NOT decrypt any secret material
        - Restores metadata verbatim
        """
        # Decode encrypted fields back into bytes
        fields = {}
        for fname, enc in data.get("_fields", {}).items():
            fields[fname] = {
                "nonce": enc["nonce"],
                "ciphertext": enc["ciphertext"],
                "salt": enc["salt"],
            }

        return cls(
            entry_id=data["entry_id"],
            site=data["site"],
            account=data.get("account", ""),
            note=data.get("note", ""),
            _fields=fields,
            pw_hist=data.get("pw_hist", []),
            other=data.get("other", {}),
            created=data.get("created", field(default_factory=lambda: pendulum.now().to_iso8601_string())),
            edited=data.get("edited", field(default_factory=lambda: pendulum.now().to_iso8601_string())),
        )
    
    def to_dict_export_plain(self, vault_key: bytes) -> dict:
        """
        Custom serialization for plaintext export:
        - Converts all bytes in _fields to base64 strings
        """
        serialized_fields = {}
        for fname, _ in self._fields.items():
            with self.get_field(fname, vault_key) as fvalue:
                serialized_fields[fname] = fvalue.decode("utf-8")

        return {
            "site": self.site,
            "note": self.note,
            "account": self.account,
            "_fields": serialized_fields,
            "pw_hist": self.pw_hist,
            "other": self.other,
            "created": self.created,
            "edited": self.edited
        }
    
    @classmethod
    def from_dict_export_plain(cls, data: dict, entry_key: bytes, entry_id: bytes) -> "Entry":
        """
        Reconstruct an Entry from plaintext export dictionary and encrypt all fields.
        Args:
            data: dict produced by to_dict_export_plain()
            vault_key: 32-byte vault key used to derive field keys

        Returns:
            Entry object with _fields encrypted and ready for vault storage.
        """

        entry = cls(
            entry_id=bytes_to_str(entry_id),
            site=data.get("site", ""),
            account=data.get("account", ""),
            note=data.get("note", ""),
            _fields={},
            pw_hist=data.get("pw_hist", []),
            other=data.get("other", {}),
            created=data.get("created", pendulum.now().to_iso8601_string()),
            edited=data.get("edited", pendulum.now().to_iso8601_string())
        )

        # Encrypt each plaintext field immediately
        for fname, plaintext_value in data.get("_fields", {}).items():
            if isinstance(plaintext_value, str):
                field_bytes = bytearray(plaintext_value.encode("utf-8"))
                entry.set_field(fname, field_bytes, entry_key)
                wipe_bytes(field_bytes)  # securely wipe temporary bytearray
                del field_bytes

        return entry


# -----------------------------
# Formatting Helper Functions
# -----------------------------
def print_bytearray(secret: bytearray):
    """
    Write a bytearray directly to stdout.

    Side Effects:
        Writes raw bytes to standard output.
    """
    mv = memoryview(secret)
    sys.stdout.buffer.write(mv)
    sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()

def _btArr_to_b64(b: bytearray) -> str:
    """Encode a bytearray as base64."""
    return base64.b64encode(b).decode("ascii")

def _b64_to_btArr(s: str) -> bytearray:
    """Decode base64 string to a bytearray."""
    return bytearray(base64.b64decode(s.encode("ascii")))

def str_to_bytes(eid_str: str) -> bytes:
    """
    Decode a URL-safe base64 string. Used in encryption.

    Args:
        eid_str: Encoded string.

    Returns:
        Decoded bytes.
    """
    padding = "=" * (-len(eid_str) % 4)
    return base64.urlsafe_b64decode(eid_str + padding)


def bytes_to_str(byt_str: bytes) -> str:
    """
    Encode bytes as URL-safe base64 string.

    Args:
        byt_str: Raw bytes.

    Returns:
        Encoded string without padding.
    """
    return base64.urlsafe_b64encode(byt_str).decode("ascii").rstrip("=")