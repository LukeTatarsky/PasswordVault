import base64
from typing import List, Tuple, Dict
import pendulum, json, secrets
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from utils.Entry import Entry
from config.config_vault import *


# Argon2id KDF to derive the root key from the master password
def derive_root_key(password: bytes, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=ARGON_HASH_LEN,
        iterations=ARGON_TIME,
        lanes=ARGON_PARALLELISM,
        memory_cost=ARGON_MEMORY,
        )
    return kdf.derive(password)


# HKDF to derive keys based on input material
def derive_key(key: bytes,*, info: bytes = b'', salt: bytes = b'', length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=SHA3_512(),
        length=length,
        salt=salt,
        info=info
    )
    return hkdf.derive(key)

def str_to_bytes(eid_str: str) -> bytes:
    """
    Decode a URL-safe base64 string into bytes.
    """
    padding = "=" * (-len(eid_str) % 4)
    return base64.urlsafe_b64decode(eid_str + padding)


def encrypt_entry(entry: Entry, entry_key: bytes) -> bytes:
    """
    Encrypts the entire Entry object and returns a single ciphertext blob (bytes)
    using ChaCha20-Poly1305.

    - entry: Entry dataclass instance
    - entry_key: 32-byte key derived via HKDF from vault/entry key
    """
    # Convert dataclass to dictionary, excluding ephemeral _fields if desired
    # Here we include _fields because it already contains field-level ciphertext
    entry_dict = entry.to_dict()

    # Serialize to canonical JSON bytes
    plaintext_bytes = json.dumps(entry_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # Generate random 12-byte nonce
    nonce = secrets.token_bytes(NONCE_LEN)

    # Use entry_id as AAD to bind ciphertext to this entry
    aad = str_to_bytes(entry.entry_id)

    # Encrypt
    aead = ChaCha20Poly1305(entry_key)
    ciphertext = aead.encrypt(nonce, plaintext_bytes, aad)

    # Prepend or return as combined blob: nonce + ciphertext
    # (Nonce is required for decryption)
    return nonce + ciphertext


def decrypt_entry(cipher_blob: bytes, entry_key: bytes, entry_id: str) -> Entry:
    """
    Decrypts bytes produced by encrypt_entry_object and returns an Entry object.
    
    Args:
        cipher_blob: bytes from encrypt_entry_object (nonce + ciphertext)
        entry_key: 32-byte ChaCha20-Poly1305 key
        entry_id: used as AAD for authentication

    Returns:
        Entry object
    """
    # Split nonce and ciphertext
    nonce = cipher_blob[:12]
    ciphertext = cipher_blob[12:]

    # Decrypt
    aead = ChaCha20Poly1305(entry_key)
    # e_id = entry_id.encode("utf-8")
    plaintext_bytes = aead.decrypt(nonce, ciphertext, str_to_bytes(entry_id))

    # Parse JSON
    entry_dict = json.loads(plaintext_bytes.decode("utf-8"))

    # Convert _fields base64 strings back to bytes
    fields_bytes = {}
    for fname, data in entry_dict["_fields"].items():
        fields_bytes[fname] = {
            "nonce": base64.b64decode(data["nonce"]),
            "ciphertext": base64.b64decode(data["ciphertext"]),
            "salt":base64.b64decode(data["salt"]),
        }
    entry_dict["_fields"] = fields_bytes

    # Reconstruct Entry object
    return Entry.from_dict(entry_dict)

def encrypt(plaintext: str, key: bytes, eid: str) -> str:
    """
    Encrypt plaintext using ChaCha20-Poly1305 with associated data.

    A random nonce is generated for each encryption. The entry identifier
    (eid) is bound to the ciphertext as associated data.

    The returned value is a URL-safe base64 encoded string containing the nonce
    followed by the ciphertext and authentication tag.

    Args:
        plaintext: Plaintext string to encrypt.
        key: Symmetric encryption key derived from the master password.
            Must be 32 bytes in length.
        eid: Entry id used as associated data. eid is bound to ciphertext.

    Returns:
        A URL-safe base64 encoded string representing the encrypted payload.

    Raises:
        ValueError: If the key length is invalid.
        Exception: Propagates unexpected encryption errors.

    Security:
        - Uses ChaCha20-Poly1305 AEAD.
        - Nonces are generated randomly and must never be reused with the same key.
        - Associated data binds ciphertext to eid.
    """

    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)

    ciphertext = aead.encrypt(
        nonce=nonce,
        data=plaintext.encode('utf-8'),
        associated_data=str_to_bytes(eid)
    )
    token = nonce + ciphertext
    return base64.urlsafe_b64encode(token).decode('utf-8')

def decrypt(token: str, key: bytes, eid: str) -> str:
    """
    Decrypt a ChaCha20-Poly1305 encrypted payload.

    The function authenticates both the ciphertext and the associated data
    (eid). Any modification to the token, nonce, ciphertext, or associated
    data will cause decryption to fail.

    Args:
        token: URL-safe base64 encoded encrypted payload produced by `encrypt`.
        key: Symmetric encryption key derived from the master password.
            Must be identical to the key used during encryption.
        eid: Entry identifier used as associated data. Must match the value
            supplied during encryption.

    Returns:
        The decrypted plaintext string.

    Raises:
        InvalidTag: If authentication fails due to an incorrect key,
            corrupted ciphertext, or mismatched associated data.
        ValueError: If the token is malformed or too short.
        Exception: Propagates unexpected decryption errors.

    Security:
        - Authentication is verified before plaintext is released.
        - A failed decryption indicates tampering or incorrect credentials.
        - No partial plaintext is returned on failure.
    """

    aead = ChaCha20Poly1305(key)

    raw = base64.urlsafe_b64decode(token.encode('utf-8'))
    nonce = raw[:12]
    ciphertext = raw[12:]
    
    plaintext = aead.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=str_to_bytes(eid)
    )
    return plaintext.decode('utf-8')