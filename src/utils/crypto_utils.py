import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type
from config.config_vault import *
from utils.Entry import Entry

def derive_key(pw: bytes, salt: bytes) -> bytes:
    """
    Derive a symmetric encryption key from a password and salt using Argon2id.

    Applies the Argon2id hashing function to produce a fixed-length
    key suitable for use with encryption.

    Args:
        pw: Master password as raw bytes.
        salt: Cryptographic salt as raw bytes.

    Returns:
        A URL-safe base64-encoded 32-byte key.

    Raises:
        ValueError: If the password or salt is invalid.
    
    Security:
        - Argon2id provides resistance to brute force attacks.
        - The derived key is kept in memory only as long as necessary.
        - The salt is not secret but must be unique per vault.
    """
    key = hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=ARGON_HASH_LEN,
        type=Type.ID
    )
    return key

def pepper_pw(pw: bytes, pepper: bytes):
    """
    Hash a password with a pepper using BLAKE2b.

    Args:
        pw: Password string.
        pepper: Secret key used as pepper.

    Returns:
        32-byte hash of password + pepper.

    Security Notes:
        - Uses keyed BLAKE2b (digest size 32).
        - Pepper protects against rainbow table attacks.
    """
    hashed = hashlib.blake2b(
        pw,
        key=pepper,
        digest_size=32
        )
    return hashed.digest()

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
    nonce = secrets.token_bytes(NONCE_LEN)

    ciphertext = aead.encrypt(
        nonce=nonce,
        data=plaintext.encode(UTF8),
        associated_data=str_to_bytes(eid)
    )
    token = nonce + ciphertext
    return base64.urlsafe_b64encode(token).decode(UTF8)

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

    raw = base64.urlsafe_b64decode(token.encode(UTF8))
    nonce = raw[:NONCE_LEN]
    ciphertext = raw[NONCE_LEN:]
    
    plaintext = aead.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=str_to_bytes(eid)
    )
    return plaintext.decode(UTF8)

def decrypt_entry(token: str, key: bytes, eid: str) -> "Entry":
    """
    Decrypt a vault entry token into an Entry object.

    Args:
        token: Base64-encoded encrypted entry.
        key: Symmetric key for ChaCha20Poly1305 decryption.
        eid: Entry ID used as associated data (AEAD).

    Returns:
        Entry object reconstructed from decrypted data.

    Raises:
        Exception if decryption fails or data is invalid.

    Security Notes:
        - Uses AEAD; ensures ciphertext integrity.
    """
    aead = ChaCha20Poly1305(key)
    raw = base64.urlsafe_b64decode(token.encode(UTF8))
    nonce = raw[:NONCE_LEN]
    ciphertext = raw[NONCE_LEN:]
 
    return Entry.from_bytes(aead.decrypt(
        nonce=nonce,
        data=ciphertext,
        associated_data=str_to_bytes(eid))
    )

def encrypt_entry(entry: Entry, key: bytes, eid: str) -> str:
    """
    Encrypt a vault entry into a base64-encoded token.

    Args:
        entry: Entry object to encrypt.
        key: Symmetric key for ChaCha20Poly1305 encryption.
        eid: Entry ID used as associated data (AEAD).

    Returns:
        Base64-encoded token containing nonce + ciphertext.

    Security Notes:
        - Generates a new random nonce for each encryption.
        - Associated data protects integrity of entry ID.
    """
    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(NONCE_LEN)

    plaintext = entry.to_bytes()

    ciphertext = aead.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=str_to_bytes(eid)
    )
    token = nonce + ciphertext
    return base64.urlsafe_b64encode(token).decode(UTF8)


def str_to_bytes(eid_str: str) -> bytes:
    """
    Decode a URL-safe base64 string into bytes.

    Args:
        eid_str: Base64 string (may omit padding).

    Returns:
        Decoded bytes.

    Raises:
        binascii.Error if input is invalid.
    """
    padding = "=" * (-len(eid_str) % 4)
    return base64.urlsafe_b64decode(eid_str + padding)


def bytes_to_str(byt_str: bytes) -> str:
    """
    Encode bytes into a URL-safe base64 string without padding.

    Args:
        byt_str: Raw bytes to encode.

    Returns:
        Base64-encoded string.
    """
    return base64.urlsafe_b64encode(byt_str).decode("ascii").rstrip("=")