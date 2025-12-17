import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type
from config.config_vault import *

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


def str_to_bytes(eid_str: str) -> bytes:
    """Converts string to bytes"""
    padding = "=" * (-len(eid_str) % 4)
    return base64.urlsafe_b64decode(eid_str + padding)

def bytes_to_str(byt_str: bytes) -> str:
    """Converts secrets bytes to str"""
    return base64.urlsafe_b64encode(byt_str).decode("ascii").rstrip("=")