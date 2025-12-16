import base64
from cryptography.fernet import Fernet
from argon2.low_level import hash_secret_raw, Type
from config import *

def derive_key(pw: bytes, salt: bytes) -> bytes:
    """
    Derive a symmetric encryption key from a password and salt using Argon2id.

    Applies the Argon2id password hashing function to produce a fixed-length,
    cryptographically strong key suitable for use with Fernet encryption.

    Args:
        pw: Master password as raw bytes.
        salt: Cryptographic salt as raw bytes.

    Returns:
        A URL-safe base64-encoded 32-byte key.

    Raises:
        ValueError: If the password or salt is invalid.
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
    return base64.urlsafe_b64encode(key)

def encrypt(text: str, key: bytes) -> str:
    """
    Encrypt a plaintext string using Fernet symmetric encryption.

    Args:
        text: Plaintext message to encrypt.
        key: A valid Fernet key.

    Returns:
        A URL-safe base64-encoded Fernet token.
    """
    return Fernet(key).encrypt(text.encode(UTF8)).decode(UTF8)

def decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a Fernet token back into its original plaintext.

    Args:
        token: Encrypted Fernet token produced by `encrypt`.
        key: The same Fernet key used for encryption.

    Returns:
        The decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the token is invalid,
            tampered with, expired, or the key is incorrect.
    """
    return Fernet(key).decrypt(token.encode(UTF8)).decode(UTF8)