import ctypes
from ctypes import wintypes
"""
TPM-backed cryptographic helpers.

This module provides a thin wrapper around Windows NCrypt APIs to encrypt
and decrypt small secrets using a persistent, TPM-backed RSA key.

Trust boundaries:
- The private key material is generated, stored, and used entirely inside
  the TPM and is never accessible to user-space software.
- Encrypted blobs may be stored on disk, but can only be decrypted on the
  same device where the TPM key exists.
- This module does NOT protect against a compromised operating system or
  malware executing with the current user's privileges. Documented in README.
- TPM protection is intended to bind vault secrets to a specific device,
  not to replace a strong master password.

Failure behavior:
- TPM key creation may fail if the key already exists or TPM support is
  unavailable.
- Encryption or decryption failures indicate that the TPM key is missing,
  inaccessible, or unsupported on the current system.

This module is Windows-specific and requires a compatible TPM and the
Microsoft Platform Crypto Provider.
"""
ncrypt = ctypes.WinDLL("ncrypt.dll")

PROVIDER = "Microsoft Platform Crypto Provider"
KEY_NAME = "PW_VAULT_KEY"
BCRYPT_RSA_ALGORITHM = "RSA"

NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
NCRYPT_SILENT_FLAG = 0x00000040
BCRYPT_PAD_OAEP = 0x00000004

class BCRYPT_OAEP_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", wintypes.LPCWSTR),
        ("pbLabel", ctypes.c_void_p),
        ("cbLabel", wintypes.DWORD),
    ]

def check(status):
    """
    Raise an exception if an NCrypt call failed.

    Args:
        status: Return code from an NCrypt API call.

    Raises:
        OSError: If the status code indicates an error.
    """
    if status != 0:
        raise OSError(f"NCrypt error: 0x{status & 0xffffffff:08X}")


def create_tpm_key():
    """
    Create a persistent RSA key backed by the system TPM.

    If the key already exists, creation may fail and should be handled
    by the caller.
    """
    provider = wintypes.HANDLE()
    check(ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(provider),
        PROVIDER,
        0
    ))

    key = wintypes.HANDLE()
    check(ncrypt.NCryptCreatePersistedKey(
        provider,
        ctypes.byref(key),
        BCRYPT_RSA_ALGORITHM,
        KEY_NAME,
        0,
        0
    ))
    check(ncrypt.NCryptFinalizeKey(key, 0))


def tpm_encrypt(data: bytes) -> bytes:
    """
    Encrypt data using the TPM-backed RSA key.

    Args:
        data: Plaintext bytes to encrypt.

    Returns:
        Encrypted byte blob.

    Raises:
        OSError: If the TPM key cannot be accessed or encryption fails.
    """
    provider = wintypes.HANDLE()
    check(ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(provider),
        PROVIDER,
        0
    ))

    key = wintypes.HANDLE()
    check(ncrypt.NCryptOpenKey(
        provider,
        ctypes.byref(key),
        KEY_NAME,
        0,
        NCRYPT_SILENT_FLAG
    ))

    padding = BCRYPT_OAEP_PADDING_INFO("SHA256", None, 0)

    in_buf = ctypes.create_string_buffer(data)
    out_len = wintypes.DWORD()

    check(ncrypt.NCryptEncrypt(
        key,
        in_buf,
        len(data),
        ctypes.byref(padding),
        None,
        0,
        ctypes.byref(out_len),
        BCRYPT_PAD_OAEP
    ))

    out = ctypes.create_string_buffer(out_len.value)

    check(ncrypt.NCryptEncrypt(
        key,
        in_buf,
        len(data),
        ctypes.byref(padding),
        out,
        out_len,
        ctypes.byref(out_len),
        BCRYPT_PAD_OAEP
    ))

    return out.raw


def tpm_decrypt(blob: bytes) -> bytes:
    """
    Decrypt data using the TPM-backed RSA key.

    Args:
        blob: Encrypted data produced by `tpm_encrypt`.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        OSError: If the TPM key cannot be accessed or decryption fails.
    """
    provider = wintypes.HANDLE()
    check(ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(provider),
        PROVIDER,
        0
    ))

    key = wintypes.HANDLE()
    check(ncrypt.NCryptOpenKey(
        provider,
        ctypes.byref(key),
        KEY_NAME,
        0,
        NCRYPT_SILENT_FLAG
    ))

    padding = BCRYPT_OAEP_PADDING_INFO("SHA256", None, 0)

    in_buf = ctypes.create_string_buffer(blob)
    out_len = wintypes.DWORD()

    check(ncrypt.NCryptDecrypt(
        key,
        in_buf,
        len(blob),
        ctypes.byref(padding),
        None,
        0,
        ctypes.byref(out_len),
        BCRYPT_PAD_OAEP
    ))

    out = ctypes.create_string_buffer(out_len.value)

    check(ncrypt.NCryptDecrypt(
        key,
        in_buf,
        len(blob),
        ctypes.byref(padding),
        out,
        out_len,
        ctypes.byref(out_len),
        BCRYPT_PAD_OAEP
    ))

    return out.raw[:out_len.value]


'''
Error list

0x80090029  NTE_NOT_SUPPORTED 
0x80090026  NTE_INVALID_HANDLE
0x8009000D  NTE_BAD_KEY
0x80090011  NTE_NO_KEY
0x80090016 NTE_BAD_KEYSET - The TPM key does not exist.
0x8009000F NTE_EXISTS - The key already exists.


'''