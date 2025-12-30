from dataclasses import dataclass, field
from typing import List, Tuple, Dict
import pendulum, base64, json, sys
from config.config_vault import UTF8

@dataclass
class Entry:
    """
    Represents a single vault entry.

    Stores account metadata, secrets, history, and auxiliary fields
    associated with a site.
    """
    # id: str 
    site: str
    account: str = ''
    note: str = ''

    password: bytearray = field(default_factory=bytearray)
    rec_keys: bytearray = field(default_factory=bytearray)
    totp: bytearray = field(default_factory=bytearray)

    pw_hist: List[Tuple[str, str]] = field(default_factory=list)

    # Used to add any other fields into the entry.
    other: Dict[str, str] = field(default_factory=dict)
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
    
    # def __repr__(self):
    #     return (
    #         f"Entry(\n"
    #         f" site={self.site} \n"
    #         f" account={self.account} \n"
    #         f" pw={self.password} \n"
    #         f" note={self.note} \n"
    #         f" keys={self.rec_keys} \n"
    #         f" totp={self.totp} \n"
    #         f" pw_hist={self.pw_hist} \n"
    #         f" other={self.other} \n"
    #         f" url={self.url} \n"
    #         f" created={self.created} \n"
    #         f" edited={self.edited})"
    #     )
    
    def wipe(self):
        """
        Wipe sensitive buffers in memory.

        Overwrites password-related buffers and clears references.

        Side Effects:
            Modifies and clears secret buffers.
        """
        for buf in (self.password, self.rec_keys, self.totp):
            for i in range(len(buf)):
                buf[i] = 0

    def __del__(self):
        """
        Best-effort cleanup of sensitive data.

        Intended as a fallback; wipe() should be called explicitly.
        """
        try:
            self.wipe()
        except Exception:
            # no errors in __del__ allowed
            pass

    def to_dict(self) -> dict:
        """
        Serialize entry to a dictionary.

        Encodes sensitive fields using base64 for storage.

        Returns:
            Dictionary representation of the entry.
        """
        return {
            "site": self.site,
            "account": self.account,
            "note": self.note,
            "password": _btArr_to_b64(self.password),
            "keys": _btArr_to_b64(self.rec_keys),
            "totp": _btArr_to_b64(self.totp),
            "password_history": [
                (timestamp, secret)
                for timestamp, secret in self.pw_hist
            ],
            "created_date": self.created,
            "edited_date": self.edited,
            "other": dict(self.other),
        }
    def to_dict_export(self) -> dict:
        """
        Serialize entry for plaintext export.

        Decodes secret fields for external use.

        Returns:
            Exportable dictionary representation.

        Security Notes:
            - Secrets are returned in plaintext.
            - Intended for trusted export only.
        """
        return {
            "site": self.site,
            "account": self.account,
            "note": self.note,
            "password": self.password.decode(UTF8, errors="strict"),
            "keys": self.rec_keys.decode(UTF8, errors="strict"),
            "totp": self.totp.decode(UTF8, errors="strict"),
            "password_history": [
                (timestamp, secret)
                for timestamp, secret in self.pw_hist
            ],
            "created_date": self.created,
            "edited_date": self.edited,
            "other": dict(self.other),
        }
    
    def to_bytes(self) -> bytes:
        """
        Serialize entry to compact JSON bytes.

        Returns:
            UTF-8 encoded JSON bytes.
        """
        return json.dumps(
            self.to_dict(),
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_dict_export(cls, data: dict) -> "Entry":
        """
        Create an entry from exported plaintext data.

        Args:
            data: Exported entry data.

        Returns:
            Reconstructed Entry instance.
        """
        if not isinstance(data, dict):
            raise TypeError("Entry data must be a dict")

        entry = cls(
            site=data["site"],
            account=data.get("account", ""),
        )

        entry.note = data.get("note", "")
        entry.password = bytearray(data.get("password", "").encode(UTF8))
        entry.rec_keys = bytearray(data.get("keys", "").encode(UTF8))
        entry.totp = bytearray(data.get("totp", "").encode(UTF8))
        data["password"] = None
        data["keys"] = None
        data["totp"] = None

        entry.pw_hist = [
            (label, secret)
            for label, secret in data.get("password_history", [])
        ]

        entry.created = data.get("created_date", "")
        entry.edited = data.get("edited_date", "")
        entry.other = dict(data.get("other", {}))
        
        return entry
    
    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        """
        Create an entry from encoded storage data.

        Args:
            data: Stored entry data.

        Returns:
            Reconstructed Entry instance.
        """
        if not isinstance(data, dict):
            raise TypeError("Entry data must be a dict")

        entry = cls(
            site=data["site"],
            account=data.get("account", ""),
        )

        entry.note = data.get("note", "")
        entry.password = _b64_to_btArr(data.get("password", ""))
        entry.rec_keys = _b64_to_btArr(data.get("keys", ""))
        entry.totp = _b64_to_btArr(data.get("totp", ""))
        data["password"] = None
        data["keys"] = None
        data["totp"] = None

        entry.pw_hist = [
            (label, secret)
            for label, secret in data.get("password_history", [])
        ]

        entry.created = data.get("created_date", "")
        entry.edited = data.get("edited_date", "")
        entry.other = dict(data.get("other", {}))
        
        return entry
    
    @classmethod
    def from_bytes(cls, raw: bytes) -> "Entry":
        """
        Deserialize an entry from JSON bytes.

        Args:
            raw: UTF-8 encoded JSON bytes.

        Returns:
            Reconstructed Entry instance.
        """
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("Input must be bytes")

        data = json.loads(raw.decode("utf-8"))
        return cls.from_dict(data)



def _btArr_to_b64(b: bytearray) -> str:
    """Encode a bytearray as base64."""
    return base64.b64encode(b).decode("ascii")

def _b64_to_btArr(s: str) -> bytearray:
    """Decode base64 string to a bytearray."""
    return bytearray(base64.b64decode(s.encode("ascii")))

def str_to_bytes(eid_str: str) -> bytes:
    """
    Decode a URL-safe base64 string.

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
