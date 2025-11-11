"""SECURITY NOTE:
 - Prefer Python stdlib `uuid`, `secrets`, `hashlib` for CSPRNG and hashing.
 - For encryption/authenticated encryption use audited libraries (AES-GCM / ChaCha20-Poly1305)."""

from typing import Optional, Union
from .helpers import to_hex
import secrets
import hashlib
import hmac
import uuid
import re
import os

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def uuid4() -> str:
    """Generate a UUIDv4 (manual implementation, kept for compatibility)."""
    r = bytearray(os.urandom(16))
    r[6] = (r[6] & 0x0F) | (4 << 4)
    r[8] = (r[8] & 0x3F) | 0x80
    h = to_hex(bytes(r))
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)

def is_uuid4(s: str) -> bool:
    """Return True if string matches UUIDv4 pattern."""
    return bool(_UUID4_RE.fullmatch(s))


def sha256_id(namespace: Optional[str], name: str, salt: Optional[str] = None) -> str:
    """Deterministic id: sha256(namespace:name[:salt])."""
    parts = []
    if namespace:
        parts.append(namespace)
    parts.append(name)
    if salt:
        parts.append(salt)
    data = ":".join(parts).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def short_id(length: int = 12) -> str:
    """Simple short id using `secrets.choice` over ALPHABET (CSPRNG)."""
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


# V1.4 ???
def uuid4_std() -> str:
    """
    Recommended: use stdlib uuid.uuid4() for security-sensitive contexts.

    This simply wraps the standard implementation and returns the canonical
    string representation.
    """
    return str(uuid.uuid4())

def uuid5_from_namespace(namespace_uuid: Union[str, uuid.UUID], name: str) -> str:
    """
    Create a name-based UUIDv5 from a namespace UUID and a name.

    Args:
        namespace_uuid: a uuid.UUID instance or its string form
        name: the name within the namespace

    Returns:
        str: UUIDv5 string
    """
    ns = uuid.UUID(str(namespace_uuid)) if not isinstance(namespace_uuid, uuid.UUID) else namespace_uuid
    return str(uuid.uuid5(ns, name))

def secure_short_id(bytes_len: int = 16) -> str:
    """
    Higher-entropy URL-safe short id for tokens/links.

    Produces a base64-url-safe token without padding. Good for tokens
    exposed to users (e.g. confirmation tokens, nonces).
    """
    return secrets.token_urlsafe(bytes_len).rstrip("=")


def hmac_id(key: bytes, namespace: Optional[str], name: str, hex_out: bool = True) -> str:
    """
    Deterministic HMAC-based id useful for canonicalizing names under a secret:
        hmac_sha256(key, namespace + ':' + name)

    Args:
        key: secret key bytes (should be stored in KMS or env var)
        namespace: optional namespace string
        name: input name (string)
        hex_out: if True return hex digest else raw bytes

    Returns:
        str or bytes: id as hex string (default) or bytes
    """
    parts = []
    if namespace:
        parts.append(namespace)
    parts.append(name)
    data = ":".join(parts).encode("utf-8")
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return mac.hex() if hex_out else mac


def id_from_bytes(b: bytes) -> str:
    """Utility: deterministic hexadecimal id from raw bytes (lowercase)."""
    return to_hex(b)


# --- TODO / NOTES ---
# - Integrate HKDF-based key derivation per RFC5869 when deriving multiple keys
#   from a single secret (PRK/OKM). See RFC 5869.
# - Use PBKDF2 / scrypt for passphrase stretching per RFC2898 or hashlib.scrypt.
# - Migrate symmetric encryption to AES-GCM or ChaCha20-Poly1305 (use `cryptography` lib)
#   rather than home-grown XOR/HMAC constructions.
# - Store long-term secrets (HMAC keys, KMS keys) in a secure key management system
#   (KMS / HashiCorp Vault / cloud KMS) rather than environment variables.

# Each of the above items is intentionally left as notes/placeholders and  -> : 
# helper functions in this module to be wired later with a secure backend. -> : 
