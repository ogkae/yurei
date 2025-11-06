from typing import Optional
from .helpers import to_hex
import os,re,secrets,hashlib

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def uuid4() -> str:
    """gen uuid v4 (without uuid module)"""
    r = bytearray(os.urandom(16))
    r[6] = (r[6] & 0x0f) | (4 << 4)
    r[8] = (r[8] & 0x3f) | 0x80
    h = to_hex(bytes(r))
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)

def is_uuid4(s: str) -> bool:
    return bool(_UUID4_RE.fullmatch(s))

def sha256_id(namespace: Optional[str], name: str, salt: Optional[str] = None) -> str:
    """id: sha256(namespace:name[:salt])."""
    parts = []
    if namespace:
        parts.append(namespace)
    parts.append(name)
    if salt:
        parts.append(salt)
    data = ":".join(parts).encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def short_id(length: int = 12) -> str:

    return ''.join(secrets.choice(ALPHABET) for _ in range(length))
