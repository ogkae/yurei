from typing import Tuple
import os,time,hmac,hashlib,base64

def now_millis() -> int:
    """ti/ms (int)."""
    return int(time.time() * 1000)

def to_hex(b: bytes) -> str:
    return b.hex()

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')

def b64u_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=dklen)