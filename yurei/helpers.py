from typing import Tuple
import hashlib
import base64
import time
import hmac
import os

def now_millis() -> int:
    """
    Return the current time in milliseconds.

    Returns:
        int: Current time in milliseconds since epoch.
    """
    return int(time.time() * 1000)

def to_hex(b: bytes) -> str:
    """
    Convert bytes to a lowercase hexadecimal string.

    Args:
        b (bytes): Bytes to convert.

    Returns:
        str: Hexadecimal representation.
    """
    return b.hex()

def b64u_encode(b: bytes) -> str:
    """
    Encode bytes to a URL-safe Base64 string without padding.

    Args:
        b (bytes): Bytes to encode.

    Returns:
        str: Base64 URL-safe encoded string without '=' padding.
    """
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64u_decode(s: str) -> bytes:
    """
    Decode a URL-safe Base64 string (with or without padding) back to bytes.

    Args:
        s (str): Base64 URL-safe encoded string.

    Returns:
        bytes: Decoded bytes.
    """
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def constant_time_eq(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    Args:
        a (bytes): First byte string.
        b (bytes): Second byte string.

    Returns:
        bool: True if equal, False otherwise.
    """
    return hmac.compare_digest(a, b)

def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2 with SHA256.

    Args:
        password (bytes): Password bytes.
        salt (bytes): Salt bytes.
        iterations (int): Number of PBKDF2 iterations.
        dklen (int): Desired length of derived key in bytes.

    Returns:
        bytes: Derived key.
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)
