"""NOTE:
- XOR obfuscation is NOT cryptographically secure.
- The additional helpers below are provided for future use and
  are intentionally not referenced by the core functions."""

from typing import Iterable, Iterator, Optional, Tuple, Union
from dataclasses import dataclass

import base64
import hashlib
import time
import os

def xor_obfuscate(s: str, key: Union[str, bytes]) -> str:
    """
    Obfuscate a string using XOR with a key, then encode as Base64 URL-safe.

    Args:
        s (str): The plaintext string to obfuscate.
        key (Union[str, bytes]): The key for XOR. Can be a string or bytes.

    Returns:
        str: Base64 URL-safe encoded obfuscated string without padding.
    """
    kb = key if isinstance(key, bytes) else key.encode("utf-8")
    b = s.encode("utf-8")
    out = bytes([b[i] ^ kb[i % len(kb)] for i in range(len(b))])
    return base64.urlsafe_b64encode(out).decode("ascii").rstrip("=")

def xor_deobfuscate(s_enc: str, key: Union[str, bytes]) -> str:
    """
    Deobfuscate a string previously obfuscated with `xor_obfuscate`.

    Args:
        s_enc (str): Base64 URL-safe encoded obfuscated string.
        key (Union[str, bytes]): The key used for XOR. Must match obfuscation key.

    Returns:
        str: The original plaintext string.
    """
    padding = "=" * (-len(s_enc) % 4)
    b = base64.urlsafe_b64decode(s_enc + padding)
    kb = key if isinstance(key, bytes) else key.encode("utf-8")
    out = bytes([b[i] ^ kb[i % len(kb)] for i in range(len(b))])
    return out.decode("utf-8")

def generate_random_key(length: int = 32) -> str:
    """
    Generate a cryptographically-random key and return it encoded
    as Base64 URL-safe without padding. Useful as a symmetric key
    or obfuscation seed.

    Args:
        length (int): Number of raw bytes to generate (default: 32).

    Returns:
        str: Base64 URL-safe encoded key (no padding).
    """
    raw = os.urandom(length)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def derive_key_from_passphrase(
    passphrase: str,
    salt: Optional[bytes] = None,
    iterations: int = 100_000,
    dklen: int = 32,
) -> Tuple[bytes, bytes]:
    """
    Derive a key from a passphrase using PBKDF2-HMAC-SHA256.

    This is provided as a convenience for future features where a
    human-friendly passphrase must be expanded to a fixed-length key.

    Args:
        passphrase (str): The user-supplied passphrase.
        salt (bytes, optional): Optional salt; if None, a random salt is generated.
        iterations (int): PBKDF2 iteration count.
        dklen (int): Desired length of derived key.

    Returns:
        Tuple[bytes, bytes]: (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=dklen)
    return dk, salt
    
def streaming_xor_obfuscate(
    chunks: Iterable[bytes],
    key: Union[str, bytes],
) -> Iterator[str]:
    """
    Stream XOR-obfuscate an iterable of byte chunks and yield each chunk
    as base64url (without padding). Useful for large payloads or
    streaming pipelines.

    NOTE: This yields independent base64-chunks; the receiver must
    reverse with the same chunking strategy. This is a convenience
    not intended for production crypto.

    Args:
        chunks (Iterable[bytes]): Iterable which yields bytes-like chunks.
        key (Union[str, bytes]): XOR key (string or bytes).

    Yields:
        Iterator[str]: Base64url-encoded obfuscated chunk strings.
    """
    kb = key if isinstance(key, bytes) else key.encode("utf-8")
    klen = len(kb)
    offset = 0
    for chunk in chunks:
        out = bytes([(chunk[i] ^ kb[(offset + i) % klen]) for i in range(len(chunk))])
        offset = (offset + len(chunk)) % klen
        yield base64.urlsafe_b64encode(out).decode("ascii").rstrip("=")

@dataclass
class KeyRotationPlan:
    """
    Semi-complete helper to manage key rotation.

    NOT fully production hardened — intended as a blueprint:
      - stores current and next key (raw bytes or base64 str)
      - `rotate_if_due` swaps keys when rotate_at <= now
      - `schedule_rotation` sets next rotation timestamp

    The class does not persist keys by itself; integrate with your
    secret storage when adopting.
    """
    current_key: Union[bytes, str]
    next_key: Optional[Union[bytes, str]] = None
    rotate_at: Optional[int] = None  # epoch millis

    def schedule_rotation(self, when_millis: int, next_key: Union[bytes, str]) -> None:
        """
        Schedule a rotation at a specific epoch-millis and set the next key.

        Args:
            when_millis (int): Epoch time in milliseconds for rotation.
            next_key (Union[bytes, str]): The key to promote at rotation time.
        """
        self.rotate_at = when_millis
        self.next_key = next_key

    def rotate_if_due(self) -> bool:
        """
        Rotate keys if the scheduled time has arrived.

        Returns:
            bool: True if rotation occurred, False otherwise.
        """
        if self.rotate_at is None or self.next_key is None:
            return False
        now = int(time.time() * 1000)
        if now >= self.rotate_at:
            self.current_key = self.next_key
            self.next_key = None
            self.rotate_at = None
            return True
        return False

    # TODO: implement secure wiping of the previous key from memory if needed. | See: ./README.md for more information
