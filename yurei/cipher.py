"""WARNING:
For production use, prefer audited libraries such as AES-GCM or
ChaCha20-Poly1305. This module is intended for prototypes
without external dependencies."""

from typing import Tuple, Optional

import hashlib
import hmac
import os

from .helpers import (
    hkdf_expand,
    b64u_encode,
    b64u_decode,
    constant_time_eq,
    pbkdf2_sha256,
)

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF extract step using HMAC-SHA256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand step using HMAC-SHA256."""
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]

def derive_keys_from_password(
    password: bytes, salt: Optional[bytes] = None, iterations: int = 200_000
) -> Tuple[bytes, bytes, bytes, int]:
    """
    Derive encryption and MAC keys from a password using PBKDF2 + HKDF.

    Args:
        password (bytes): Password to derive keys from.
        salt (bytes, optional): Optional salt. Generated if None.
        iterations (int): Number of PBKDF2 iterations.

    Returns:
        Tuple[enc_key, mac_key, salt, iterations]:
            enc_key (32 bytes), mac_key (32 bytes), salt, iterations
    """
    if salt is None:
        salt = os.urandom(16)
    ikm = pbkdf2_sha256(password, salt, iterations, 32)
    prk = _hkdf_extract(b"", ikm)
    okm = _hkdf_expand(prk, b"secure-ids", 64)
    return okm[:32], okm[32:64], salt, iterations

def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a pseudorandom keystream using HMAC-SHA256 as a PRF."""
    output = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]

def encrypt_bytes(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt a plaintext bytes using a key (passphrase or raw 32-byte key).

    Args:
        plaintext (bytes): Data to encrypt.
        key (bytes): Passphrase or 32-byte raw key.

    Returns:
        str: Base64url-encoded blob: salt(16) + nonce(12) + ciphertext + mac(32)
    """
    if len(key) != 32:
        enc_key, mac_key, salt, _ = derive_keys_from_password(key)
    else:
        enc_key = key
        prk = _hkdf_extract(b"", enc_key)
        mac_key = _hkdf_expand(prk, b"mac", 32)
        salt = b""

    nonce = os.urandom(12)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    blob = salt + nonce + ciphertext + mac
    return b64u_encode(blob)

def decrypt_bytes(blob_b64: str, key: bytes) -> bytes:
    """
    Decrypt a base64url-encoded blob produced by encrypt_bytes.

    Args:
        blob_b64 (str): Encrypted blob.
        key (bytes): Passphrase or raw 32-byte key.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        ValueError: If blob is malformed or MAC check fails.
    """
    blob = b64u_decode(blob_b64)
    if len(blob) < 12 + 32:
        raise ValueError("Blob too small")

    if len(key) == 32:
        # raw key
        salt = b""
        nonce = blob[:12]
        mac = blob[-32:]
        ciphertext = blob[12:-32]
        prk = _hkdf_extract(b"", key)
        mac_key = _hkdf_expand(prk, b"mac", 32)
        enc_key = key
    else:
        # derived key
        salt = blob[:16]
        nonce = blob[16:28]
        mac = blob[-32:]
        ciphertext = blob[28:-32]
        enc_key, mac_key, _, _ = derive_keys_from_password(key, salt=salt)

    if not constant_time_eq(hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest(), mac):
        raise ValueError("MAC mismatch / tampered data")

    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))

def encrypt_parallel(
    plaintext: bytes, key: bytes, chunk_size: int = 128 * 1024, workers: Optional[int] = None
) -> str:
    """
    Encrypt large plaintext in parallel chunks if necessary.

    Args:
        plaintext (bytes): Data to encrypt.
        key (bytes): Passphrase or raw key.
        chunk_size (int): Size of chunks for parallel encryption.
        workers (int, optional): Number of parallel workers.

    Returns:
        str: Base64url-encoded encrypted blob.
    """
    if len(plaintext) <= chunk_size:
        return encrypt_bytes(plaintext, key)

    from .cipher_parallel import encrypt_parallel as _parallel  # type: ignore
    return _parallel(plaintext, key, chunk_size=chunk_size, workers=workers)

def decrypt_parallel(blob_b64: str, key: bytes, workers: Optional[int] = None) -> bytes:
    """
    Decrypt large blob using parallel chunks if needed.

    Args:
        blob_b64 (str): Encrypted blob.
        key (bytes): Passphrase or raw key.
        workers (int, optional): Number of parallel workers.

    Returns:
        bytes: Decrypted plaintext.
    """
    try:
        return decrypt_bytes(blob_b64, key)
    except Exception:
        from .cipher_parallel import decrypt_parallel as _parallel  # type: ignore
        return _parallel(blob_b64, key, workers=workers)            # $ (...)
