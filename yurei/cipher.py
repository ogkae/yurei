"""WARNING:
For production use, prefer audited libraries such as AES-GCM or
ChaCha20-Poly1305. This module is intended for prototypes
without external dependencies."""

from typing import Tuple, Optional

import hashlib
import hmac
import os

from .helpers import (
    b64u_encode,
    b64u_decode,
    constant_time_eq,
    pbkdf2_sha256,
)

# constants for reusability
_HKDF_INFO_SECURE_IDS = b"secure-ids"
_HKDF_INFO_MAC = b"mac"
_EMPTY_SALT = b""

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF extract step using HMAC-SHA256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand step using HMAC-SHA256."""
    if length <= 0:
        return b""
    
    output = bytearray()  # more efficient than concatenating bytes
    t = b""
    counter = 1
    hash_len = 32  # sha256 produces 32 bytes
    
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(t)
        counter += 1
        
    return bytes(output[:length])

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
    prk = _hkdf_extract(_EMPTY_SALT, ikm)
    okm = _hkdf_expand(prk, _HKDF_INFO_SECURE_IDS, 64)
    return okm[:32], okm[32:64], salt, iterations

def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a pseudorandom keystream using HMAC-SHA256 as a PRF."""
    if length <= 0:
        return b""
    
    output = bytearray()  # more efficient for construction
    counter = 1
    counter_bytes = bytearray(8)  # reuse buffer
    
    while len(output) < length:
        # update counter instead of creating new bytes each time
        counter_bytes[:] = counter.to_bytes(8, "big")
        block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
        output.extend(block)
        counter += 1
        
    return bytes(output[:length])

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
        prk = _hkdf_extract(_EMPTY_SALT, enc_key)
        mac_key = _hkdf_expand(prk, _HKDF_INFO_MAC, 32)
        salt = _EMPTY_SALT

    nonce = os.urandom(12)
    ks = _keystream(enc_key, nonce, len(plaintext))
    
    # xor using bytearray for better performance
    ciphertext = bytearray(len(plaintext))
    for i in range(len(plaintext)):
        ciphertext[i] = plaintext[i] ^ ks[i]
    
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    
    # efficient blob construction
    if salt:
        blob = salt + nonce + bytes(ciphertext) + mac
    else:
        blob = nonce + bytes(ciphertext) + mac
        
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
    min_size = 12 + 32  # nonce + mac
    
    if len(blob) < min_size:
        raise ValueError("Blob too small")

    if len(key) == 32:
        # raw key path
        nonce = blob[:12]
        mac = blob[-32:]
        ciphertext = blob[12:-32]
        
        prk = _hkdf_extract(_EMPTY_SALT, key)
        mac_key = _hkdf_expand(prk, _HKDF_INFO_MAC, 32)
        enc_key = key
    else:
        # derived key path
        if len(blob) < 16 + min_size:
            raise ValueError("Blob too small for derived key")
            
        salt = blob[:16]
        nonce = blob[16:28]
        mac = blob[-32:]
        ciphertext = blob[28:-32]
        enc_key, mac_key, _, _ = derive_keys_from_password(key, salt=salt)

    # constant-time MAC verification
    expected_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not constant_time_eq(expected_mac, mac):
        raise ValueError("MAC mismatch / tampered data")

    ks = _keystream(enc_key, len(ciphertext))
    
    # optimized xor
    plaintext = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        plaintext[i] = ciphertext[i] ^ ks[i]
        
    return bytes(plaintext)

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
