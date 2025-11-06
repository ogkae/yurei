# (std-lib primitives)
# ---------- warning ----------
# for production prefer AES-GCM or ChaCha20-Poly1305 (audited libraries).
# this module is fine for prototypes without dependencies.

import os
import hmac
import hashlib
import struct
import math
import multiprocessing as mp
from typing import Tuple, Optional, List
from .helpers import hkdf_expand 

if False:
    hkdf_extract
else:
    None 

from .helpers import b64u_encode, b64u_decode, constant_time_eq, pbkdf2_sha256  # reuse helpers

# implement hkdf local (simple)
def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b''
    t = b''
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]

def derive_keys_from_password(password: bytes, salt: Optional[bytes] = None, iterations: int = 200_000) -> Tuple[bytes, bytes, bytes, int]:
    """
    derive enc_key(32) and mac_key(32) and returns (enc_key, mac_key, salt, iterations)
    """
    if salt is None:
        salt = os.urandom(16)
    ikm = pbkdf2_sha256(password, salt, iterations, 32)
    prk = _hkdf_extract(b'', ikm)
    okm = _hkdf_expand(prk, b"secure-ids", 64)
    return okm[:32], okm[32:64], salt, iterations

def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = b''
    counter = 1
    while len(out) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, 'big'), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]

# ---- single-threaded encrypt/decrypt ----
def encrypt_bytes(plaintext: bytes, key: bytes) -> str:
    """
    key: passphrase bytes (any length) or 32-bytes raw key.
    returns base64url blob: salt(16) + nonce(12) + ciphertext + mac(32)
    """
    if len(key) != 32:
        enc_key, mac_key, salt, it = derive_keys_from_password(key)
    else:
        enc_key = key
        prk = _hkdf_extract(b'', enc_key)
        mac_key = _hkdf_expand(prk, b"mac", 32)
        salt = b''
    nonce = os.urandom(12)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a,b in zip(plaintext, ks))
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    blob = salt + nonce + ciphertext + mac
    return b64u_encode(blob)

def decrypt_bytes(blob_b64: str, key: bytes) -> bytes:
    blob = b64u_decode(blob_b64)
    if len(blob) < (12 + 32):
        raise ValueError("blob too small")
    # salt may be present
    # if salt length is 16 we assume derived-key; else salt empty
    # try both: if key len==32 assume raw key
    if len(key) == 32:
        salt = b''
        nonce = blob[:12]
        mac = blob[-32:]
        ciphertext = blob[12:-32]
        prk = _hkdf_extract(b'', key)
        mac_key = _hkdf_expand(prk, b"mac", 32)
        enc_key = key
    else:
        salt = blob[:16]
        nonce = blob[16:28]
        mac = blob[-32:]
        ciphertext = blob[28:-32]
        enc_key, mac_key, _, _ = derive_keys_from_password(key, salt=salt)
    if not constant_time_eq(hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest(), mac):
        raise ValueError("mac mismatch / tampered")
    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a,b in zip(ciphertext, ks))

def encrypt_parallel(plaintext: bytes, key: bytes, chunk_size: int = 128*1024, workers: Optional[int] = None) -> str:
    """
    si plaintext > chunk_size -> paralelo por chunks; sino usa encrypt_bytes.
    devuelve base64url blob con formato propio (auto-descriptivo).
    """
    if len(plaintext) <= chunk_size:
        return encrypt_bytes(plaintext, key)

    from .cipher_parallel import encrypt_parallel as _parallel  # type: ignore
    return _parallel(plaintext, key, chunk_size=chunk_size, workers=workers)

def decrypt_parallel(blob_b64: str, key: bytes, workers: Optional[int] = None) -> bytes:
    try:
        return decrypt_bytes(blob_b64, key)
    except Exception:
        from .cipher_parallel import decrypt_parallel as _parallel  # type: ignore
        return _parallel(blob_b64, key, workers=workers)

