"""Authenticated encryption using HMAC-based stream cipher

WARNING:
    For production use, prefer audited libraries such as AES-GCM or
    ChaCha20-Poly1305. This module is intended for prototypes
    without external dependencies.

Security:
    - Encrypt-then-MAC construction
    - PBKDF2 + HKDF key derivation
    - Random salt and nonce per encryption
    - HMAC-SHA256 authentication
"""

from typing import Final, Optional, Tuple
import hashlib
import hmac
import os

from .helpers import (
    b64u_encode,
    b64u_decode,
    constant_time_eq,
    pbkdf2_sha256,
    hkdf_extract,
    hkdf_expand,
)

_SALT_LEN: Final[int] = 16
_NONCE_LEN: Final[int] = 12
_MAC_LEN: Final[int] = 32
_KEY_LEN: Final[int] = 32
_PBKDF2_ITERS: Final[int] = 100_000
_HKDF_INFO_ENC: Final[bytes] = b"yurei-encryption-v1"
_HKDF_INFO_MAC: Final[bytes] = b"yurei-mac-v1"
_EMPTY_SALT: Final[bytes] = b""
_KEYSTREAM_BLOCK_SIZE: Final[int] = 64

def derive_keys_from_password(
    password: bytes, 
    salt: Optional[bytes] = None, 
    iterations: int = _PBKDF2_ITERS
) -> Tuple[bytes, bytes, bytes]:
    """Derive encryption and MAC keys from a password using PBKDF2 + HKDF.
    
    Args:
        password: Password to derive keys from.
        salt: Optional salt (generated if None).
        iterations: Number of PBKDF2 iterations.
        
    Returns:
        Tuple of (enc_key, mac_key, salt).
    """
    if salt is None:
        salt = os.urandom(_SALT_LEN)
    ikm = pbkdf2_sha256(password, salt, iterations, _KEY_LEN) # PBKDF2: password + salt -> intermediate key
    prk = hkdf_extract(_EMPTY_SALT, ikm)                      # HKDF: expand to encryption + MAC keys
    okm = hkdf_expand(prk, _HKDF_INFO_ENC, 64)
    
    enc_key = okm[:32]
    mac_key = okm[32:64]
    
    return enc_key, mac_key, salt


def _generate_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate pseudorandom keystream using HMAC-SHA256 as PRF.
    
    Args:
        enc_key: 32-byte encryption key.
        nonce: 12-byte nonce.
        length: Desired keystream length.
        
    Returns:
        Keystream bytes.
    """
    if length <= 0:
        return b""
    
    output = bytearray()
    counter = 0
    
    while len(output) < length:
        counter_bytes = counter.to_bytes(8, "big") # Use counter as input to PRF
        block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    
    return bytes(output[:length])


def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
    """XOR data with keystream efficiently.
    
    Args:
        data: Data to XOR.
        keystream: Keystream of same length.
        
    Returns:
        XORed result.
    """
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ keystream[i]
    return bytes(result)


def encrypt_bytes(plaintext: bytes, key: bytes) -> str:
    """Encrypt plaintext bytes using a key (passphrase or raw 32-byte key).
    
    Args:
        plaintext: Data to encrypt.
        key: Passphrase or 32-byte raw key.
        
    Returns:
        Base64url-encoded blob: salt(16) + nonce(12) + ciphertext + mac(32)
        
    Example:
        >>> encrypted = encrypt_bytes(b"secret", b"password")
        >>> len(encrypted) > 0
        True
        
    Security:
        - Random salt and nonce per encryption
        - Encrypt-then-MAC construction
        - HMAC-SHA256 authentication
    """
    if len(key) != _KEY_LEN:
        enc_key, mac_key, salt = derive_keys_from_password(key)
    else:
        enc_key = key
        prk = hkdf_extract(_EMPTY_SALT, enc_key)
        mac_key = hkdf_expand(prk, _HKDF_INFO_MAC, _KEY_LEN)
        salt = _EMPTY_SALT
    nonce = os.urandom(_NONCE_LEN) # Generate random nonce
    

    keystream     = _generate_keystream(enc_key, nonce, len(plaintext))
    ciphertext    = _xor_bytes(plaintext, keystream)
    mac           = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    
    if salt:
        blob = salt + nonce + ciphertext + mac
    else:
        blob = nonce + ciphertext + mac
    
    return b64u_encode(blob)


def decrypt_bytes(blob_b64: str, key: bytes) -> bytes:
    """Decrypt a base64url-encoded blob produced by encrypt_bytes.
    
    Args:
        blob_b64: Encrypted blob.
        key: Passphrase or raw 32-byte key.
        
    Returns:
        Decrypted plaintext.
        
    Raises:
        ValueError: If blob is malformed or MAC check fails.
        
    Example:
        >>> encrypted = encrypt_bytes(b"secret", b"password")
        >>> decrypted = decrypt_bytes(encrypted, b"password")
        >>> decrypted
        b'secret'
        
    Security:
        - Constant-time MAC verification
        - Fails safely on tampering
    """
    try:
        blob = b64u_decode(blob_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}")
    
    min_size = _NONCE_LEN + _MAC_LEN
    
    if len(blob) < min_size:
        raise ValueError("Blob too small")
    
    if len(key) == _KEY_LEN:
        nonce = blob[:_NONCE_LEN] # Raw key path
        mac = blob[-_MAC_LEN:]
        ciphertext = blob[_NONCE_LEN:-_MAC_LEN]
        
        prk = hkdf_extract(_EMPTY_SALT, key)
        mac_key = hkdf_expand(prk, _HKDF_INFO_MAC, _KEY_LEN)
        enc_key = key
    else:
        if len(blob) < _SALT_LEN + min_size:
            raise ValueError("Blob too small for derived key")
        
        salt = blob[:_SALT_LEN]
        nonce = blob[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
        mac = blob[-_MAC_LEN:]
        ciphertext = blob[_SALT_LEN + _NONCE_LEN:-_MAC_LEN]
        
        enc_key, mac_key, _ = derive_keys_from_password(key, salt=salt)
    
    expected_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not constant_time_eq(expected_mac, mac):
        raise ValueError("MAC verification failed - data may be tampered")
    
    keystream = _generate_keystream(enc_key, nonce, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, keystream)
    
    return plaintext


def encrypt_parallel(
    plaintext: bytes, 
    key: bytes, 
    chunk_size: int = 128 * 1024, 
    workers: Optional[int] = None
) -> str:
    """Encrypt large plaintext in parallel chunks if necessary.
    
    Args:
        plaintext: Data to encrypt.
        key: Passphrase or raw key.
        chunk_size: Size of chunks for parallel encryption.
        workers: Number of parallel workers (None = auto).
        
    Returns:
        Base64url-encoded encrypted blob.
    """
    if len(plaintext) <= chunk_size: # For small data, use sequential encryption
        return encrypt_bytes(plaintext, key)
    try: # For large data, use parallel implementation if available
        from .cipher_parallel import encrypt_parallel as _parallel
        return _parallel(plaintext, key, chunk_size=chunk_size, workers=workers)
    except ImportError:
        return encrypt_bytes(plaintext, key)


def decrypt_parallel(
    blob_b64: str, 
    key: bytes, 
    workers: Optional[int] = None
) -> bytes:
    """Decrypt large blob using parallel chunks if needed.
    
    Args:
        blob_b64: Encrypted blob.
        key: Passphrase or raw key.
        workers: Number of parallel workers (None = auto).
        
    Returns:
        Decrypted plaintext.
    """
    try: # Try sequential decryption first
        return decrypt_bytes(blob_b64, key)
    except Exception:
        try:  # Try parallel implementation if available
            from .cipher_parallel import decrypt_parallel as _parallel
            return _parallel(blob_b64, key, workers=workers)
        except ImportError:
            raise # Re-raise original exception
