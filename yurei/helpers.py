"""Internal helper functions for cryptographic operations

Provides low-level utilities used across yurei modules:
- Time utilities (millisecond timestamps)
- Encoding utilities (hex, base64url)
- Constant-time comparison (timing attack prevention)
- Key derivation (PBKDF2, HKDF)
"""

from typing import Final
import hashlib
import base64
import time
import hmac

_BASE64_PADDING: Final[str] = "="
_HMAC_DIGEST_SIZE: Final[int] = 32  # SHA256 output size
_MAX_HKDF_LENGTH: Final[int] = 255 * _HMAC_DIGEST_SIZE  # RFC 5869 limit

def now_millis() -> int:
    """Return current Unix timestamp in milliseconds.
    
    Returns:
        int: Milliseconds since epoch (Jan 1, 1970 UTC).
        
    Example:
        >>> ts = now_millis()
        >>> print(f"Current time: {ts}ms")
    """
    return int(time.time() * 1000)


def to_hex(b: bytes) -> str:
    """Convert bytes to lowercase hexadecimal string.
    
    Args:
        b: Raw bytes to convert.
        
    Returns:
        Hexadecimal representation.
        
    Example:
        >>> to_hex(b"\\x00\\xff")
        '00ff'
    """
    return b.hex()


def b64u_encode(b: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding.
    
    URL-safe variant uses '-' and '_' instead of '+' and '/'.
    Padding ('=') is removed for cleaner URLs.
    
    Args:
        b: Raw bytes to encode.
        
    Returns:
        Base64url string without padding.
        
    Example:
        >>> b64u_encode(b"hello")
        'aGVsbG8'
    """
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip(_BASE64_PADDING)


def b64u_decode(s: str) -> bytes:
    """Decode URL-safe base64 string back to bytes.
    
    Automatically adds required padding if missing.
    
    Args:
        s: Base64url encoded string.
        
    Returns:
        Decoded raw bytes.
        
    Raises:
        binascii.Error: If input is not valid base64.
        
    Example:
        >>> b64u_decode('aGVsbG8')
        b'hello'
    """
    padding_needed = (4 - len(s) % 4) % 4
    if padding_needed:
        s += _BASE64_PADDING * padding_needed
    return base64.urlsafe_b64decode(s)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.
    
    Prevents timing attacks by ensuring comparison always takes
    the same time regardless of where the first difference occurs.
    
    Args:
        a: First byte string.
        b: Second byte string.
        
    Returns:
        True if equal, False otherwise.
        
    Note:
        Uses hmac.compare_digest which is designed to prevent
        timing analysis attacks.
        
    Example:
        >>> constant_time_eq(b"secret", b"secret")
        True
        >>> constant_time_eq(b"secret", b"public")
        False
    """
    return hmac.compare_digest(a, b)


def pbkdf2_sha256(
    password: bytes, 
    salt: bytes, 
    iterations: int, 
    dklen: int
) -> bytes:
    """Derive cryptographic key from password using PBKDF2-HMAC-SHA256.
    
    PBKDF2 (Password-Based Key Derivation Function 2) applies a
    pseudorandom function to the password along with a salt value
    and repeats the process many times to produce a derived key,
    which helps defend against brute-force attacks.
    
    Args:
        password: Password to derive key from.
        salt: Cryptographic salt (should be unique per password).
        iterations: Number of iterations (higher = slower = more secure).
        dklen: Desired length of derived key in bytes.
        
    Returns:
        Derived key of specified length.
        
    Security:
        - Minimum 100,000 iterations recommended (yurei uses 200,000)
        - Salt should be at least 16 bytes random data
        - Use unique salt per password
        
    Example:
        >>> import os
        >>> salt = os.urandom(16)
        >>> key = pbkdf2_sha256(b"password", salt, 200_000, 32)
        >>> len(key)
        32
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF extract step using HMAC-SHA256.
    
    Extracts a fixed-length pseudorandom key from input keying material.
    Part of the HKDF (HMAC-based Key Derivation Function) from RFC 5869.
    
    Args:
        salt: Optional salt value (use empty bytes if not needed).
        ikm: Input keying material.
        
    Returns:
        Pseudorandom key of fixed length (32 bytes for SHA256).
        
    Example:
        >>> prk = hkdf_extract(b"", b"input_key_material")
        >>> len(prk)
        32
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand step using HMAC-SHA256.
    
    Expands a pseudorandom key to the desired length using optional
    context/application-specific info.
    
    Args:
        prk: Pseudorandom key from extract step.
        info: Optional context/application specific info.
        length: Desired output length in bytes.
        
    Returns:
        Expanded key material.
        
    Raises:
        ValueError: If length exceeds RFC 5869 limit (255 * 32 bytes).
        
    Note:
        Part of HKDF (RFC 5869) key derivation function.
        
    Example:
        >>> import os
        >>> prk = os.urandom(32)
        >>> okm = hkdf_expand(prk, b"app-context", 64)
        >>> len(okm)
        64
    """
    if length <= 0:
        return b""
    
    if length > _MAX_HKDF_LENGTH:
        raise ValueError(f"Cannot expand to more than {_MAX_HKDF_LENGTH} bytes")
    
    output = bytearray()
    t = b""
    counter = 1
    
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(t)
        counter += 1
    
    return bytes(output[:length])


def secure_zero(data: bytearray) -> None:
    """Securely zero out sensitive data in memory.
    
    Overwrites memory with zeros to prevent sensitive data from
    lingering in memory after use.
    
    Args:
        data: Bytearray to zero out (modified in-place).
        
    Note:
        This provides basic memory clearing but does not guarantee
        complete protection against all memory access techniques.
        For high-security applications, consider using specialized
        memory protection libraries.
        
    Example:
        >>> sensitive = bytearray(b"password")
        >>> secure_zero(sensitive)
        >>> sensitive
        bytearray(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')
    """
    for i in range(len(data)):
        data[i] = 0
