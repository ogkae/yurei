"""internal helper functions for cryptographic operations

provides low-level utilities used across yurei modules:
- time utilities (millisecond timestamps)
- encoding utilities (hex, base64url)
- constant-time comparison (timing attack prevention)
- key derivation (pbkdf2, hkdf)
"""

from typing import Tuple
import hashlib
import base64
import time
import hmac
import os

_BASE64_PADDING = "=" # cached padding string to avoid string concatenation overhead

def now_millis() -> int:
    """return current unix timestamp in milliseconds
    
    returns:
        int: milliseconds since epoch (jan 1, 1970)
        
    example:
        >>> ts = now_millis()
        >>> print(f"current time: {ts}ms")
    """
    return int(time.time() * 1000)


def to_hex(b: bytes) -> str:
    """convert bytes to lowercase hexadecimal string
    
    args:
        b (bytes): raw bytes to convert
        
    returns:
        str: hexadecimal representation
        
    example:
        >>> to_hex(b"\\x00\\xff")
        '00ff'
    """
    return b.hex()


def b64u_encode(b: bytes) -> str:
    """encode bytes to url-safe base64 without padding
    
    url-safe variant uses '-' and '_' instead of '+' and '/'
    padding ('=') is removed to make urls cleaner
    
    args:
        b (bytes): raw bytes to encode
        
    returns:
        str: base64url string without padding
        
    example:
        >>> b64u_encode(b"hello")
        'aGVsbG8'
    """
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip(_BASE64_PADDING)


def b64u_decode(s: str) -> bytes:
    """decode url-safe base64 string back to bytes
    
    automatically adds required padding if missing
    
    args:
        s (str): base64url encoded string
        
    returns:
        bytes: decoded raw bytes
        
    raises:
        binascii.Error: if input is not valid base64
        
    example:
        >>> b64u_decode('aGVsbG8')
        b'hello'
    """
    
    padding_needed = (4 - len(s) % 4) % 4 
    if padding_needed:
        s = s + (_BASE64_PADDING * padding_needed)
    return base64.urlsafe_b64decode(s)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """compare two byte strings in constant time
    
    prevents timing attacks by ensuring comparison
    always takes the same time regardless of where
    the first difference occurs
    
    args:
        a (bytes): first byte string
        b (bytes): second byte string
        
    returns:
        bool: true if equal, false otherwise
        
    note:
        uses hmac.compare_digest which is designed to
        prevent timing analysis attacks
        
    example:
        >>> constant_time_eq(b"secret", b"secret")
        True
        >>> constant_time_eq(b"secret", b"public")
        False
    """
    return hmac.compare_digest(a, b)


def pbkdf2_sha256(
    password: bytes, salt: bytes, iterations: int, dklen: int
) -> bytes:
    """derive cryptographic key from password using pbkdf2-hmac-sha256
    
    pbkdf2 (password-based key derivation function 2) applies
    a pseudorandom function to the password along with a salt
    value and repeats the process many times to produce a
    derived key, which helps defend against brute-force attacks
    
    args:
        password (bytes): password to derive key from
        salt (bytes): cryptographic salt (should be unique per password)
        iterations (int): number of iterations (higher = slower = more secure)
        dklen (int): desired length of derived key in bytes
        
    returns:
        bytes: derived key of specified length
        
    security:
        - minimum 100,000 iterations recommended (yurei uses 200,000)
        - salt should be at least 16 bytes random data
        - use unique salt per password
        
    example:
        >>> salt = os.urandom(16)
        >>> key = pbkdf2_sha256(b"password", salt, 200_000, 32)
        >>> len(key)
        32
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """hkdf expand step using hmac-sha256
    
    hkdf (hmac-based key derivation function) expand takes a
    pseudorandom key and expands it to the desired length
    
    args:
        prk (bytes): pseudorandom key from extract step
        info (bytes): optional context/application specific info
        length (int): desired output length in bytes
        
    returns:
        bytes: expanded key material
        
    raises:
        ValueError: if length exceeds 255 * 32 bytes (sha256 limit)
        
    note:
        part of hkdf (rfc 5869) key derivation function
        
    example:
        >>> prk = os.urandom(32)  # from hkdf extract
        >>> okm = hkdf_expand(prk, b"app-context", 64)
        >>> len(okm)
        64
    """
    if length <= 0:
        return b""
    
    output = bytearray()
    t = b""
    counter = 1
    
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(t)
        counter += 1
        if counter > 255:
            raise ValueError("cannot expand to more than 255 * hash_len bytes")
    
    return bytes(output[:length])7
    # ~7/8
