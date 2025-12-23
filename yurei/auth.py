"""password hashing and verification using pbkdf2-hmac-sha256

implements secure password storage with:
- pbkdf2-hmac-sha256 key derivation
- 200,000 iterations (configurable)
- 16-byte random salt per password
- 32-byte derived key
- constant-time verification

security considerations:
    - pbkdf2 is vulnerable to gpu/asic attacks
    - for high-security applications, prefer argon2id
    - minimum 100,000 iterations recommended
    - use unique salt per password (automatic)
"""

from .helpers import pbkdf2_sha256
import base64
import hmac
import os

DEFAULT_ITERS = 200_000  # pbkdf2 iteration count
SALT_LEN = 16            # salt length in bytes
DK_LEN = 32              # derived key length in bytes
_B64_PADDING = "=="      # cached padding for efficiency


def hash_password(password: str, iterations: int = DEFAULT_ITERS) -> str:
    """hash password using pbkdf2-hmac-sha256
    
    creates secure password hash suitable for database storage
    
    args:
        password (str): plaintext password to hash
        iterations (int): pbkdf2 iterations (default: 200,000)
        
    returns:
        str: encoded hash string in format:
             pbkdf2$<iterations>$<salt_b64>$<hash_b64>
             
    raises:
        ValueError: if iterations < 100,000 (insecure)
        
    example:
        >>> pwd_hash = hash_password("SecurePass123")
        >>> print(pwd_hash)
        'pbkdf2$200000$...$...'
        >>> verify_password(pwd_hash, "SecurePass123")
        True
        
    security:
        - random 16-byte salt generated automatically
        - salt stored with hash (not secret)
        - iterations configurable (higher = slower = more secure)
        - output is safe for database storage
        
    performance:
        - ~200ms on typical hardware (200k iterations)
        - intentionally slow to resist brute-force
    """
    if iterations < 100_000:
        raise ValueError("iterations must be >= 100,000 for security")
    
    salt = os.urandom(SALT_LEN) # generate cryptographically random salt
    pwd_bytes = password.encode("utf-8")
    
    dk = pbkdf2_sha256(pwd_bytes, salt, iterations, DK_LEN)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")

    return f"pbkdf2${iterations}${salt_b64}${dk_b64}"


def verify_password(stored: str, attempt: str) -> bool:
    """verify password attempt against stored hash
    
    performs constant-time comparison to prevent timing attacks
    
    args:
        stored (str): stored hash from hash_password()
        attempt (str): password attempt to verify
        
    returns:
        bool: true if password matches, false otherwise
        
    example:
        >>> pwd_hash = hash_password("correct")
        >>> verify_password(pwd_hash, "correct")
        True
        >>> verify_password(pwd_hash, "wrong")
        False
        
    security:
        - constant-time comparison prevents timing attacks
        - validates hash format before processing
        - safe against malformed input
        - re-derives key to compare (never stores plaintext)
        
    performance:
        - same time as hash_password() (~200ms)
        - time independent of where passwords differ
    """
    try:
        # parse stored hash format: pbkdf2$iterations$salt_b64$hash_b64
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2":
            return False

        iterations = int(parts[1])
        
        if iterations < 10_000 or iterations > 10_000_000: # validate iteration range (prevent dos attacks)
            return False
        
        salt = base64.urlsafe_b64decode(parts[2] + _B64_PADDING)
        expected_dk = base64.urlsafe_b64decode(parts[3] + _B64_PADDING)
        
        if len(salt) != SALT_LEN or len(expected_dk) != DK_LEN: # validate expected lengths
            return False

        attempt_bytes = attempt.encode("utf-8")
        attempt_dk = pbkdf2_sha256(
            attempt_bytes, salt, iterations, len(expected_dk)
        )
        return hmac.compare_digest(attempt_dk, expected_dk) # constant-time comparison (critical for security)
        
    except (ValueError, TypeError, UnicodeDecodeError):  # any parsing error = invalid hash = fail closed
        return False
