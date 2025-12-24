"""Password hashing and verification using PBKDF2-HMAC-SHA256

Implements secure password storage with:
- PBKDF2-HMAC-SHA256 key derivation
- 200,000 iterations (configurable)
- 16-byte random salt per password
- 32-byte derived key
- Constant-time verification

Security considerations:
    - PBKDF2 is vulnerable to GPU/ASIC attacks
    - For high-security applications, prefer Argon2id
    - Minimum 100,000 iterations recommended
    - Use unique salt per password (automatic)
"""

from typing import Final
from .helpers import pbkdf2_sha256
import base64
import hmac
import os

DEFAULT_ITERS: Final[int] = 200_000
SALT_LEN: Final[int] = 16
DK_LEN: Final[int] = 32
MIN_ITERS: Final[int] = 100_000
MAX_ITERS: Final[int] = 10_000_000
_B64_PADDING: Final[str] = "=="
_HASH_PREFIX: Final[str] = "pbkdf2"

def hash_password(password: str, iterations: int = DEFAULT_ITERS) -> str:
    """Hash password using PBKDF2-HMAC-SHA256.
    
    Creates secure password hash suitable for database storage.
    
    Args:
        password: Plaintext password to hash.
        iterations: PBKDF2 iterations (default: 200,000).
        
    Returns:
        Encoded hash string in format:
        pbkdf2$<iterations>$<salt_b64>$<hash_b64>
        
    Raises:
        ValueError: If iterations < 100,000 (insecure) or password empty.
        
    Example:
        >>> pwd_hash = hash_password("SecurePass123")
        >>> print(pwd_hash[:20])
        'pbkdf2$200000$...'
        >>> verify_password(pwd_hash, "SecurePass123")
        True
        
    Security:
        - Random 16-byte salt generated automatically
        - Salt stored with hash (not secret)
        - Iterations configurable (higher = slower = more secure)
        - Output is safe for database storage
        
    Performance:
        - ~200ms on typical hardware (200k iterations)
        - Intentionally slow to resist brute-force
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if iterations < MIN_ITERS:
        raise ValueError(f"Iterations must be >= {MIN_ITERS} for security")
    
    if iterations > MAX_ITERS:
        raise ValueError(f"Iterations must be <= {MAX_ITERS} to prevent DoS")
    
    salt = os.urandom(SALT_LEN)
    pwd_bytes = password.encode("utf-8")
    
    dk = pbkdf2_sha256(pwd_bytes, salt, iterations, DK_LEN)
    
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")

    return f"{_HASH_PREFIX}${iterations}${salt_b64}${dk_b64}"


def verify_password(stored: str, attempt: str) -> bool:
    """Verify password attempt against stored hash.
    
    Performs constant-time comparison to prevent timing attacks.
    
    Args:
        stored: Stored hash from hash_password().
        attempt: Password attempt to verify.
        
    Returns:
        True if password matches, False otherwise.
        
    Example:
        >>> pwd_hash = hash_password("correct")
        >>> verify_password(pwd_hash, "correct")
        True
        >>> verify_password(pwd_hash, "wrong")
        False
        
    Security:
        - Constant-time comparison prevents timing attacks
        - Validates hash format before processing
        - Safe against malformed input
        - Re-derives key to compare (never stores plaintext)
        
    Performance:
        - Same time as hash_password() (~200ms)
        - Time independent of where passwords differ
    """
    if not stored or not attempt:
        return False
    
    try:
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != _HASH_PREFIX:
            return False

        iterations = int(parts[1])
        
        # Validate iteration range (prevent DoS attacks)
        if iterations < MIN_ITERS or iterations > MAX_ITERS:
            return False
        
        salt = base64.urlsafe_b64decode(parts[2] + _B64_PADDING)
        expected_dk = base64.urlsafe_b64decode(parts[3] + _B64_PADDING)
        if len(salt) != SALT_LEN or len(expected_dk) != DK_LEN: # Validate expected lengths 
            return False
        attempt_bytes = attempt.encode("utf-8") # Derive key from attempt
        attempt_dk = pbkdf2_sha256(attempt_bytes, salt, iterations, DK_LEN)
        return hmac.compare_digest(attempt_dk, expected_dk) # Constant-time comparison (critical for security)
        
    except (ValueError, TypeError, UnicodeDecodeError):
        return False # Any parsing error = invalid hash = fail closed


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Validate password strength based on common security requirements.
    
    Args:
        password: Password to validate.
        
    Returns:
        Tuple of (is_valid, list_of_issues).
        
    Example:
        >>> is_valid, issues = validate_password_strength("weak")
        >>> print(is_valid)
        False
        >>> print(issues)
        ['Password must be at least 8 characters', ...]
    """
    issues = []
    if len(password) < 8:
        issues.append("Password must be at least 8 characters")
    
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one digit")
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?" # Check for special characters
    if not any(c in special_chars for c in password): 
        issues.append("Password must contain at least one special character")
    return len(issues) == 0, issues
