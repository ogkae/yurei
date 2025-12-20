from .helpers import pbkdf2_sha256
from typing import Tuple

import base64
import hmac
import os

#      constants
DEFAULT_ITERS = 200_000
SALT_LEN      = 16
DK_LEN        = 32

# cached padding to avoid recalculation
_B64_PADDING = "=="

def hash_password(password: str, iterations: int = DEFAULT_ITERS) -> str:
    """
    Hash a password using (PBKDF2-SHA256).

    Args:
        password (str): The plaintext password to hash.
        iterations (int): Number of PBKDF2 iterations (default: 200_000).

    Returns:
        str: Encoded hash string in the format:
             pbkdf2$<iterations>$<salt_b64>$<hash_b64>
    """
    if iterations < 100_000:
        raise ValueError("iterations must be >= 100,000 for security")
    
    salt = os.urandom(SALT_LEN)
    pwd_bytes = password.encode("utf-8")
    dk = pbkdf2_sha256(pwd_bytes, salt, iterations, DK_LEN)

    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")

    return f"pbkdf2${iterations}${salt_b64}${dk_b64}"


def verify_password(stored: str, attempt: str) -> bool:
    """
    Verify a password attempt against a stored PBKDF2 hash.

    Args:
        stored (str): The stored hash string.
        attempt (str): The password attempt to verify.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    try:
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2":
            return False

        iterations = int(parts[1])
        
        # validate reasonable iteration range
        if iterations < 10_000 or iterations > 10_000_000:
            return False
        
        # decode with efficient padding
        salt = base64.urlsafe_b64decode(parts[2] + _B64_PADDING)
        expected_dk = base64.urlsafe_b64decode(parts[3] + _B64_PADDING)
        
        # validate expected lengths
        if len(salt) != SALT_LEN or len(expected_dk) != DK_LEN:
            return False

        attempt_bytes = attempt.encode("utf-8")
        attempt_dk = pbkdf2_sha256(
            attempt_bytes, salt, iterations, len(expected_dk)
        )

        return hmac.compare_digest(attempt_dk, expected_dk)
    except (ValueError, TypeError, UnicodeDecodeError):
        return False
