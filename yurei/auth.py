from .helpers import pbkdf2_sha256
from typing import Tuple
import base64
import hmac
import os

DEFAULT_ITERS = 200_000
SALT_LEN      = 16
DK_LEN        = 32

def hash_password(password: str, iterations: int = DEFAULT_ITERS) -> str:
    """
    return: pbkdf2$iterations$salt_b64$hash_b64
    """
    salt = os.urandom(SALT_LEN)
    dk = pbkdf2_sha256(password.encode('utf-8'), salt, iterations, DK_LEN)
    return "pbkdf2${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode('ascii').rstrip('='),
        base64.urlsafe_b64encode(dk).decode('ascii').rstrip('=')
    )

def verify_password(stored: str, attempt: str) -> bool:
    try:
        parts = stored.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2':
            return False
        it = int(parts[1])
        salt = base64.urlsafe_b64decode(parts[2] + '==')
        expected = base64.urlsafe_b64decode(parts[3] + '==')
        dk = pbkdf2_sha256(attempt.encode('utf-8'), salt, it, len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False