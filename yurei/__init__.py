"""yurei: zero-dependency python cryptography library

provides cryptographic utilities for:
- identifier generation (uuid4, deterministic ids, short tokens)
- password hashing (pbkdf2-hmac-sha256)
- session management (hmac-signed tokens)
- authenticated encryption (encrypt-then-mac)
- key-value storage (memory/sqlite)
- xor obfuscation utilities

example:
    $>>> from yurei import encrypt_bytes, create_token, hash_password
    $>>> encrypted = encrypt_bytes(b"secret", b"password")
    $>>> token = create_token({"user": "alice"}, b"key", ttl_seconds=3600)
    $>>> pwd_hash = hash_password("SecurePass123")

note:
    for production systems, prefer audited libraries like `cryptography`
    with aes-gcm or chacha20-poly1305.
"""

__version__ = "2.1.0"
__author__ = "ogkae"
__license__ = "MIT"

from .uid import is_uuid4, sha256_id, short_id, uuid4 # identifier generation
from .obfusc import xor_deobfuscate, xor_obfuscate    # xor obfuscation (non-cryptographic)
from .auth import hash_password, verify_password      # password authentication
from .session import create_token, verify_token       # session token management
from .store import KVStore                            # key-value storage


from .cipher import ( 
    decrypt_bytes,
    decrypt_parallel,
    encrypt_bytes,
    encrypt_parallel,
) # encryption and decryption

__all__ = (
    "__version__",
    "__author__",
    "__license__",

    "uuid4",
    "is_uuid4",
    "sha256_id",
    "short_id",
    "hash_password",
    "verify_password",
    "create_token",
    "verify_token",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_parallel",
    "decrypt_parallel",
    "KVStore",
    "xor_obfuscate",
    "xor_deobfuscate",
)
