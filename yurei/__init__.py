"""yurei: zero-dependency python cryptography library

Provides cryptographic utilities for:
- Identifier generation (UUID4, deterministic IDs, short tokens)
- Password hashing (PBKDF2-HMAC-SHA256)
- Session management (HMAC-signed tokens)
- Authenticated encryption (Encrypt-then-MAC)
- Key-value storage (memory/SQLite)
- XOR obfuscation utilities

Example:
    >>> from yurei import encrypt_bytes, create_token, hash_password
    >>> encrypted = encrypt_bytes(b"secret", b"password")
    >>> token = create_token({"user": "alice"}, b"key", ttl_seconds=3600)
    >>> pwd_hash = hash_password("SecurePass123")

Note:
    For production systems, prefer audited libraries like `cryptography`
    with AES-GCM or ChaCha20-Poly1305.
"""

__version__ = "1.4.1"
__author__ = "zektrace"
__license__ = "MIT"

from .uid import is_uuid4, sha256_id, short_id, uuid4
from .obfusc import xor_deobfuscate, xor_obfuscate
from .auth import hash_password, verify_password
from .session import create_token, verify_token
from .store import KVStore
from .cipher import (
    decrypt_bytes,
    decrypt_parallel,
    encrypt_bytes,
    encrypt_parallel,
)

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

