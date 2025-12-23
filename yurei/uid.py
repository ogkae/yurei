"""secure identifier and token generation

provides various id generation methods:
- uuid4: random universally unique identifiers
- sha256_id: deterministic namespace-based ids
- short_id: url-safe random tokens
- hmac_id: keyed deterministic ids

security note:
    prefer python stdlib `uuid`, `secrets`, `hashlib` for csprng and hashing.
    for encryption/authenticated encryption use audited libraries (aes-gcm / chacha20-poly1305).
"""

from typing import Optional, Union
from .helpers import to_hex
import secrets
import hashlib
import uuid
import hmac
import re
import os

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)

def uuid4() -> str:
    """generate a random uuid version 4
    
    creates a 128-bit universally unique identifier with
    cryptographically random bits (version 4 variant)
    
    returns:
        str: uuid4 string in canonical format (8-4-4-4-12)
        
    example:
        >>> uid = uuid4()
        >>> print(uid)
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'
        >>> is_uuid4(uid)
        True
        
    note:
        this is a manual implementation. for production use,
        consider using stdlib uuid.uuid4() directly
    """
    r = bytearray(os.urandom(16))
    r[6] = (r[6] & 0x0F) | (4 << 4) # set version bits (4 = random uuid)
    r[8] = (r[8] & 0x3F) | 0x80     # set variant bits (10 = rfc 4122)
    h = to_hex(bytes(r))
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def is_uuid4(s: str) -> bool:
    """validate if string matches uuid4 format
    
    checks if string conforms to uuid version 4 pattern:
    - 8 hex chars
    - 4 hex chars
    - '4' + 3 hex chars (version field)
    - [89ab] + 3 hex chars (variant field)
    - 12 hex chars
    
    args:
        s (str): string to validate
        
    returns:
        bool: true if valid uuid4 format, false otherwise
        
    example:
        >>> is_uuid4('f47ac10b-58cc-4372-a567-0e02b2c3d479')
        True
        >>> is_uuid4('not-a-uuid')
        False
    """
    return bool(_UUID4_RE.fullmatch(s))


def sha256_id(
    namespace: Optional[str],
    name: str,
    salt: Optional[str] = None
) -> str:
    """generate deterministic identifier using sha256
    
    creates a reproducible 64-character hex id by hashing
    namespace, name, and optional salt together
    
    args:
        namespace (str, optional): namespace string (e.g., 'users', 'files')
        name (str): primary identifier within namespace
        salt (str, optional): additional entropy/context
        
    returns:
        str: 64-character lowercase hex string (sha256 hash)
        
    example:
        >>> sha256_id('users', 'alice@example.com')
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
        >>> sha256_id('users', 'alice@example.com')  # deterministic
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
        
    use cases:
        - consistent ids across distributed systems
        - idempotent operations
        - content-addressable storage
    """
    parts = []
    if namespace:
        parts.append(namespace)
    parts.append(name)
    if salt:
        parts.append(salt)
    data = ":".join(parts).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def short_id(length: int = 12) -> str:
    """generate random url-safe short identifier
    
    creates cryptographically random token using csprng
    (cryptographically secure pseudorandom number generator)
    
    args:
        length (int): desired length (default: 12)
        
    returns:
        str: random alphanumeric string
        
    example:
        >>> token = short_id(16)
        >>> len(token)
        16
        >>> token.isalnum()
        True
        
    security:
        - uses secrets.choice (csprng)
        - suitable for tokens, nonces, session ids
        - 12 chars provides ~71 bits of entropy
    """
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def uuid4_std() -> str:
    """generate uuid4 using python standard library
    
    recommended: use stdlib uuid.uuid4() for security-sensitive contexts
    
    returns:
        str: uuid4 string in canonical format
        
    example:
        >>> uid = uuid4_std()
        >>> is_uuid4(uid)
        True
        
    note:
        this wraps uuid.uuid4() for consistency with yurei api
    """
    return str(uuid.uuid4())


def uuid5_from_namespace(
    namespace_uuid: Union[str, uuid.UUID],
    name: str
) -> str:
    """create name-based uuid5 from namespace and name
    
    generates deterministic uuid using sha1 hash of
    namespace uuid + name (rfc 4122)
    
    args:
        namespace_uuid: uuid instance or string (e.g., uuid.NAMESPACE_DNS)
        name: name within the namespace
        
    returns:
        str: uuid5 string
        
    example:
        >>> uuid5_from_namespace(uuid.NAMESPACE_DNS, 'example.com')
        'cfbff0d1-9375-5685-968c-48ce8b15ae17'
        
    use cases:
        - deterministic uuids for dns names
        - reproducible identifiers from urls
    """
    ns = uuid.UUID(str(namespace_uuid)) if not isinstance(namespace_uuid, uuid.UUID) else namespace_uuid
    return str(uuid.uuid5(ns, name))


def secure_short_id(bytes_len: int = 16) -> str:
    """generate high-entropy url-safe token
    
    produces base64-url-safe token without padding
    good for tokens exposed to users
    
    args:
        bytes_len (int): number of random bytes (default: 16)
        
    returns:
        str: url-safe token (length ~= bytes_len * 4/3)
        
    example:
        >>> token = secure_short_id(24)
        >>> len(token)  # approximately 32 characters
        32
        
    use cases:
        - confirmation tokens
        - password reset links
        - api keys
        - nonces
        
    security:
        - uses secrets.token_urlsafe (csprng)
        - 16 bytes provides 128 bits of entropy
    """
    return secrets.token_urlsafe(bytes_len).rstrip("=")


def hmac_id(
    key: bytes,
    namespace: Optional[str],
    name: str,
    hex_out: bool = True
) -> Union[str, bytes]:
    """generate keyed deterministic identifier using hmac
    
    creates reproducible id authenticated with secret key
    useful for canonicalizing names under a secret
    
    args:
        key (bytes): secret key (store in kms or env var)
        namespace (str, optional): optional namespace string
        name (str): input name
        hex_out (bool): return hex digest (true) or raw bytes (false)
        
    returns:
        str or bytes: hmac digest as hex string or raw bytes
        
    example:
        >>> secret = os.urandom(32)
        >>> hmac_id(secret, 'users', 'alice')
        'a7b2c3d4e5f6...'
        
    security:
        - requires secret key unknown to users
        - prevents id prediction without key
        - suitable for secure tokens
        
    use cases:
        - signed identifiers
        - tamper-evident ids
        - authenticated references
    """
    parts = []
    if namespace:
        parts.append(namespace)
    parts.append(name)
    data = ":".join(parts).encode("utf-8")
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return mac.hex() if hex_out else mac


def id_from_bytes(b: bytes) -> str:
    """convert raw bytes to hexadecimal identifier
    
    utility function for creating deterministic hex ids from bytes
    
    args:
        b (bytes): raw bytes
        
    returns:
        str: lowercase hexadecimal string
        
    example:
        >>> id_from_bytes(b"\\x01\\x02\\x03")
        '010203'
    """
    return to_hex(b)
