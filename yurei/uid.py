"""Secure identifier and token generation

Provides various ID generation methods:
- uuid4: Random universally unique identifiers
- sha256_id: Deterministic namespace-based IDs
- short_id: URL-safe random tokens
- hmac_id: Keyed deterministic IDs

Security note:
    All random generation uses cryptographically secure sources.
    For production use, consider Python stdlib uuid, secrets, hashlib.
"""

from typing import Final, Optional
import secrets
import hashlib
import hmac
import os
import re

ALPHABET: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UUID_VERSION_MASK: Final[int] = 0x0F
_UUID_VERSION_SHIFT: Final[int] = 4
_UUID_VARIANT_MASK: Final[int] = 0x3F
_UUID_VARIANT_VALUE: Final[int] = 0x80

_UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

def uuid4() -> str:
    """Generate a random UUID version 4.
    
    Creates a 128-bit universally unique identifier with
    cryptographically random bits (version 4 variant).
    
    Returns:
        UUID4 string in canonical format (8-4-4-4-12).
        
    Example:
        >>> uid = uuid4()
        >>> print(uid)
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'
        >>> is_uuid4(uid)
        True
        
    Note:
        Uses os.urandom for cryptographic randomness.
    """
    random_bytes = bytearray(os.urandom(16))
    
    
    random_bytes[6] = (random_bytes[6] & _UUID_VERSION_MASK) | (4 << _UUID_VERSION_SHIFT) # Set version bits (4 = random UUID)
    random_bytes[8] = (random_bytes[8] & _UUID_VARIANT_MASK) | _UUID_VARIANT_VALUE        # Set variant bits (10 = RFC 4122)
    
    hex_str = random_bytes.hex() # Format as UUID string
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


def is_uuid4(s: str) -> bool:
    """Validate if string matches UUID4 format.
    
    Checks if string conforms to UUID version 4 pattern:
    - 8 hex chars
    - 4 hex chars
    - '4' + 3 hex chars (version field)
    - [89ab] + 3 hex chars (variant field)
    - 12 hex chars
    
    Args:
        s: String to validate.
        
    Returns:
        True if valid UUID4 format, False otherwise.
        
    Example:
        >>> is_uuid4('f47ac10b-58cc-4372-a567-0e02b2c3d479')
        True
        >>> is_uuid4('not-a-uuid')
        False
    """
    if not isinstance(s, str):
        return False
    return bool(_UUID4_PATTERN.fullmatch(s))


def sha256_id(namespace: str, name: str, salt: Optional[str] = None) -> str:
    """Generate deterministic identifier using SHA256.
    
    Creates a reproducible 64-character hex ID by hashing
    namespace, name, and optional salt together.
    
    Args:
        namespace: Namespace string (e.g., 'users', 'files').
        name: Primary identifier within namespace.
        salt: Optional additional entropy/context.
        
    Returns:
        64-character lowercase hex string (SHA256 hash).
        
    Example:
        >>> sha256_id('users', 'alice@example.com')
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
        >>> # Deterministic - same inputs produce same output
        >>> sha256_id('users', 'alice@example.com')
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
        
    Use cases:
        - Consistent IDs across distributed systems
        - Idempotent operations
        - Content-addressable storage
    """
    parts = [namespace, name]
    if salt:
        parts.append(salt)
    
    data = ":".join(parts).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def short_id(length: int = 12) -> str:
    """Generate random URL-safe short identifier.
    
    Creates cryptographically random token using CSPRNG
    (cryptographically secure pseudorandom number generator).
    
    Args:
        length: Desired length (default: 12).
        
    Returns:
        Random alphanumeric string.
        
    Raises:
        ValueError: If length < 1 or length > 128.
        
    Example:
        >>> token = short_id(16)
        >>> len(token)
        16
        >>> token.isalnum()
        True
        
    Security:
        - Uses secrets.choice (CSPRNG)
        - Suitable for tokens, nonces, session IDs
        - 12 chars provides ~71 bits of entropy
    """
    if length < 1:
        raise ValueError("Length must be at least 1")
    if length > 128:
        raise ValueError("Length must be at most 128")
    
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def hmac_id(
    key: bytes,
    namespace: str,
    name: str,
    hex_output: bool = True
) -> str:
    """Generate keyed deterministic identifier using HMAC.
    
    Creates reproducible ID authenticated with secret key.
    Useful for canonicalizing names under a secret.
    
    Args:
        key: Secret key (store in KMS or env var).
        namespace: Namespace string.
        name: Input name.
        hex_output: Return hex digest (True) or base64 (False).
        
    Returns:
        HMAC digest as hex string or base64.
        
    Raises:
        ValueError: If key is empty.
        
    Example:
        >>> secret = os.urandom(32)
        >>> hmac_id(secret, 'users', 'alice')
        'a7b2c3d4e5f6...'
        
    Security:
        - Requires secret key unknown to users
        - Prevents ID prediction without key
        - Suitable for secure tokens
        
    Use cases:
        - Signed identifiers
        - Tamper-evident IDs
        - Authenticated references
    """
    if not key:
        raise ValueError("Key cannot be empty")
    
    data = f"{namespace}:{name}".encode("utf-8")
    mac = hmac.new(key, data, hashlib.sha256).digest()
    
    if hex_output:
        return mac.hex()
    else:
        import base64
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def secure_token(bytes_length: int = 32) -> str:
    """Generate high-entropy URL-safe token.
    
    Produces base64-url-safe token without padding.
    Good for tokens exposed to users.
    
    Args:
        bytes_length: Number of random bytes (default: 32).
        
    Returns:
        URL-safe token (length ~= bytes_length * 4/3).
        
    Raises:
        ValueError: If bytes_length < 1 or bytes_length > 256.
        
    Example:
        >>> token = secure_token(24)
        >>> len(token) >= 30  # Approximately 32 characters
        True
        
    Use cases:
        - Confirmation tokens
        - Password reset links
        - API keys
        - Nonces
        
    Security:
        - Uses secrets.token_urlsafe (CSPRNG)
        - 32 bytes provides 256 bits of entropy
    """
    if bytes_length < 1:
        raise ValueError("Bytes length must be at least 1")
    if bytes_length > 256:
        raise ValueError("Bytes length must be at most 256")
    
    return secrets.token_urlsafe(bytes_length).rstrip("=")


def nanoid(length: int = 21, alphabet: Optional[str] = None) -> str:
    """Generate NanoID-style identifier.
    
    Creates compact, URL-safe, unique identifier similar to NanoID.
    Default uses base62 alphabet (A-Za-z0-9) with 21 characters.
    
    Args:
        length: Desired length (default: 21).
        alphabet: Optional custom alphabet (default: base62).
        
    Returns:
        Random identifier string.
        
    Example:
        >>> uid = nanoid()
        >>> len(uid)
        21
        >>> nanoid(10, alphabet="0123456789")
        '4819273650'
    """
    if alphabet is None:
        alphabet = ALPHABET
    
    if length < 1 or length > 128:
        raise ValueError("Length must be between 1 and 128")
    
    if not alphabet:
        raise ValueError("Alphabet cannot be empty")
    
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ulid() -> str:
    """Generate ULID (Universally Unique Lexicographically Sortable Identifier).
    
    ULIDs are 128-bit identifiers that are:
    - Lexicographically sortable
    - Canonically encoded as 26 character string
    - URL-safe (case insensitive)
    - Monotonic sort order (when generated in same millisecond)
    
    Returns:
        26-character ULID string.
        
    Example:
        >>> uid = ulid()
        >>> len(uid)
        26
        
    Note:
        This is a simplified implementation. For production use,
        consider using a dedicated ULID library.
    """
    import time
    
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" # Crockford's base32 alphabet (excludes I, L, O, U)

    timestamp_ms = int(time.time() * 1000) # Timestamp component (48 bits)
    random_bytes = os.urandom(10)          # Random component (80 bits)
    
    timestamp_part = "" # Encode timestamp (10 characters)
    for _ in range(10):
        timestamp_part = alphabet[timestamp_ms & 0x1F] + timestamp_part
        timestamp_ms >>= 5

    random_int = int.from_bytes(random_bytes, "big") # Encode random (16 characters)
    random_part = ""
    for _ in range(16):
        random_part = alphabet[random_int & 0x1F] + random_part
        random_int >>= 5
    
    return timestamp_part + random_part
