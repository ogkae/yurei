"""Lightweight session token management with HMAC signatures

Provides simple authenticated tokens with expiration:
- HMAC-SHA256 signatures
- Automatic expiration handling
- Compact format (not JWT-compatible)

Warning:
    Not JWT-compatible. Designed for internal/prototype use.
    For production APIs, consider using PyJWT or python-jose.

Token format:
    base64url(payload).base64url(hmac_signature)
    
    Payload contains:
    - User-provided key-value pairs
    - exp=<timestamp_ms> (added automatically)
"""

from typing import Dict, Final, Optional
import hashlib
import json
import hmac

from .helpers import b64u_encode, b64u_decode, constant_time_eq, now_millis

# Configuration constants
_MIN_SECRET_LEN: Final[int] = 16
_MAX_TTL_SECONDS: Final[int] = 86400 * 30  # 30 days
_TOKEN_SEPARATOR: Final[str] = "."


def create_token(
    payload: Dict[str, str],
    secret: bytes,
    ttl_seconds: int = 3600
) -> str:
    """Create signed token with expiration.
    
    Generates compact token containing payload and HMAC signature.
    
    Args:
        payload: Key-value pairs to include.
        secret: Secret key for signing (min 16 bytes).
        ttl_seconds: Time-to-live in seconds (default: 1 hour).
        
    Returns:
        Signed token string.
        
    Raises:
        ValueError: If secret too short or TTL invalid.
        
    Example:
        >>> import os
        >>> secret = os.urandom(32)
        >>> token = create_token({"uid": "123", "role": "admin"}, secret, 3600)
        >>> len(token) > 0
        True
        
    Security:
        - HMAC-SHA256 signature prevents tampering
        - Expiration enforced automatically
        - Secret must be kept confidential
        - Recommend 32-byte random secret
        
    Use cases:
        - API authentication tokens
        - Session identifiers
        - Short-lived authorization grants
    """
    if not secret or len(secret) < _MIN_SECRET_LEN:
        raise ValueError(f"Secret must be at least {_MIN_SECRET_LEN} bytes")
    
    if ttl_seconds <= 0:
        raise ValueError("TTL must be positive")
    
    if ttl_seconds > _MAX_TTL_SECONDS:
        raise ValueError(f"TTL must be <= {_MAX_TTL_SECONDS} seconds")
    
    # Add expiration to payload
    exp = now_millis() + ttl_seconds * 1000
    token_data = payload.copy()
    token_data["exp"] = str(exp)
    
    # Serialize payload as JSON
    payload_json = json.dumps(token_data, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    
    # Encode payload
    payload_b64 = b64u_encode(payload_bytes)
    
    # Sign payload
    sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    sig_b64 = b64u_encode(sig)
    
    return f"{payload_b64}{_TOKEN_SEPARATOR}{sig_b64}"


def verify_token(token: str, secret: bytes) -> Optional[Dict[str, str]]:
    """Verify HMAC-signed token and extract payload.
    
    Validates signature and expiration, returns payload if valid.
    
    Args:
        token: Token string from create_token().
        secret: Secret key used for signing.
        
    Returns:
        Payload without 'exp' key if valid, None if invalid or expired.
        
    Example:
        >>> token = create_token({"uid": "123"}, secret, 3600)
        >>> payload = verify_token(token, secret)
        >>> payload["uid"]
        '123'
        >>> verify_token(token, b"wrong_secret")
        
    Security:
        - Constant-time signature verification
        - Rejects expired tokens
        - Safe against malformed input
        - Validates before processing
        
    Failure cases:
        - Invalid signature (tampering)
        - Expired token
        - Malformed token format
        - Wrong secret key
    """
    if not secret or len(secret) < _MIN_SECRET_LEN:
        return None
    
    if not token or _TOKEN_SEPARATOR not in token:
        return None
    
    try:
        # Split token
        parts = token.split(_TOKEN_SEPARATOR, 1)
        if len(parts) != 2:
            return None
        
        payload_b64, sig_b64 = parts
        
        if not payload_b64 or not sig_b64:
            return None
        
        # Verify signature (constant-time)
        sig = b64u_decode(sig_b64)
        expected = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        
        if not constant_time_eq(sig, expected):
            return None
        
        # Decode payload
        payload_bytes = b64u_decode(payload_b64)
        payload_json = payload_bytes.decode("utf-8")
        token_data = json.loads(payload_json)
        
        if not isinstance(token_data, dict):
            return None
        
        # Extract and validate expiration
        exp_str = token_data.get("exp")
        if not exp_str:
            return None
        
        try:
            exp = int(exp_str)
        except (ValueError, TypeError):
            return None
        
        # Check if token expired
        if now_millis() > exp:
            return None
        
        # Remove expiration from returned payload
        result = {k: v for k, v in token_data.items() if k != "exp"}
        return result
        
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def refresh_token(token: str, secret: bytes, new_ttl_seconds: int = 3600) -> Optional[str]:
    """Refresh an existing token with new expiration time.
    
    Args:
        token: Existing valid token.
        secret: Secret key.
        new_ttl_seconds: New TTL in seconds.
        
    Returns:
        New token with same payload but updated expiration, or None if invalid.
        
    Example:
        >>> token = create_token({"uid": "123"}, secret, 60)
        >>> refreshed = refresh_token(token, secret, 3600)
        >>> refreshed is not None
        True
    """
    payload = verify_token(token, secret)
    if payload is None:
        return None
    
    return create_token(payload, secret, new_ttl_seconds)
