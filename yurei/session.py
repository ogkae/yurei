"""WARNING:
- Not JWT-compatible.
- Lightweight and suitable for prototypes or internal tools."""

from .helpers import b64u_encode, b64u_decode, constant_time_eq, now_millis
from typing import Dict, Optional
import hashlib
import hmac

def create_token(
    payload: Dict[str, str], secret: bytes, ttl_seconds: int = 3600
) -> str:
    """
    Create a simple token with a payload dictionary and HMAC-SHA256 signature.

    Token format:
        base64url(payload);base64url(signature)

    Args:
        payload (Dict[str, str]): Arbitrary key-value pairs to include.
        secret (bytes): Secret key used to sign the token.
        ttl_seconds (int): Time-to-live in seconds (default 3600s).

    Returns:
        str: Token string containing the payload and signature.
    """
    if not secret or len(secret) < 16:
        raise ValueError("Secret must be at least 16 bytes")
    
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    
    exp = now_millis() + ttl_seconds * 1000
    
    # more efficient payload construction
    parts = [f"{k}={v}" for k, v in payload.items()]
    parts.append(f"exp={exp}")
    raw = ";".join(parts).encode("utf-8")
    
    raw_b64 = b64u_encode(raw)
    raw_b64_bytes = raw_b64.encode("ascii")
    
    sig = hmac.new(secret, raw_b64_bytes, hashlib.sha256).digest()
    sig_b64 = b64u_encode(sig)
    
    return f"{raw_b64}.{sig_b64}"

def verify_token(token: str, secret: bytes) -> Optional[Dict[str, str]]:
    """
    Verify an HMAC-signed token and return the payload if valid and unexpired.

    Args:
        token (str): Token string produced by `create_token`.
        secret (bytes): Secret key used to verify the token.

    Returns:
        Optional[Dict[str, str]]: Payload dictionary without the 'exp' key
        if verification succeeds; otherwise, None.
    """
    if not secret or len(secret) < 16:
        return None
    
    try:
        # basic format validation
        if "." not in token:
            return None
        
        raw_b64, sig_b64 = token.split(".", 1)
        
        # avoid empty tokens
        if not raw_b64 or not sig_b64:
            return None
        
        sig = b64u_decode(sig_b64)
        raw_b64_bytes = raw_b64.encode("ascii")
        
        expected = hmac.new(secret, raw_b64_bytes, hashlib.sha256).digest()
        
        if not constant_time_eq(sig, expected):
            return None

        raw = b64u_decode(raw_b64)
        s = raw.decode("utf-8")
        
        items = {}
        for part in s.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            items[k] = v

        exp_str = items.get("exp", "0")
        try:
            exp = int(exp_str)
        except ValueError:
            return None
        
        # verify expiration
        if now_millis() > exp:
            return None

        items.pop("exp", None)
        return items
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
