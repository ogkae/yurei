"""lightweight session token management with hmac signatures

provides simple authenticated tokens with expiration:
- hmac-sha256 signatures
- automatic expiration handling
- compact format (not jwt-compatible)

warning:
    not jwt-compatible. designed for internal/prototype use.
    for production apis, consider using pyjwt or python-jose
    
token format:
    base64url(payload).base64url(hmac_signature)
    
    payload contains:
    - user-provided key-value pairs
    - exp=<timestamp_ms> (added automatically)
"""

from .helpers import b64u_encode, b64u_decode, constant_time_eq, now_millis
from typing import Dict, Optional
import hashlib
import hmac

def create_token(
    payload: Dict[str, str],
    secret: bytes,
    ttl_seconds: int = 3600
) -> str:
    """create signed token with expiration
    
    generates compact token containing payload and hmac signature
    
    args:
        payload (dict[str, str]): key-value pairs to include
        secret (bytes): secret key for signing (min 16 bytes)
        ttl_seconds (int): time-to-live in seconds (default: 1 hour)
        
    returns:
        str: signed token string
        
    raises:
        ValueError: if secret too short or ttl invalid
        
    example:
        >>> import os
        >>> secret = os.urandom(32)
        >>> token = create_token({"uid": "123", "role": "admin"}, secret, 3600)
        >>> print(token)
        'eyJ1aWQiOiIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDk1NjMyMDB9.a7b8c9...'
        
    security:
        - hmac-sha256 signature prevents tampering
        - expiration enforced automatically
        - secret must be kept confidential
        - recommend 32-byte random secret
        
    use cases:
        - api authentication tokens
        - session identifiers
        - short-lived authorization grants
    """
    if not secret or len(secret) < 16:
        raise ValueError("secret must be at least 16 bytes")
    
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    
    exp = now_millis() + ttl_seconds * 1000
    
    # construct payload string: key1=val1;key2=val2;exp=timestamp
    parts = [f"{k}={v}" for k, v in payload.items()]
    parts.append(f"exp={exp}")
    raw = ";".join(parts).encode("utf-8")
    
    raw_b64 = b64u_encode(raw)
    raw_b64_bytes = raw_b64.encode("ascii")
    
    sig = hmac.new(secret, raw_b64_bytes, hashlib.sha256).digest()
    sig_b64 = b64u_encode(sig)
    
    return f"{raw_b64}.{sig_b64}"


def verify_token(token: str, secret: bytes) -> Optional[Dict[str, str]]:
    """verify hmac-signed token and extract payload
    
    validates signature and expiration, returns payload if valid
    
    args:
        token (str): token string from create_token()
        secret (bytes): secret key used for signing
        
    returns:
        dict[str, str] or None: payload without 'exp' key if valid,
                                 none if invalid or expired
                                 
    example:
        >>> token = create_token({"uid": "123"}, secret, 3600)
        >>> payload = verify_token(token, secret)
        >>> print(payload)
        {'uid': '123'}
        >>> verify_token(token, b"wrong_secret")
        None
        
    security:
        - constant-time signature verification
        - rejects expired tokens
        - safe against malformed input
        - validates before processing
        
    failure cases:
        - invalid signature (tampering)
        - expired token
        - malformed token format
        - wrong secret key
    """
    if not secret or len(secret) < 16:
        return None
    
    try:

        if "." not in token:
            return None
        
        raw_b64, sig_b64 = token.split(".", 1)

        if not raw_b64 or not sig_b64:
            return None

        sig = b64u_decode(sig_b64)
        raw_b64_bytes = raw_b64.encode("ascii")
        
        expected = hmac.new(secret, raw_b64_bytes, hashlib.sha256).digest()
        
        if not constant_time_eq(sig, expected):
            return None

        raw = b64u_decode(raw_b64) # decode payload
        s = raw.decode("utf-8")
        items = {}
        for part in s.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            items[k] = v

        exp_str = items.get("exp", "0") # extract and validate expiration
        try:
            exp = int(exp_str)
        except ValueError:
            return None
        
        if now_millis() > exp: # check if token expired
            return None

        items.pop("exp", None) # remove expiration from returned payload
        return items
        
    except (ValueError, TypeError, UnicodeDecodeError):
        return None # any error during processing = invalid token

