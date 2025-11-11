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
    exp = now_millis() + ttl_seconds * 1000
    parts = [f"{k}={v}" for k, v in payload.items()]
    parts.append(f"exp={exp}")
    raw = ";".join(parts).encode("utf-8")
    raw_b64 = b64u_encode(raw)
    sig = hmac.new(secret, raw_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{raw_b64}.{b64u_encode(sig)}"

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
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        sig = b64u_decode(sig_b64)
        expected = hmac.new(raw_b64.encode("ascii"), secret, hashlib.sha256).digest()
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

        exp = int(items.get("exp", "0"))
        if now_millis() > exp:
            return None

        items.pop("exp", None)
        return items
    except Exception:
        return None
