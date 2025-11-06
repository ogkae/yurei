import hmac
import hashlib
from typing import Dict, Optional
from .helpers import b64u_encode, b64u_decode, constant_time_eq, now_millis

def create_token(payload: Dict[str,str], secret: bytes, ttl_seconds: int = 3600) -> str:
    """
    create token w simple payload (key=value;...;exp=ms).
    return: (raw_b64.signature_b64)
    """
    exp = now_millis() + ttl_seconds * 1000
    parts = [f"{k}={v}" for k,v in payload.items()]
    parts.append(f"exp={exp}")
    raw = ";".join(parts).encode('utf-8')
    raw_b64 = b64u_encode(raw)
    sig = hmac.new(secret, raw_b64.encode('ascii'), hashlib.sha256).digest()
    return f"{raw_b64}.{b64u_encode(sig)}"

def verify_token(token: str, secret: bytes) -> Optional[Dict[str,str]]:
    """verify firm and expiry; return payload dict (without exp) / None."""
    try:
        raw_b64, sig_b64 = token.split('.', 1)
        sig = b64u_decode(sig_b64)
        expected = hmac.new(secret, raw_b64.encode('ascii'), hashlib.sha256).digest()
        if not constant_time_eq(sig, expected):
            return None
        raw = b64u_decode(raw_b64)
        s = raw.decode('utf-8')
        items = {}
        for part in s.split(';'):
            if '=' not in part:
                continue
            k, v = part.split('=', 1)
            items[k] = v
        exp = int(items.get('exp', '0'))
        if now_millis() > exp:
            return None
        items.pop('exp', None)
        return items
    except Exception:

        return None
