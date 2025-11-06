from typing import Union
import base64

def xor_obfuscate(s: str, key: Union[str, bytes]) -> str:
    kb = key if isinstance(key, bytes) else key.encode('utf-8')
    b = s.encode('utf-8')
    out = bytes([b[i] ^ kb[i % len(kb)] for i in range(len(b))])
    return base64.urlsafe_b64encode(out).decode('ascii').rstrip('=')

def xor_deobfuscate(s_enc: str, key: Union[str, bytes]) -> str:
    pad = '=' * (-len(s_enc) % 4)
    b = base64.urlsafe_b64decode(s_enc + pad)
    kb = key if isinstance(key, bytes) else key.encode('utf-8')
    out = bytes([b[i] ^ kb[i % len(kb)] for i in range(len(b))])
    return out.decode('utf-8')