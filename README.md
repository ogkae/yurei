# yurei

ZDP Python library for encryption, authentication, and secure identifier generation.

![Version](https://img.shields.io/badge/2.1.0-stable-5d5d5d?style=flat-square&logo=python) ![Python](https://img.shields.io/badge/python-3.8+-5d5d5d?style=flat-square&logo=python) [![Give a star](https://img.shields.io/badge/Give%20a%20⭐-%20-5d5d5d?style=flat-square&logo=github)](https://github.com/ogcae/yurei/stargazers)

**Yurei** *(幽霊 - ghost)* provides cryptographic primitives for modern Python applications without external dependencies. Built for prototyping secure systems, internal tools, and environments where dependency installation is restricted.

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Modules](#modules)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Data Formats](#data-formats)
- [Security](#security)
- [Deployment](#deployment)
<!-- - [FAQ](#faq) -->

---

## Install

```bash
$ git clone https://github.com/ogcae/yurei
$ cd yurei
$ pip install -e .
```

<!-- 
**Run tests:**
```bash
$ python -m pytest tests/
$ python main.py  # examples
```
-->

---

## Quick Start

```python
from yurei import (
    uuid4, hash_password, verify_password,
    create_token, verify_token,
    encrypt_bytes, decrypt_bytes,
    KVStore
)

# generate secure id
user_id = uuid4()  # '550e8400-e29b-41d4-a716-446655440000'

# hash password
pwd_hash = hash_password("SecurePass123")

# create session token
token = create_token({"uid": user_id}, b"secret-key", ttl_seconds=3600)

# encrypt data
blob  = encrypt_bytes(b"sensitive data", b"passphrase")
plain = decrypt_bytes(blob, b"passphrase")
```

---

## Modules

| module | description | key functions |
|--------|-------------|---------------|
| `uid` | uuid4, deterministic sha256 ids, short tokens | `uuid4()`, `sha256_id()`, `short_id()` |
| `auth` | password hashing (pbkdf2-hmac-sha256) | `hash_password()`, `verify_password()` |
| `session` | signed tokens with hmac | `create_token()`, `verify_token()` |
| `cipher` | symmetric encryption + authentication | `encrypt_bytes()`, `decrypt_bytes()` |
| `cipher_parallel` | parallel chunked encryption | `encrypt_parallel()`, `decrypt_parallel()` |
| `store` | key-value storage (sqlite/memory) | `KVStore.set()`, `KVStore.get()` |
| `obfusc` | xor obfuscation utilities | `xor_obfuscate()`, `xor_deobfuscate()` |
| `utils` | base64url, pbkdf2, timing-safe compare | `b64u_encode()`, `constant_time_eq()` |

---

## API Reference

### `uid` - Identifier Generation

```python
uuid4() -> str
```
Generate random UUID4 (format: `8-4-4-4-12`).

```python
is_uuid4(s: str) -> bool
```
Validate UUID4 format.

```python
sha256_id(namespace: Optional[str], name: str, salt: Optional[str] = None) -> str
```
Deterministic 64-character hex ID from SHA256.

```python
short_id(length: int = 12) -> str
```
URL-safe alphanumeric token.

**Example:**
```python
from yurei import uuid4, sha256_id, short_id

user_id = uuid4()                                      # random
doc_id  = sha256_id("documents", "report_2024.pdf")    # deterministic
token   = short_id(16)                                 # url-safe
```

---

### `auth` - Password Hashing

```python
hash_password(password: str, iterations: int = 200_000) -> str
```
PBKDF2-HMAC-SHA256 hash. Returns format:  
`pbkdf2$<iterations>$<salt_b64url>$<hash_b64url>`

```python
verify_password(stored: str, attempt: str) -> bool
```
Constant-time password verification.

**Example:**
```python
from yurei import hash_password, verify_password

# registration
pwd_hash = hash_password("MySecret123")

# login
is_valid = verify_password(pwd_hash, "MySecret123")  # True
```

---

### `session` - Token Management

```python
create_token(payload: Dict[str, str], secret: bytes, ttl_seconds: int = 3600) -> str
```
Create signed token. Format: `<payload_b64>.<signature_b64>`

```python
verify_token(token: str, secret: bytes) -> Optional[Dict[str, str]]
```
Verify signature and expiration. Returns payload dict.

**Example:**
```python
from yurei import create_token, verify_token
import os

secret = os.urandom(32)

# create
token = create_token(
    {
    "uid": "user_123",
    "role": "admin"
    },
    secret,
    ttl_seconds=3600
)

# verify
payload = verify_token(token, secret)
if payload:
    print(f"User: {payload['uid']}, Role: {payload['role']}")
```

---

### `cipher` - Encryption

```python
encrypt_bytes(plaintext: bytes, key: bytes) -> str
```
Encrypt with HMAC-SHA256 authentication. Returns base64url string.

**Key types:**
- Passphrase (any length) → derives encryption + MAC keys via PBKDF2
- Raw 32-byte key → used directly

**Format:** `salt(16) + nonce(12) + ciphertext + mac(32)` → base64url

```python
decrypt_bytes(blob_b64: str, key: bytes) -> bytes
```
Decrypt and verify MAC (constant-time).

**Example:**
```python
from yurei import encrypt_bytes, decrypt_bytes

# with passphrase
blob  = encrypt_bytes(b"sensitive data", b"my-passphrase")
plain = decrypt_bytes(blob, b"my-passphrase")

# with raw key
key   = os.urandom(32)
blob  = encrypt_bytes(b"data", key)
plain = decrypt_bytes(blob, key)
```

---

### `cipher_parallel` - Large File Encryption

```python
encrypt_parallel(
    plaintext:  bytes,
    password:   bytes,
    chunk_size: int = 128 * 1024,
    workers:    Optional[int] = None
) -> str
```
Multi-process encryption for large data. Returns base64url blob.

```python
decrypt_parallel(
    blob_b64: str,
    password: bytes,
    workers: Optional[int] = None
) -> bytes
```
Parallel decryption with global MAC verification.

**Example:**
```python
from yurei import encrypt_parallel, decrypt_parallel
large_file = b"x" * (50 * 1024 * 1024)  # 50 MB

# encrypt w 4 workers, 256KB chunks
blob = encrypt_parallel(large_file, b"key", chunk_size=256*1024, workers=4)

# decrypt
plain = decrypt_parallel(blob, b"key", workers=4)
```

**Performance:** ~4x faster on quad-core systems for files >10MB.

---

### `store` - Key-Value Storage

```python
class KVStore(path: Optional[str] = None)
```

**Methods:**
```python
set(key: str, value: Dict) -> None
get(key: str) -> Optional[Dict]
delete(key: str) -> None
```

- `path=None`      → in-memory dict
- `path="file.db"` → persistent SQLite

**Example:**
```python
from yurei import KVStore

# in-memory
store = KVStore()
store.set("user_123", {"name": "alice", "role": "admin"})

# persistent
db = KVStore("data.db")
db.set("session_456", {"uid": "user_123", "exp": 1234567890})
record = db.get("session_456")
```

---

### `obfusc` - Obfuscation

```python
xor_obfuscate(s: str, key: Union[str, bytes]) -> str
```
XOR with repeating key + base64url encoding.

```python
xor_deobfuscate(s_enc: str, key: Union[str, bytes]) -> str
```
Reverse XOR obfuscation.

**Example:**
```python
from yurei import xor_obfuscate, xor_deobfuscate

# hide connection string
conn_str = "postgres://user:pass@localhost/db"
hidden = xor_obfuscate(conn_str, b"salt")

# restore
original = xor_deobfuscate(hidden, b"salt")
```


> [!WARNING]  
> *[XOR obfuscation is NOT encryption. Use only for deterring casual inspection.]*

---

### `utils` - Helpers

```python
now_millis() -> int                           # current unix timestamp (ms)
to_hex(b: bytes) -> str                       # bytes to hex
b64u_encode(b: bytes) -> str                  # base64url encode
b64u_decode(s: str) -> bytes                  # base64url decode
constant_time_eq(a: bytes, b: bytes) -> bool  # timing-safe comparison
pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes
```

---

## Usage Examples

### Complete User Authentication Flow

```python
from yurei import (
    uuid4, hash_password, verify_password,
    create_token, verify_token, KVStore
)
import os

# setup
store = KVStore("users.db")
session_secret = os.urandom(32)

# --- REGISTRATION ---
def register(username: str, password: str):
    user_id = uuid4()
    pwd_hash = hash_password(password)
    store.set(user_id, {
        "username": username,
        "pwd": pwd_hash,
        "created": now_millis()
    })
    return user_id

# --- LOGIN ---
def login(user_id: str, password: str):
    record = store.get(user_id)
    if not record:
        return None
    
    if verify_password(record["pwd"], password):
        token = create_token(
            {"uid": user_id, "username": record["username"]},
            session_secret,
            ttl_seconds=86400  # 24h
        )
        return token
    return None

# --- VERIFY SESSION ---
def verify_session(token: str):
    payload = verify_token(token, session_secret)
    return payload  # None if invalid/expired

# usage
user_id = register("alice", "SecurePass123")
token = login(user_id, "SecurePass123")
session = verify_session(token)
print(f"Logged in: {session['username']}")
```

---

### Secure File Storage

```python
from yurei import encrypt_bytes, decrypt_bytes, sha256_id
import os

class SecureFileStore:
    def __init__(self, key: bytes):
        self.key = key
    
    def save(self, filename: str, data: bytes) -> str:
        # generate deterministic id
        file_id = sha256_id("files", filename)
        
        # encrypt
        blob = encrypt_bytes(data, self.key)
        
        # store (simplified - use real storage)
        with open(f"vault/{file_id}.enc", "w") as f:
            f.write(blob)
        
        return file_id
    
    def load(self, file_id: str) -> bytes:
        with open(f"vault/{file_id}.enc") as f:
            blob = f.read()
        return decrypt_bytes(blob, self.key)

# usage
vault = SecureFileStore(os.urandom(32))
file_id = vault.save("report.pdf", b"pdf content...")
content = vault.load(file_id)
```

---

### Configuration Obfuscation

```python
from yurei import xor_obfuscate, xor_deobfuscate

# at build time - obfuscate sensitive config
config = {
    "db": "postgres://user:pass@host/db",
    "api_key": "sk_live_abc123xyz",
    "secret": "dont-commit-this"
}

OBFUSC_KEY = b"random-build-salt"

obfuscated = {
    k: xor_obfuscate(v, OBFUSC_KEY)
    for k, v in config.items()
}

# at runtime - deobfuscate
runtime_config = {
    k: xor_deobfuscate(v, OBFUSC_KEY)
    for k, v in obfuscated.items()
}
```

---

## Data Formats

### Password Hash
```
pbkdf2$<iterations>$<salt_b64url>$<hash_b64url>
```
**Example:**
```
pbkdf2$200000$aGVsbG93b3JsZA$dGhpc2lzYWhhc2g
```

### Session Token
```
<payload_b64>.<signature_b64>
```
**Payload format:** `k=v;k2=v2;exp=<unix_ms>`

### Cipher Blob (Simple)
```
salt(16) + nonce(12) + ciphertext + mac(32) → base64url
```

### Cipher Blob (Parallel)
```
Header:
  MAGIC: 'FCRT' (4 bytes)
  VERSION: 1 (1 byte)
  salt: 16 bytes
  gnonce: 12 bytes
  chunk_size: 4 bytes (uint32 big-endian)
  iterations: 4 bytes (uint32)
  num_chunks: 4 bytes (uint32)

Body:
  [chunk_len(4)][ciphertext][mac(32)] × num_chunks

Footer:
  global_mac: 32 bytes
```

---

## Security

### Cryptographic Primitives

| component | algorithm | parameters |
|-----------|-----------|------------|
| password hashing | PBKDF2-HMAC-SHA256 | 200k iterations, 16-byte salt |
| key derivation | PBKDF2-HMAC-SHA256 | 100k iterations |
| mac | HMAC-SHA256 | 32-byte output |
| encryption | hmac-based stream | 12-byte nonce |
| random | `os.urandom` | cryptographically secure |
| comparison | `hmac.compare_digest` | constant-time |

### Security Features

`✅` Constant-time password/MAC verification  
`✅` Secure random generation (`os.urandom`)  
`✅` Authenticated encryption (encrypt-then-MAC)  
`✅` Perchunk + global MAC in parallel mode  
`✅` Salt + nonce included in ciphertext  

### Limitations

> [!WARNING]  
> - Cipher uses HMAC-SHA256 stream, not AES-GCM or ChaCha20-Poly1305
> - No hardware acceleration (AES-NI)
> - PBKDF2 is weaker than Argon2id against GPU attacks
> - XOR obfuscation provides minimal security
> 
> *[Not a replacement for audited libraries]*

### Recommendations

| concern | recommendation |
|---------|----------------|
| **production systems** | migrate to `cryptography` or `pynacl` |
| **password hashing** | use Argon2id for new passwords |
| **key storage** | use vault/secret manager (AWS Secrets Manager, HashiCorp Vault) |
| **transport** | always use TLS/HTTPS |
| **key rotation** | implement version field in tokens |
| **auditing** | fuzz test critical paths |

### Attack Surface

```python
# ❌ NO
key = b"hardcoded-secret"  # committed to git
token = create_token(payload, key)

# ✅ YES
key = os.environ["SESSION_SECRET"].encode()
if len(key) < 32:
    raise ValueError("SECRET must be 32+ bytes")
```

---

## Deployment

### Environment Setup

```bash
# generate secure secret
$ python -c "import os; print(os.urandom(32).hex())"

# set environment
export YUREI_IDS_SESSION_SECRET="your-64-char-hex-string"
export YUREI_IDS_DB_PATH="/secure/path/users.db"
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -e .

# restrict permissions
RUN chmod 600 /app/data.db

ENV YUREI_IDS_SESSION_SECRET=""
CMD ["python", "main.py"]
```

### Performance Tuning

| scenario | recommendation |
|----------|----------------|
| files < 1MB | use `encrypt_bytes()` |
| files > 10MB | use `encrypt_parallel()` with 4+ workers |
| chunk size | 128KB-512KB (balance memory/speed) |
| iterations | 200k for passwords, 100k for KDF |
| database | use WAL mode for SQLite (`PRAGMA journal_mode=WAL`) |

---

## Migration Path

### To Audited Libraries

```python
# BEFORE (yurei)
from yurei import encrypt_bytes, decrypt_bytes
blob = encrypt_bytes(data, key)

# AFTER (cryptography)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
cipher = ChaCha20Poly1305(key)
blob = cipher.encrypt(nonce, data, None)
```

### Password Hashing Migration

```python
# new users: argon2
import argon2
ph = argon2.PasswordHasher()
hash = ph.hash(password)

# existing users: keep yurei hashes, migrate on next login
if stored_hash.startswith("pbkdf2$"):
    if verify_password(stored_hash, password):
        # update to argon2
        new_hash = ph.hash(password)
        store.set(user_id, {"pwd": new_hash})
```

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting PRs.

**Priority areas:**
- [ ] Comprehensive test suite (pytest)
- [ ] Benchmark suite (encryption throughput)
- [ ] Streaming encryption API
- [ ] Key rotation utilities
- [ ] Optional Argon2id support

---

## Contributors

<a href="https://github.com/ogcae/yurei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ogcae/yurei" />
</a>

---

made with <a href="https://github.com/hexa-hosting"><code>hexaʰ</code></a> by <a href="https://github.com/ogkae"><code>ogkae</code></a>

<a href="./LICENSE"><code>LICENSE</code></a> · <a href="./CONTRIBUTING.md"><code>CONTRIBUTE</code></a> · <a href="./CHANGELOG.md"><code>CHANGELOG</code></a>
