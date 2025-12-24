"""XOR obfuscation utilities

WARNING:
    XOR obfuscation is NOT cryptographically secure.
    Use only for non-security purposes such as:
    - Deterring casual inspection
    - Basic data mangling
    - Configuration file obfuscation
    
    DO NOT USE FOR:
    - Protecting passwords or credentials
    - Encrypting sensitive data
    - Any security-critical application
"""

from typing import Final, Union
import base64

_BASE64_PADDING: Final[str] = "="


def xor_obfuscate(s: str, key: Union[str, bytes]) -> str:
    """Obfuscate a string using XOR with a key, then encode as Base64 URL-safe.
    
    Args:
        s: The plaintext string to obfuscate.
        key: The key for XOR (string or bytes).
        
    Returns:
        Base64 URL-safe encoded obfuscated string without padding.
        
    Raises:
        ValueError: If key is empty.
        
    Example:
        >>> obfuscated = xor_obfuscate("secret", "key")
        >>> len(obfuscated) > 0
        True
        
    Warning:
        This is NOT secure encryption. Easily reversible with key.
    """
    if not key:
        raise ValueError("Key cannot be empty")
    
    key_bytes = key if isinstance(key, bytes) else key.encode("utf-8")
    text_bytes = s.encode("utf-8")
    
    result = bytes([
        text_bytes[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(text_bytes))
    ]) # XOR operation
    
    return base64.urlsafe_b64encode(result).decode("ascii").rstrip(_BASE64_PADDING)  # Encode as base64url without padding

def xor_deobfuscate(s_enc: str, key: Union[str, bytes]) -> str:
    """Deobfuscate a string previously obfuscated with xor_obfuscate.
    
    Args:
        s_enc: Base64 URL-safe encoded obfuscated string.
        key: The key used for XOR (must match obfuscation key).
        
    Returns:
        The original plaintext string.
        
    Raises:
        ValueError: If key is empty or decoding fails.
        
    Example:
        >>> obfuscated = xor_obfuscate("secret", "key")
        >>> deobfuscated = xor_deobfuscate(obfuscated, "key")
        >>> deobfuscated
        'secret'
    """
    if not key:
        raise ValueError("Key cannot be empty")
    
    try:
        padding = (4 - len(s_enc) % 4) % 4 # Add padding if needed
        if padding:                        # Verify padding
            s_enc += _BASE64_PADDING * padding
        
        encoded_bytes = base64.urlsafe_b64decode(s_enc) # Decode from base64url
        
        key_bytes = key if isinstance(key, bytes) else key.encode("utf-8") # XOR operation
        result = bytes([
            encoded_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(encoded_bytes))
        ])
        
        return result.decode("utf-8")
        
    except Exception as e:
        raise ValueError(f"Failed to deobfuscate: {e}")


def rot13(s: str) -> str:
    """Apply ROT13 cipher to a string.
    
    ROT13 is a simple letter substitution cipher that replaces
    a letter with the 13th letter after it in the alphabet.
    
    Args:
        s: String to transform.
        
    Returns:
        ROT13 transformed string.
        
    Example:
        >>> rot13("Hello World")
        'Uryyb Jbeyq'
        >>> rot13(rot13("Hello World"))
        'Hello World'
        
    Note:
        ROT13 is its own inverse (applying it twice returns original).
        Not secure - purely for obfuscation.
    """
    result = []
    for char in s:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def caesar_cipher(s: str, shift: int = 3) -> str:
    """Apply Caesar cipher to a string.
    
    Shifts each letter by a fixed number of positions in the alphabet.
    
    Args:
        s: String to transform.
        shift: Number of positions to shift (default: 3).
        
    Returns:
        Caesar cipher transformed string.
        
    Example:
        >>> caesar_cipher("Hello", 3)
        'Khoor'
        >>> caesar_cipher("Khoor", -3)
        'Hello'
    """
    result = []
    shift = shift % 26  # Normalize shift
    
    for char in s:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    
    return ''.join(result)


def base64_encode(s: str) -> str:
    """Encode string as standard base64.
    
    Args:
        s: String to encode.
        
    Returns:
        Base64 encoded string.
        
    Example:
        >>> base64_encode("Hello World")
        'SGVsbG8gV29ybGQ='
    """
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def base64_decode(s: str) -> str:
    """Decode base64 encoded string.
    
    Args:
        s: Base64 encoded string.
        
    Returns:
        Decoded string.
        
    Raises:
        ValueError: If input is not valid base64.
        
    Example:
        >>> base64_decode("SGVsbG8gV29ybGQ=")
        'Hello World'
    """
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decode base64: {e}")


def reverse_string(s: str) -> str:
    """Reverse a string.
    
    Args:
        s: String to reverse.
        
    Returns:
        Reversed string.
        
    Example:
        >>> reverse_string("Hello")
        'olleH'
    """
    return s[::-1]
