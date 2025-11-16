"""
Common utility helpers for SecureChat.

- now_ms(): current UTC time in milliseconds since Unix epoch
- b64e():   base64-encode bytes -> string
- b64d():   base64-decode string -> bytes
- sha256_hex(): SHA-256 digest of bytes, as lowercase hex string
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Union


def now_ms() -> int:
    """
    Return current UTC time in milliseconds since Unix epoch.

    Used for message timestamps so both sides can reason about ordering/freshness.
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64-encode raw bytes and return a UTF-8 string.

    This is useful for safely putting binary data (ciphertext, signatures, etc.)
    into JSON messages.
    """
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b64e expects bytes or bytearray")
    return base64.b64encode(bytes(b)).decode("ascii")


def b64d(s: str) -> bytes:
    """
    Base64-decode a string into raw bytes.

    Inverse of b64e().
    """
    if not isinstance(s, str):
        raise TypeError("b64d expects a string")
    return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: Union[bytes, bytearray]) -> str:
    """
    Compute SHA-256 digest of `data` and return it as a lowercase hex string.

    This is the building block for:
      - message digests you sign with RSA
      - transcript hashes for session receipts
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sha256_hex expects bytes or bytearray")
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()
