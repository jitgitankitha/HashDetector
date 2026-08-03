"""
utils.py
========
Small, stateless helper functions used by rules.py and detector.py.
Nothing in here should know about HashMatch / scoring — pure string/byte
level utilities only, so they're trivially unit-testable.
"""

import base64
import binascii

from .constants import HEX_RE, BASE64_RE, BASE64URL_RE, DELIMITERS


def is_hex(value: str) -> bool:
    """True if value is a non-empty string of only hex digits."""
    return bool(value) and bool(HEX_RE.match(value))


def is_base64(value: str) -> bool:
    """True if value looks like standard base64 (loose charset check)."""
    if not value or len(value) % 4 != 0:
        return False
    return bool(BASE64_RE.match(value))


def is_base64url(value: str) -> bool:
    """True if value looks like URL-safe base64 (used by JWT etc.)."""
    return bool(value) and bool(BASE64URL_RE.match(value))


def decoded_byte_length(value: str) -> int | None:
    """
    Attempt to base64-decode `value` and return the decoded byte length.
    Returns None if it isn't valid base64.
    """
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.b64decode(padded, validate=True)
        return len(raw)
    except (binascii.Error, ValueError):
        return None


def strip_known_delimiters(value: str) -> list[str]:
    """
    Split a value on common hash-dump delimiters (':', ';', '$', '*')
    only when it looks like a compound record (e.g. 'hash:salt' or
    'user:hash'). Returns the original single-item list if no split helps.
    """
    for delim in DELIMITERS:
        if delim in value:
            parts = [p for p in value.split(delim) if p]
            if len(parts) > 1:
                return parts
    return [value]


def normalize(value: str) -> str:
    """Trim whitespace/newlines a user might paste in accidentally."""
    return value.strip()


def hex_length(value: str) -> int:
    """Character length, assuming value is already confirmed hex."""
    return len(value)
