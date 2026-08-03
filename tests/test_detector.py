"""
test_detector.py
=================
Basic unit tests covering each module. Run with:
    pytest tests/
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector.utils import is_hex, is_base64, decoded_byte_length, strip_known_delimiters
from detector.rules import match_prefix_rules, match_hex_length_rules
from detector.confidence import score_matches
from detector.detector import identify, identify_compound
from detector.models import Tier


# ---------------------------------------------------------------------------
# utils.py
# ---------------------------------------------------------------------------

def test_is_hex_true():
    assert is_hex("deadbeef")
    assert is_hex("0123456789abcdefABCDEF")


def test_is_hex_false():
    assert not is_hex("not-hex!")
    assert not is_hex("")


def test_is_base64_basic():
    assert is_base64("SGVsbG8gV29ybGQ=")  # "Hello World"


def test_decoded_byte_length():
    # base64 of 16 zero bytes
    import base64
    encoded = base64.b64encode(b"\x00" * 16).decode()
    assert decoded_byte_length(encoded) == 16


def test_strip_known_delimiters_splits():
    parts = strip_known_delimiters("admin:5f4dcc3b5aa765d61d8327deb882cf99")
    assert parts == ["admin", "5f4dcc3b5aa765d61d8327deb882cf99"]


def test_strip_known_delimiters_noop():
    parts = strip_known_delimiters("5f4dcc3b5aa765d61d8327deb882cf99")
    assert parts == ["5f4dcc3b5aa765d61d8327deb882cf99"]


# ---------------------------------------------------------------------------
# rules.py
# ---------------------------------------------------------------------------

def test_prefix_rule_bcrypt():
    bcrypt_hash = "$2b$12$KIXQeuSK6BqZ1HbCiOL1eO7Nq2xzWQ3l4vF6XwXbY1s3nq8XyPz2K"
    matches = match_prefix_rules(bcrypt_hash)
    names = [m.name for m in matches]
    assert "bcrypt" in names


def test_prefix_rule_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
    matches = match_prefix_rules(jwt)
    names = [m.name for m in matches]
    assert "JWT (JSON Web Token)" in names


def test_length_rule_md5_size():
    md5_like = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
    matches = match_hex_length_rules(md5_like)
    names = [m.name for m in matches]
    assert "MD5" in names
    assert "NTLM" in names  # ambiguous by design at this stage


def test_length_rule_wrong_charset_returns_empty():
    matches = match_hex_length_rules("not-a-hex-string!!")
    assert matches == []


# ---------------------------------------------------------------------------
# confidence.py
# ---------------------------------------------------------------------------

def test_score_matches_prefix_outranks_length():
    raw = match_prefix_rules("$2b$12$KIXQeuSK6BqZ1HbCiOL1eO7Nq2xzWQ3l4vF6XwXbY1s3nq8XyPz2K")
    ranked = score_matches(raw)
    assert ranked[0].tier == Tier.PREFIX
    assert ranked[0].confidence > 50


def test_score_matches_context_bonus_windows():
    raw = match_hex_length_rules("5f4dcc3b5aa765d61d8327deb882cf99")
    ranked_no_ctx = score_matches(list(raw), context=None)
    raw2 = match_hex_length_rules("5f4dcc3b5aa765d61d8327deb882cf99")
    ranked_ctx = score_matches(list(raw2), context="windows")

    ntlm_no_ctx = next(m.confidence for m in ranked_no_ctx if m.name == "NTLM")
    ntlm_ctx = next(m.confidence for m in ranked_ctx if m.name == "NTLM")
    assert ntlm_ctx > ntlm_no_ctx


def test_score_matches_dedupes():
    raw = match_prefix_rules("$2b$12$KIXQeuSK6BqZ1HbCiOL1eO7Nq2xzWQ3l4vF6XwXbY1s3nq8XyPz2K")
    doubled = raw + raw
    ranked = score_matches(doubled)
    names = [m.name for m in ranked]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# detector.py (integration)
# ---------------------------------------------------------------------------

def test_identify_md5():
    result = identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert result.best_match is not None
    assert result.best_match.name in ("MD5", "NTLM")  # ambiguous, order depends on scoring


def test_identify_bcrypt_high_confidence():
    result = identify("$2b$12$KIXQeuSK6BqZ1HbCiOL1eO7Nq2xzWQ3l4vF6XwXbY1s3nq8XyPz2K")
    assert result.best_match.name == "bcrypt"
    assert result.best_match.confidence > 70


def test_identify_unknown_string():
    result = identify("this is definitely not a hash")
    assert result.matches == []


def test_identify_compound_splits_salt():
    results = identify_compound("admin:5f4dcc3b5aa765d61d8327deb882cf99")
    assert len(results) >= 1
    all_names = [m.name for r in results for m in r.matches]
    assert "MD5" in all_names
