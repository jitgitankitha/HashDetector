"""
rules.py
========
Turns the static data in constants.py into actual candidate matches for
a given input string. This module only produces *raw* candidates with a
base score — final ranking/adjustment happens in confidence.py.

Two passes:
  1. match_prefix_rules   -> Tier.PREFIX   (unambiguous marker-based)
  2. match_length_rules   -> Tier.LENGTH_CHARSET (ambiguous, needs scoring)
"""

from .constants import PREFIX_RULES, HEX_LENGTH_TABLE, BASE64_LENGTH_TABLE
from .models import HashMatch, Tier
from .utils import is_hex, is_base64, decoded_byte_length

# Rules whose regex is too generic to be trusted when the input length
# already matches a *known standard digest length* (e.g. 32/40/64 hex
# chars). Without this guard, loose "catch-all" rules like Cisco Type 7
# would fire on every plain MD5/SHA hash and clutter results.
_AMBIGUOUS_AT_STANDARD_LENGTHS = {"Cisco Type 7"}


def match_prefix_rules(value: str) -> list[HashMatch]:
    """Check value against every Tier-1 (marker/prefix) rule."""
    matches = []
    for rule in PREFIX_RULES:
        if rule["name"] in _AMBIGUOUS_AT_STANDARD_LENGTHS and len(value) in HEX_LENGTH_TABLE:
            continue
        if rule["pattern"].match(value):
            matches.append(
                HashMatch(
                    name=rule["name"],
                    category=rule["category"],
                    notes=rule["notes"],
                    tier=Tier.PREFIX,
                    confidence=float(rule["score"]),
                    evidence=[f"Matched prefix/structure pattern for {rule['name']}"],
                )
            )
    return matches


def match_hex_length_rules(value: str) -> list[HashMatch]:
    """Check value as a raw hex digest against the length candidate table."""
    if not is_hex(value):
        return []

    candidates = HEX_LENGTH_TABLE.get(len(value), [])
    matches = []
    for name, category, weight, notes in candidates:
        matches.append(
            HashMatch(
                name=name,
                category=category,
                notes=notes,
                tier=Tier.LENGTH_CHARSET,
                confidence=float(weight),  # raw prevalence weight; refined later
                evidence=[f"{len(value)} hex characters matches known length for {name}"],
            )
        )
    return matches


def match_base64_length_rules(value: str) -> list[HashMatch]:
    """Check value as a base64-encoded digest against the decoded-length table."""
    if not is_base64(value):
        return []

    n_bytes = decoded_byte_length(value)
    if n_bytes is None:
        return []

    candidates = BASE64_LENGTH_TABLE.get(n_bytes, [])
    matches = []
    for name, category, weight, notes in candidates:
        matches.append(
            HashMatch(
                name=name,
                category=category,
                notes=notes,
                tier=Tier.STRUCTURAL,
                confidence=float(weight),
                evidence=[f"Base64 decodes to {n_bytes} bytes, matching {name}"],
            )
        )
    return matches


def collect_all_matches(value: str) -> list[HashMatch]:
    """Run every rule tier against value and concatenate raw candidates."""
    matches: list[HashMatch] = []
    matches.extend(match_prefix_rules(value))

    # Only bother with ambiguous tiers if no confident prefix match already
    # dominates — but we still compute them so confidence.py can decide.
    matches.extend(match_hex_length_rules(value))
    matches.extend(match_base64_length_rules(value))

    return matches
