"""
models.py
=========
Typed data structures shared across the detector package.

Using dataclasses keeps rules.py / confidence.py / formatter.py decoupled:
each module only needs to know the shape of HashMatch, not each other's
internals.
"""

from dataclasses import dataclass, field
from enum import Enum


class Tier(str, Enum):
    """How the match was derived — informs how much we trust it."""
    PREFIX = "prefix"          # unambiguous marker (e.g. $2b$, eyJ...)
    LENGTH_CHARSET = "length_charset"  # ambiguous, length+charset only
    STRUCTURAL = "structural"  # delimiter/encoding-based inference


@dataclass(frozen=True)
class HashRule:
    """A single detection rule (mostly mirrors constants.py entries)."""
    name: str
    category: str
    notes: str
    base_score: int
    tier: Tier


@dataclass
class HashMatch:
    """A candidate hash-type identification result for a given input."""
    name: str
    category: str
    notes: str
    tier: Tier
    confidence: float  # 0-100, final score after confidence.py scoring
    evidence: list[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"HashMatch({self.name!r}, confidence={self.confidence:.1f}, tier={self.tier.value})"


@dataclass
class DetectionResult:
    """Full result for one input string."""
    input_value: str
    length: int
    matches: list[HashMatch]

    @property
    def best_match(self) -> HashMatch | None:
        return self.matches[0] if self.matches else None

    def top(self, n: int = 5) -> list[HashMatch]:
        return self.matches[:n]
