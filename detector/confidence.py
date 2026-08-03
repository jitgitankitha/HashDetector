"""
confidence.py
=============
Turns raw candidate HashMatch objects (from rules.py) into a ranked,
deduplicated result list. This is where ambiguity between same-length
hashes (e.g. MD5 vs NTLM, both 32 hex chars) gets resolved as best as
a static ruleset can.

Scoring approach
----------------
final_score = base_score
              * tier_multiplier
              + context_bonus
              - length_ambiguity_penalty

- tier_multiplier: PREFIX matches are trusted far more than LENGTH_CHARSET
  guesses, so they get a large multiplier.
- context_bonus: optional user-supplied hints (e.g. "windows", "unix",
  "database") boost algorithms known to occur in that context.
- length_ambiguity_penalty: the more candidates share the same length
  bucket, the less any single one can be trusted -> spread confidence
  out rather than letting every candidate claim near-100%.
"""

from .models import HashMatch, Tier

TIER_MULTIPLIER = {
    Tier.PREFIX: 1.0,          # already high base_score (90s), keep as-is
    Tier.STRUCTURAL: 0.9,
    Tier.LENGTH_CHARSET: 0.6,  # heavily discounted: length alone is weak evidence
}

# context keyword -> {hash name substring: bonus points}
CONTEXT_BONUSES = {
    "windows": {"NTLM": 20, "LM hash": 15, "MD4": 5},
    "unix": {"MD5-crypt": 10, "sha256-crypt": 10, "sha512-crypt": 10, "bcrypt": 5},
    "database": {"MySQL": 15, "Django": 10},
    "web": {"bcrypt": 10, "phpass": 10, "Argon2": 10, "JWT": 10},
    "legacy": {"MD5": 10, "SHA-1": 10, "MySQL3.2.3": 15},
}


def _length_ambiguity_penalty(same_length_count: int) -> float:
    """
    More candidates sharing a length bucket -> lower ceiling per candidate.
    1 candidate: no penalty. 5+ candidates: meaningful penalty.
    """
    if same_length_count <= 1:
        return 0.0
    return min(5.0 * (same_length_count - 1), 25.0)


def score_matches(
    matches: list[HashMatch],
    context: str | None = None,
) -> list[HashMatch]:
    """
    Apply tier multipliers, context bonuses, and ambiguity penalties.
    Returns a new list, sorted by descending confidence, deduplicated
    by (name, tier) — mutates confidence in place on the given objects.
    """
    if not matches:
        return []

    # Count how many LENGTH_CHARSET candidates collide, for ambiguity penalty
    length_tier_count = sum(1 for m in matches if m.tier is Tier.LENGTH_CHARSET)
    penalty = _length_ambiguity_penalty(length_tier_count)

    context_key = context.lower().strip() if context else None
    bonuses = CONTEXT_BONUSES.get(context_key, {}) if context_key else {}

    scored: list[HashMatch] = []
    seen = set()
    for m in matches:
        key = (m.name, m.tier)
        if key in seen:
            continue
        seen.add(key)

        multiplier = TIER_MULTIPLIER.get(m.tier, 0.5)
        score = m.confidence * multiplier

        if m.tier is Tier.LENGTH_CHARSET:
            score -= penalty

        # context bonus: match if any keyword substring is in the hash name
        for name_fragment, bonus in bonuses.items():
            if name_fragment.lower() in m.name.lower():
                score += bonus
                m.evidence.append(f"Context hint '{context_key}' boosted this candidate (+{bonus})")

        m.confidence = max(0.0, min(100.0, round(score, 1)))
        scored.append(m)

    scored.sort(key=lambda m: m.confidence, reverse=True)
    return scored
