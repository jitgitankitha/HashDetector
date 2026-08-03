"""
detector.py
===========
Public entrypoint for the detection pipeline. Orchestrates:

    normalize -> collect_all_matches (rules.py) -> score_matches (confidence.py)
    -> DetectionResult

Also handles compound inputs (e.g. "hash:salt" dumps) by splitting on
known delimiters and running detection on each part.
"""

from .models import DetectionResult
from .rules import collect_all_matches
from .confidence import score_matches
from .utils import normalize, strip_known_delimiters


def identify(value: str, context: str | None = None) -> DetectionResult:
    """
    Identify the likely hash type(s) for a single input string.

    Parameters
    ----------
    value : the raw hash string to analyze
    context : optional hint like "windows", "unix", "database", "web",
              "legacy" — used by confidence.py to bias ambiguous matches

    Returns
    -------
    DetectionResult with matches sorted by descending confidence.
    """
    cleaned = normalize(value)
    raw_matches = collect_all_matches(cleaned)
    ranked = score_matches(raw_matches, context=context)

    return DetectionResult(
        input_value=cleaned,
        length=len(cleaned),
        matches=ranked,
    )


def identify_compound(value: str, context: str | None = None) -> list[DetectionResult]:
    """
    Handle dump-style input that may contain a hash bundled with a salt,
    username, or other field (e.g. 'admin:5f4dcc3b5aa765d61d8327deb882cf99').

    Runs `identify` on the whole string first; if that yields nothing
    confident, retries on each delimiter-split part and returns all
    per-part results so the caller can present them together.
    """
    whole = identify(value, context=context)
    if whole.best_match and whole.best_match.confidence >= 50:
        return [whole]

    parts = strip_known_delimiters(normalize(value))
    if len(parts) == 1:
        return [whole]

    results = [identify(part, context=context) for part in parts]
    # Keep only parts that produced at least one candidate
    results = [r for r in results if r.matches] or [whole]
    return results
