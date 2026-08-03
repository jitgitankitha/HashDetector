from .models import DetectionResult
from .rules import collect_all_matches
from .confidence import score_matches
from .utils import normalize, strip_known_delimiters


def identify(value: str, context: str | None = None) -> DetectionResult:

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
    # Keep only parts that produced at least one candidate okay??
    results = [r for r in results if r.matches] or [whole]
    return results
