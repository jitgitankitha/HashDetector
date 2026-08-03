import json

from .models import DetectionResult


def to_json(results: list[DetectionResult]) -> str:
    payload = []
    for r in results:
        payload.append(
            {
                "input": r.input_value,
                "length": r.length,
                "matches": [
                    {
                        "name": m.name,
                        "category": m.category,
                        "confidence": m.confidence,
                        "tier": m.tier.value,
                        "notes": m.notes,
                        "evidence": m.evidence,
                    }
                    for m in r.matches
                ],
            }
        )
    return json.dumps(payload, indent=2)


def to_table(results: list[DetectionResult], top_n: int = 5) -> str:
    lines = []
    for r in results:
        lines.append(f"Input: {r.input_value}")
        lines.append(f"Length: {r.length} characters")
        if not r.matches:
            lines.append("  No candidate hash types identified.")
            lines.append("")
            continue

        header = f"  {'#':<3}{'Candidate':<30}{'Confidence':<12}{'Tier':<16}{'Category'}"
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))
        for i, m in enumerate(r.top(top_n), start=1):
            lines.append(
                f"  {i:<3}{m.name:<30}{m.confidence:<12.1f}{m.tier.value:<16}{m.category}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_plain_best(results: list[DetectionResult]) -> str:
    """One line per input: just the best guess ashte."""
    lines = []
    for r in results:
        if r.best_match:
            lines.append(f"{r.input_value} -> {r.best_match.name} ({r.best_match.confidence:.1f}%)")
        else:
            lines.append(f"{r.input_value} -> unknown")
    return "\n".join(lines)
