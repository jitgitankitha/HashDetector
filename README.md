# hashdetector

A hash-type identification tool built for an academic project. Given a
hash/digest string, it infers the most likely algorithm(s) that produced
it, along with a confidence score.

## How it works

Detection runs in tiers:

1. **Prefix / marker rules** (`detector/rules.py::match_prefix_rules`) —
   formats with an unambiguous embedded marker, e.g. bcrypt's `$2b$12$...`,
   JWTs' `eyJ...` header, Django's `pbkdf2_sha256$...`. High confidence.
2. **Length + charset rules** (`match_hex_length_rules`,
   `match_base64_length_rules`) — many algorithms (MD5, NTLM, MD4) produce
   identical-looking 32-hex-character output, so these matches are
   inherently ambiguous and start at a lower confidence.
3. **Confidence scoring** (`detector/confidence.py`) — applies a
   tier multiplier, an ambiguity penalty (more same-length candidates =
   lower ceiling per candidate), and optional context bonuses (e.g.
   `--context windows` boosts NTLM/LM over generic MD5).

Results are ranked and returned as a `DetectionResult` containing a list
of `HashMatch` objects sorted by descending confidence.

## Project structure

```
hashdetector/
├── detector/
│   ├── __init__.py     # public API: identify(), identify_compound()
│   ├── constants.py    # regex signatures, length tables, charsets
│   ├── models.py        # HashRule, HashMatch, DetectionResult dataclasses
│   ├── rules.py          # raw candidate generation from constants.py
│   ├── confidence.py    # scoring / ranking / deduplication
│   ├── detector.py       # orchestration entrypoint
│   ├── formatter.py      # table / JSON / plain-text output
│   └── utils.py           # hex/base64 helpers, delimiter splitting
├── cli.py                # argparse-based command-line interface
├── tests/
│   └── test_detector.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Usage

```bash
# Single hash
python cli.py 5f4dcc3b5aa765d61d8327deb882cf99

# Multiple hashes
python cli.py 5f4dcc3b5aa765d61d8327deb882cf99 $2b$12$KIXQeuSK6BqZ1HbCiOL1eO7Nq2xzWQ3l4vF6XwXbY1s3nq8XyPz2K

# From a file (one hash per line)
python cli.py --file hashes.txt

# Bias ambiguous matches with a context hint
python cli.py 5f4dcc3b5aa765d61d8327deb882cf99 --context windows

# Machine-readable output
python cli.py 5f4dcc3b5aa765d61d8327deb882cf99 --json

# Just the best guess (good for scripting)
python cli.py 5f4dcc3b5aa765d61d8327deb882cf99 --best-only
```

## As a library

```python
from detector import identify

result = identify("5f4dcc3b5aa765d61d8327deb882cf99", context="windows")
print(result.best_match)          # HashMatch('NTLM', confidence=..., tier=length_charset)
for match in result.top(3):
    print(match.name, match.confidence, match.notes)
```

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Design notes / known limitations

- **Ambiguity is fundamental, not a bug.** Many algorithms produce
  identical-length, identical-charset output (MD5 vs NTLM vs MD4 at 32
  hex chars). This tool ranks by prevalence and context rather than
  claiming false certainty — always treat `length_charset`-tier matches
  as *candidates*, not confirmed identifications.
- **No cracking / validation.** This tool only classifies the *format*
  of a hash string; it does not attempt to verify, crack, or reverse it.
- **Extending the ruleset:** add new entries to `PREFIX_RULES`,
  `HEX_LENGTH_TABLE`, or `BASE64_LENGTH_TABLE` in `constants.py` — no
  other file needs to change for a straightforward new signature.
