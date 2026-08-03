#!/usr/bin/env python3
"""
cli.py
======
Command-line interface for hashdetector.

Usage
-----
    python cli.py <hash>
    python cli.py <hash1> <hash2> ...
    python cli.py --file hashes.txt
    python cli.py <hash> --context windows
    python cli.py <hash> --json
    python cli.py <hash> --best-only
"""

import argparse
import sys

from detector import identify_compound
from detector.formatter import to_table, to_json, to_plain_best


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashdetector",
        description="Identify likely hash / digest / password-hash types from a string.",
    )
    parser.add_argument(
        "hashes",
        nargs="*",
        help="One or more hash strings to identify.",
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to a file containing one hash per line.",
    )
    parser.add_argument(
        "-c", "--context",
        choices=["windows", "unix", "database", "web", "legacy"],
        default=None,
        help="Optional context hint to bias ambiguous matches.",
    )
    parser.add_argument(
        "--top", type=int, default=5,
        help="Max number of candidates to show per hash (default: 5).",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON."
    )
    output_group.add_argument(
        "--best-only", action="store_true", help="Output only the single best guess per hash."
    )
    return parser


def gather_inputs(args: argparse.Namespace) -> list[str]:
    values = list(args.hashes)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                values.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            print(f"Error reading file {args.file}: {exc}", file=sys.stderr)
            sys.exit(1)
    return values


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    values = gather_inputs(args)
    if not values:
        parser.print_help()
        return 1

    all_results = []
    for value in values:
        all_results.extend(identify_compound(value, context=args.context))

    if args.json:
        print(to_json(all_results))
    elif args.best_only:
        print(to_plain_best(all_results))
    else:
        print(to_table(all_results, top_n=args.top))

    return 0


if __name__ == "__main__":
    sys.exit(main())
