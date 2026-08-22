"""Validate one hosted hardware experiment report without echoing its contents."""

# pattern: Imperative Shell

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from privacy_policy import MAX_REPORT_BYTES, validate_report


def main() -> int:
    """Validate the report path and emit only a generic result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="JSON report to validate")
    args = parser.parse_args()

    try:
        size = args.input.stat().st_size
    except OSError:
        print("report validation failed: input unavailable", file=sys.stderr)
        return 1
    if size > MAX_REPORT_BYTES:
        print("report validation failed: input exceeds maximum size", file=sys.stderr)
        return 1

    try:
        report = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("report validation failed: input is not valid JSON", file=sys.stderr)
        return 1

    errors = validate_report(report, serialized_size=size)
    if errors:
        print(f"report validation failed: {len(errors)} privacy policy violation(s)", file=sys.stderr)
        return 1
    print("report validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
