"""Privacy validator for physical hardware fixture files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Patterns that indicate unredacted identifiers.
FORBIDDEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"CN0\d{5}", re.IGNORECASE),  # Dell service tags
    re.compile(r"[A-Z]{3}\d{4}", re.IGNORECASE),  # Monitor manufacturer codes
    re.compile(r"PMEM", re.IGNORECASE),
    re.compile(r"NVRAM", re.IGNORECASE),
    re.compile(r"\bUUID\b", re.IGNORECASE),
]

# Placeholders the capture script uses. Fixture values must match these.
EXPECTED_PLACEHOLDER_PREFIXES = ("PLACEHOLDER_", "MFR", "PROD", "SER", "MONITOR_")


def check_text(text: str, source: str) -> list[str]:
    """Check text for forbidden patterns."""
    violations: list[str] = []
    for pattern in FORBIDDEN_PATTERNS:
        match = pattern.search(text)
        if match:
            violations.append(f"{source}: forbidden pattern '{pattern.pattern}' matched '{match.group()}'")
    return violations


def check_wmi_monitors(data: list[dict], source: str) -> list[str]:
    """Check WMI monitor fixtures for unredacted identifiers."""
    violations: list[str] = []
    for i, monitor in enumerate(data):
        serial = monitor.get("serial_number_id", "")
        if serial and not serial.startswith("SER"):
            violations.append(f"{source}[{i}]: unredacted serial '{serial}'")
        manufacturer = monitor.get("manufacturer_name", "")
        if manufacturer and not manufacturer.startswith("MFR"):
            violations.append(f"{source}[{i}]: unredacted manufacturer '{manufacturer}'")
        product = monitor.get("product_code", "")
        if product and not product.startswith("PROD"):
            violations.append(f"{source}[{i}]: unredacted product code '{product}'")
    return violations


def validate_fixture_dir(fixture_dir: Path) -> list[str]:
    """Validate all fixture files in a directory."""
    violations: list[str] = []

    # Check JSON files for forbidden patterns.
    for json_path in fixture_dir.glob("*.json"):
        text = json_path.read_text(encoding="utf-8")
        violations.extend(check_text(text, str(json_path)))

        # Check WMI monitors specifically.
        if json_path.name == "wmi_monitors.json":
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    violations.extend(check_wmi_monitors(data, str(json_path)))
            except json.JSONDecodeError:
                violations.append(f"{json_path}: invalid JSON")

    # Check binary SMBIOS fixture for readable identifier patterns.
    smbios_path = fixture_dir / "smbios_fixture.bin"
    if smbios_path.exists():
        raw = smbios_path.read_bytes()
        # Scan for readable ASCII strings longer than 8 chars that are not placeholders.
        ascii_strings = re.findall(rb"[\x20-\x7e]{8,}", raw)
        for s in ascii_strings:
            decoded = s.decode("ascii", errors="replace")
            if not any(
                decoded.startswith(prefix) or prefix.startswith(decoded)
                for prefix in EXPECTED_PLACEHOLDER_PREFIXES
            ):
                violations.append(f"{smbios_path}: non-placeholder string in SMBIOS data: '{decoded}'")

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate physical fixture privacy.")
    parser.add_argument("--input", required=True, type=Path, help="Fixture directory to validate.")
    args = parser.parse_args()

    if not args.input.is_dir():
        print(f"error: {args.input} is not a directory", file=sys.stderr)
        return 1

    violations = validate_fixture_dir(args.input)
    if violations:
        print(f"FAIL: {len(violations)} privacy violation(s) found:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print(f"OK: {args.input} passed privacy validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
