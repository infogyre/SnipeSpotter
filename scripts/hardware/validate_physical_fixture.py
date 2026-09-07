"""Privacy validator for physical hardware fixture files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# pattern: Mixed (unavoidable)
# Reason: This small command keeps bounded file I/O beside its pure validation API.
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_DIAGNOSTICS = 16
UUID_SENTINEL = bytes(16)
ERROR_CATEGORIES = frozenset(
    {
        "fixture_not_directory",
        "fixture_file_oversize",
        "fixture_read_failed",
        "json_invalid",
        "json_forbidden_pattern",
        "wmi_invalid_shape",
        "wmi_serial_not_redacted",
        "wmi_manufacturer_not_redacted",
        "wmi_product_not_redacted",
        "smbios_missing",
        "smbios_invalid_wrapper",
        "smbios_truncated_structure",
        "smbios_invalid_structure_length",
        "smbios_unterminated_strings",
        "smbios_type1_uuid_unavailable",
        "smbios_uuid_not_redacted",
    }
)
FORBIDDEN_PATTERNS = (
    re.compile(r"CN0\d{5}", re.IGNORECASE),
    re.compile(r"[A-Z]{3}\d{4}", re.IGNORECASE),
    re.compile(r"PMEM", re.IGNORECASE),
    re.compile(r"NVRAM", re.IGNORECASE),
    re.compile(r"\bUUID\b", re.IGNORECASE),
)


def _bounded(categories: list[str]) -> list[str]:
    """Return fixed categories with bounded duplicate counts."""
    counts = Counter(categories)
    result: list[str] = []
    for category in sorted(counts):
        if category in ERROR_CATEGORIES:
            result.extend([category] * min(counts[category], 2))
        if len(result) >= MAX_DIAGNOSTICS:
            break
    return result[:MAX_DIAGNOSTICS]


def validate_smbios(raw: bytes) -> list[str]:
    """Validate a complete RawSMBIOSData wrapper and redacted Type 1 UUIDs."""
    if len(raw) > MAX_FIXTURE_BYTES:
        return ["fixture_file_oversize"]
    if len(raw) < 8:
        return ["smbios_invalid_wrapper"]
    declared = int.from_bytes(raw[4:8], "little")
    if declared == 0 or declared != len(raw) - 8:
        return ["smbios_invalid_wrapper"]
    offset = 8
    end = len(raw)
    errors: list[str] = []
    while offset < end and len(errors) < MAX_DIAGNOSTICS:
        if end - offset < 4:
            errors.append("smbios_truncated_structure")
            break
        kind = raw[offset]
        length = raw[offset + 1]
        if length < 4:
            errors.append("smbios_invalid_structure_length")
            break
        formatted_end = offset + length
        if formatted_end > end:
            errors.append("smbios_truncated_structure")
            break
        if kind == 1:
            if length < 24:
                errors.append("smbios_type1_uuid_unavailable")
            elif raw[offset + 8 : offset + 24] != UUID_SENTINEL:
                errors.append("smbios_uuid_not_redacted")
        terminator = raw.find(b"\0\0", formatted_end, end)
        if terminator < 0:
            errors.append("smbios_unterminated_strings")
            break
        offset = terminator + 2
        if kind == 127:
            if offset != end:
                errors.append("smbios_invalid_wrapper")
            break
    if offset != end and not errors:
        errors.append("smbios_invalid_wrapper")
    return _bounded(errors)


def _check_json(text: str, name: str) -> list[str]:
    errors = ["json_forbidden_pattern" for pattern in FORBIDDEN_PATTERNS if pattern.search(text)]
    if name != "wmi_monitors.json":
        return errors
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return errors + ["json_invalid"]
    if not isinstance(data, list):
        return errors + ["wmi_invalid_shape"]
    for monitor in data[:256]:
        if not isinstance(monitor, dict):
            errors.append("wmi_invalid_shape")
            continue
        for field, prefix, category in (
            ("serial_number_id", "SER", "wmi_serial_not_redacted"),
            ("manufacturer_name", "MFR", "wmi_manufacturer_not_redacted"),
            ("product_code", "PROD", "wmi_product_not_redacted"),
        ):
            value = monitor.get(field, "")
            if not isinstance(value, str) or (value and not value.startswith(prefix)):
                errors.append(category)
    return errors


def validate_fixture_dir(fixture_dir: Path) -> list[str]:
    """Validate bounded fixture files without including values or paths in errors."""
    errors: list[str] = []
    for name in ("chassis.json", "fixture_summary.json", "wmi_monitors.json"):
        path = fixture_dir / name
        if not path.exists():
            continue
        try:
            if path.stat().st_size > MAX_FIXTURE_BYTES:
                errors.append("fixture_file_oversize")
                continue
            errors.extend(_check_json(path.read_text(encoding="utf-8-sig"), name))
        except (OSError, UnicodeError):
            errors.append("fixture_read_failed")
    smbios_path = fixture_dir / "smbios_fixture.bin"
    if not smbios_path.exists():
        errors.append("smbios_missing")
    else:
        try:
            if smbios_path.stat().st_size > MAX_FIXTURE_BYTES:
                errors.append("fixture_file_oversize")
            else:
                errors.extend(validate_smbios(smbios_path.read_bytes()))
        except OSError:
            errors.append("fixture_read_failed")
    return _bounded(errors)


def main() -> int:
    """Run fixture validation and emit machine-readable, value-free output."""
    parser = argparse.ArgumentParser(description="Validate physical fixture privacy.")
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_dir():
        print(json.dumps({"status": "error", "errors": {"fixture_not_directory": 1}}, sort_keys=True), file=sys.stderr)
        return 1
    violations = validate_fixture_dir(args.input)
    if violations:
        print(json.dumps({"status": "error", "errors": dict(sorted(Counter(violations).items()))}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "errors": {}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
