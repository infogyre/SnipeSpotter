"""Validate the bounded report contract for the hosted hardware experiment.

The validator is deliberately strict: it accepts only the report fields produced by
``collect_hardware.ps1`` and rejects unknown fields before an artifact can be uploaded. It never
reads files, environment variables, or secret values.
"""

# pattern: Functional Core

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

MAX_REPORT_BYTES = 32_768
MAX_LIST_ITEMS = 32
MAX_MAP_ITEMS = 64
MAX_STRING_LENGTH = 256
MAX_HMAC_FRAGMENT_LENGTH = 16
MAX_DURATION_MS = 120_000
MAX_SMBIOS_LENGTH = 16_384
MAX_STRUCTURE_COUNT = 256
MAX_WMI_COUNT = 32
MAX_ARRAY_LENGTH = 64
MAX_CHASSIS_COUNT = 16
MAX_EXCEPTION_LENGTH = 0

_ALLOWED_TOP_LEVEL = {
    "schema_version",
    "experiment",
    "build",
    "process",
    "privacy",
    "api_results",
    "smbios",
    "wmi",
    "chassis",
    "hmac_fragments",
}
_ALLOWED_EXPERIMENT = {
    "image",
    "context",
    "repetition",
    "caller_class",
    "session_id",
}
_ALLOWED_BUILD = {
    "image",
    "image_alias",
    "image_os",
    "image_version",
    "os_build",
    "powershell_version",
    "runner_architecture",
}
_ALLOWED_PROCESS = {"bitness"}
_ALLOWED_PRIVACY = {
    "hmac_algorithm",
    "hmac_key_uploaded",
    "raw_identifiers_emitted",
    "raw_payloads_emitted",
    "max_report_bytes",
}
_ALLOWED_API = {"api", "result", "duration_ms"}
_ALLOWED_SMBIOS = {
    "status",
    "length",
    "structure_count",
    "type_histogram",
    "capped",
}
_ALLOWED_WMI = {
    "status",
    "count",
    "array_lengths",
    "placeholder_classes",
    "capped",
}
_ALLOWED_CHASSIS = {"status", "count", "class_counts", "capped"}
_ALLOWED_HMAC = {"kind", "fragment"}
_ALLOWED_CHASSIS_CLASSES = {"portable", "desktop", "server", "enclosure", "unknown"}
_ALLOWED_RESULTS = {"ok", "unavailable", "access_denied", "error", "timeout", "not_run"}
_ALLOWED_STATUSES = {"ok", "unavailable", "access_denied", "error", "timeout", "not_run"}
_ALLOWED_CALLER_CLASSES = {"interactive-admin", "LocalSystem"}
_ALLOWED_HMAC_KINDS = {"machine", "monitor", "smbios", "chassis"}
_SAFE_FIELD_NAMES = (
    _ALLOWED_TOP_LEVEL
    | _ALLOWED_EXPERIMENT
    | _ALLOWED_BUILD
    | _ALLOWED_PROCESS
    | _ALLOWED_PRIVACY
    | _ALLOWED_API
    | _ALLOWED_SMBIOS
    | _ALLOWED_WMI
    | _ALLOWED_CHASSIS
    | _ALLOWED_HMAC
    | {
        "manufacturer_name",
        "product_code_id",
        "serial_number_id",
        "week_of_manufacture",
        "year_of_manufacture",
        *(_ALLOWED_CHASSIS_CLASSES),
    }
)

_TOKEN_PATTERN = re.compile(
    r"(?i)(?:bearer\s+|basic\s+|gh[pousr]_\w+|github_pat_\w+|sk[-_]live[-_]\w+|"
    r"(?:api|access|refresh|secret|private)[_-]?(?:key|token)\s*[:=]\s*\S+)"
)
_RAW_PAYLOAD_KEY_PATTERN = re.compile(
    r"(?i)(?:serial|asset[_-]?tag|instance[_-]?name|manufacturer|model|firmware|"
    r"edid|environment|env(?:ironment)?[_-]?dump|exception|stack[_-]?trace|"
    r"raw|base64|hex|uuid|guid|mac[_-]?address|hostname|computername|username|"
    r"user[_-]?name|path|command[_-]?line|token|secret|password|credential)"
)
_IDENTIFIER_LIKE_PATTERN = re.compile(
    r"(?i)(?:\b(?:host|machine|computer|serial|asset|instance|uuid|guid|mac)"
    r"(?:[-_][a-z0-9]+){1,}\b|\b(?:monitor|host|machine|computer)[-_][a-z0-9]*\d[a-z0-9_-]*\b|"
    r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b|\b[0-9a-f]{12}\b)"
)
_PATH_LIKE_PATTERN = re.compile(r"(?i)(?:^[a-z]:[\\/]|^\\\\|/Users/|/home/|/var/|/tmp/)")


def validate_report(report: object, serialized_size: int | None = None) -> list[str]:
    """Return policy violations for one decoded report object.

    The function is pure and deterministic. Callers should validate the exact
    bytes they intend to upload by passing their serialized byte length.
    """
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ["report must be a JSON object"]

    if serialized_size is None:
        try:
            serialized_size = len(json.dumps(report, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError):
            return ["report must be JSON serializable"]
    if serialized_size > MAX_REPORT_BYTES:
        errors.append(f"serialized report exceeds maximum {MAX_REPORT_BYTES} bytes")
    if serialized_size < 0:
        errors.append("serialized report size cannot be negative")

    _check_keys(report, _ALLOWED_TOP_LEVEL, "report", errors)
    _require(report, _ALLOWED_TOP_LEVEL, "report", errors)
    _check_int(report.get("schema_version"), "report.schema_version", 1, 1, errors)

    experiment = _object(report, "experiment", errors)
    if experiment is not None:
        _check_keys(experiment, _ALLOWED_EXPERIMENT, "experiment", errors)
        _require(experiment, _ALLOWED_EXPERIMENT, "experiment", errors)
        _check_choice(experiment.get("image"), "experiment.image", {"windows-2022", "windows-latest", "windows-2025"}, errors)
        _check_choice(experiment.get("context"), "experiment.context", _ALLOWED_CALLER_CLASSES, errors)
        _check_int(experiment.get("repetition"), "experiment.repetition", 1, 3, errors)
        caller_class = experiment.get("caller_class")
        _check_choice(caller_class, "experiment.caller_class", _ALLOWED_CALLER_CLASSES, errors)
        context = experiment.get("context")
        if caller_class != context:
            errors.append("experiment.caller_class must match experiment.context")
        _check_session_id(experiment.get("session_id"), "experiment.session_id", errors)

    build = _object(report, "build", errors)
    if build is not None:
        _check_keys(build, _ALLOWED_BUILD, "build", errors)
        _require(build, _ALLOWED_BUILD, "build", errors)
        _check_choice(build.get("image"), "build.image", {"windows-2022", "windows-latest", "windows-2025"}, errors)
        _check_choice(build.get("image_alias"), "build.image_alias", {"windows-2022", "windows-latest", "windows-2025"}, errors)
        if build.get("image_alias") != build.get("image"):
            errors.append("build.image_alias must match build.image")
        _check_safe_metadata_string(build.get("image_os"), "build.image_os", errors)
        _check_safe_metadata_string(build.get("image_version"), "build.image_version", errors)
        _check_int(build.get("os_build"), "build.os_build", 0, 10_000_000, errors)
        _check_safe_metadata_string(build.get("powershell_version"), "build.powershell_version", errors)
        _check_choice(build.get("runner_architecture"), "build.runner_architecture", {"X64", "ARM64"}, errors)

    process = _object(report, "process", errors)
    if process is not None:
        _check_keys(process, _ALLOWED_PROCESS, "process", errors)
        _require(process, _ALLOWED_PROCESS, "process", errors)
        _check_choice(process.get("bitness"), "process.bitness", {32, 64}, errors)

    privacy = _object(report, "privacy", errors)
    if privacy is not None:
        _check_keys(privacy, _ALLOWED_PRIVACY, "privacy", errors)
        _require(privacy, _ALLOWED_PRIVACY, "privacy", errors)
        _check_choice(privacy.get("hmac_algorithm"), "privacy.hmac_algorithm", {"HMAC-SHA256"}, errors)
        _check_bool(privacy.get("hmac_key_uploaded"), "privacy.hmac_key_uploaded", errors)
        if privacy.get("hmac_key_uploaded") is True:
            errors.append("privacy.hmac_key_uploaded must be false")
        _check_bool(privacy.get("raw_identifiers_emitted"), "privacy.raw_identifiers_emitted", errors)
        if privacy.get("raw_identifiers_emitted") is True:
            errors.append("privacy.raw_identifiers_emitted must be false")
        _check_bool(privacy.get("raw_payloads_emitted"), "privacy.raw_payloads_emitted", errors)
        if privacy.get("raw_payloads_emitted") is True:
            errors.append("privacy.raw_payloads_emitted must be false")
        _check_int(privacy.get("max_report_bytes"), "privacy.max_report_bytes", 1, MAX_REPORT_BYTES, errors)

    api_results = report.get("api_results")
    if isinstance(api_results, Sequence) and not isinstance(api_results, (str, bytes, bytearray)):
        if len(api_results) > MAX_LIST_ITEMS:
            errors.append(f"api_results has more than {MAX_LIST_ITEMS} items")
        for index, item in enumerate(api_results):
            path = f"api_results[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path} must be an object")
                continue
            _check_keys(item, _ALLOWED_API, path, errors)
            _require(item, _ALLOWED_API, path, errors)
            _check_safe_metadata_string(item.get("api"), f"{path}.api", errors)
            _check_choice(item.get("result"), f"{path}.result", _ALLOWED_RESULTS, errors)
            _check_int(item.get("duration_ms"), f"{path}.duration_ms", 0, MAX_DURATION_MS, errors)
    else:
        errors.append("api_results must be an array")

    _validate_smbios(report.get("smbios"), errors)
    _validate_wmi(report.get("wmi"), errors)
    _validate_chassis(report.get("chassis"), errors)
    _validate_hmac_fragments(report.get("hmac_fragments"), errors)
    _scan_for_forbidden_values(report, "report", errors)
    return sorted(set(errors))


def _validate_smbios(value: object, errors: list[str]) -> None:
    section = _section(value, "smbios", errors)
    if section is None:
        return
    _check_keys(section, _ALLOWED_SMBIOS, "smbios", errors)
    _require(section, _ALLOWED_SMBIOS, "smbios", errors)
    _check_choice(section.get("status"), "smbios.status", _ALLOWED_STATUSES, errors)
    _check_int(section.get("length"), "smbios.length", 0, MAX_SMBIOS_LENGTH, errors)
    _check_int(section.get("structure_count"), "smbios.structure_count", 0, MAX_STRUCTURE_COUNT, errors)
    _check_histogram(section.get("type_histogram"), "smbios.type_histogram", 0, 127, errors)
    _check_bool(section.get("capped"), "smbios.capped", errors)


def _validate_wmi(value: object, errors: list[str]) -> None:
    section = _section(value, "wmi", errors)
    if section is None:
        return
    _check_keys(section, _ALLOWED_WMI, "wmi", errors)
    _require(section, _ALLOWED_WMI, "wmi", errors)
    _check_choice(section.get("status"), "wmi.status", _ALLOWED_STATUSES, errors)
    _check_int(section.get("count"), "wmi.count", 0, MAX_WMI_COUNT, errors)
    lengths = section.get("array_lengths")
    if not isinstance(lengths, Mapping):
        errors.append("wmi.array_lengths must be an object")
    else:
        allowed = {
            "manufacturer_name",
            "product_code_id",
            "serial_number_id",
            "week_of_manufacture",
            "year_of_manufacture",
        }
        _check_keys(lengths, allowed, "wmi.array_lengths", errors)
        _require(lengths, allowed, "wmi.array_lengths", errors)
        for key, values in lengths.items():
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
                errors.append(f"wmi.array_lengths.{key} must be an array")
                continue
            if len(values) > MAX_LIST_ITEMS:
                errors.append(f"wmi.array_lengths.{key} has more than {MAX_LIST_ITEMS} items")
            for index, item in enumerate(values):
                _check_int(item, f"wmi.array_lengths.{key}[{index}]", 0, MAX_ARRAY_LENGTH, errors)
    placeholders = section.get("placeholder_classes")
    if not isinstance(placeholders, Sequence) or isinstance(placeholders, (str, bytes, bytearray)):
        errors.append("wmi.placeholder_classes must be an array")
    else:
        if len(placeholders) > MAX_LIST_ITEMS:
            errors.append(f"wmi.placeholder_classes has more than {MAX_LIST_ITEMS} items")
        for index, item in enumerate(placeholders):
            _check_safe_metadata_string(item, f"wmi.placeholder_classes[{index}]", errors)
    _check_bool(section.get("capped"), "wmi.capped", errors)


def _validate_chassis(value: object, errors: list[str]) -> None:
    section = _section(value, "chassis", errors)
    if section is None:
        return
    _check_keys(section, _ALLOWED_CHASSIS, "chassis", errors)
    _require(section, _ALLOWED_CHASSIS, "chassis", errors)
    _check_choice(section.get("status"), "chassis.status", _ALLOWED_STATUSES, errors)
    _check_int(section.get("count"), "chassis.count", 0, MAX_CHASSIS_COUNT, errors)
    classes = section.get("class_counts")
    if not isinstance(classes, Mapping):
        errors.append("chassis.class_counts must be an object")
    else:
        _check_keys(classes, _ALLOWED_CHASSIS_CLASSES, "chassis.class_counts", errors)
        _require(classes, _ALLOWED_CHASSIS_CLASSES, "chassis.class_counts", errors)
        for key, item in classes.items():
            _check_int(item, f"chassis.class_counts.{key}", 0, MAX_CHASSIS_COUNT, errors)
    _check_bool(section.get("capped"), "chassis.capped", errors)


def _validate_hmac_fragments(value: object, errors: list[str]) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        errors.append("hmac_fragments must be an array")
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.append(f"hmac_fragments has more than {MAX_LIST_ITEMS} items")
    for index, item in enumerate(value):
        path = f"hmac_fragments[{index}]"
        if not isinstance(item, Mapping):
            errors.append(f"{path} must be an object")
            continue
        _check_keys(item, _ALLOWED_HMAC, path, errors)
        _require(item, _ALLOWED_HMAC, path, errors)
        _check_choice(item.get("kind"), f"{path}.kind", _ALLOWED_HMAC_KINDS, errors)
        fragment = item.get("fragment")
        _check_bounded_string(fragment, f"{path}.fragment", MAX_HMAC_FRAGMENT_LENGTH, errors)
        if isinstance(fragment, str) and (not re.fullmatch(r"[0-9a-f]{16}", fragment) or fragment == "0" * 16):
            errors.append(f"{path}.fragment must be a non-zero 16-character lowercase hex fragment")


def _section(value: object, name: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{name} must be an object")
        return None
    return value


def _object(report: Mapping[str, Any], name: str, errors: list[str]) -> Mapping[str, Any] | None:
    value = report.get(name)
    if not isinstance(value, Mapping):
        errors.append(f"{name} must be an object")
        return None
    return value


def _check_keys(value: Mapping[str, Any], allowed: set[str], path: str, errors: list[str]) -> None:
    for key in value:
        if not isinstance(key, str) or key not in allowed:
            errors.append(f"{path} contains an unknown field")


def _require(value: Mapping[str, Any], allowed: set[str], path: str, errors: list[str]) -> None:
    for key in allowed:
        if key not in value:
            errors.append(f"{path} missing required field {key!r}")


def _check_bounded_string(value: object, path: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{path} must be a string")
    elif not value or len(value) > maximum:
        errors.append(f"{path} must be 1..{maximum} characters")


def _check_session_id(value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000:
        errors.append(f"{path} must be a numeric session id in 0..10000")


def _check_safe_metadata_string(value: object, path: str, errors: list[str]) -> None:
    _check_bounded_string(value, path, MAX_STRING_LENGTH, errors)
    if not isinstance(value, str):
        return
    if _IDENTIFIER_LIKE_PATTERN.search(value):
        errors.append(f"{path} contains identifier-like content")
    if _PATH_LIKE_PATTERN.search(value):
        errors.append(f"{path} contains path-like content")


def _check_choice(value: object, path: str, choices: set[object], errors: list[str]) -> None:
    if value not in choices:
        errors.append(f"{path} has an unsupported value")


def _check_int(value: object, path: str, minimum: int, maximum: int, errors: list[str]) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        errors.append(f"{path} must be an integer in {minimum}..{maximum}")


def _check_bool(value: object, path: str, errors: list[str]) -> None:
    if not isinstance(value, bool):
        errors.append(f"{path} must be a boolean")


def _check_histogram(value: object, path: str, minimum: int, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return
    if len(value) > MAX_MAP_ITEMS:
        errors.append(f"{path} has more than {MAX_MAP_ITEMS} entries")
    for key, count in value.items():
        if not isinstance(key, str) or not key.isdigit():
            errors.append(f"{path} keys must be numeric strings")
        else:
            _check_int(int(key), f"{path}.{key}", minimum, maximum, errors)
        _check_int(count, f"{path}.{key}", 0, MAX_STRUCTURE_COUNT, errors)


def _scan_for_forbidden_values(value: object, path: str, errors: list[str]) -> None:
    """Reject forbidden key/value shapes even if a caller changes the schema."""
    if isinstance(value, Mapping):
        if len(value) > MAX_MAP_ITEMS:
            errors.append(f"{path} has more than {MAX_MAP_ITEMS} entries")
        for key, child in value.items():
            key_text = str(key)
            if key_text not in _SAFE_FIELD_NAMES and _RAW_PAYLOAD_KEY_PATTERN.search(key_text):
                errors.append(f"{path} contains a forbidden field name")
            _scan_for_forbidden_values(child, f"{path}.{key_text}", errors)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_LIST_ITEMS:
            errors.append(f"{path} has more than {MAX_LIST_ITEMS} items")
        for index, child in enumerate(value):
            _scan_for_forbidden_values(child, f"{path}[{index}]", errors)
    elif isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            errors.append(f"{path} contains a string longer than {MAX_STRING_LENGTH} characters")
        if _TOKEN_PATTERN.search(value):
            errors.append(f"{path} contains token-like content")
        if "-----BEGIN" in value or "MII" in value:
            errors.append(f"{path} contains key/certificate-like content")


def validate_json_bytes(payload: bytes) -> list[str]:
    """Validate exactly the UTF-8 JSON bytes that would be uploaded."""
    if len(payload) > MAX_REPORT_BYTES:
        return [f"serialized report exceeds maximum {MAX_REPORT_BYTES} bytes"]
    try:
        report = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["report must be valid UTF-8 JSON"]
    return validate_report(report, serialized_size=len(payload))


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Validate a redacted hardware report")
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    violations = validate_json_bytes(args.report.read_bytes())
    if violations:
        for violation in violations:
            print(violation)
        raise SystemExit(1)
    print("hardware report privacy validation passed")
