"""Behavioral tests for physical SMBIOS fixture privacy."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARDWARE = ROOT / "scripts" / "hardware"
VALIDATOR_PATH = HARDWARE / "validate_physical_fixture.py"
REDACTOR_PATH = HARDWARE / "Redact-SmbiosFixture.ps1"
CONVERTER_PATH = HARDWARE / "Convert-PhysicalFixtures.ps1"
SENTINEL = bytes(16)
PRIVATE_UUID = bytes(range(1, 17))

spec = importlib.util.spec_from_file_location("physical_validator", VALIDATOR_PATH)
assert spec and spec.loader
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def structure(kind: int, formatted: bytes, strings: tuple[bytes, ...] = ()) -> bytes:
    body = bytearray(formatted)
    body[0] = kind
    body[1] = len(body)
    suffix = b"".join(value + b"\0" for value in strings) + b"\0"
    if not strings:
        suffix += b"\0"
    return bytes(body) + suffix


def wrapped_fixture(uuid: bytes = PRIVATE_UUID) -> bytes:
    system = bytearray(25)
    system[4], system[5], system[7] = 1, 2, 3
    system[8:24] = uuid
    chassis = bytearray(9)
    chassis[5], chassis[8] = 3, 1
    table = structure(1, system, (b"MAKER", b"MODEL", b"SERIAL"))
    table += structure(3, chassis, (b"ASSET",))
    table += structure(127, bytes(4))
    return bytes((0, 3, 6, 0)) + len(table).to_bytes(4, "little") + table


class PhysicalFixturePrivacyTests(unittest.TestCase):
    def test_physical_uuid_redaction_roundtrip(self) -> None:
        """physical_uuid_redaction_roundtrip"""
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "input.bin"
            output_path = root / "output.bin"
            input_path.write_bytes(wrapped_fixture())
            result = subprocess.run(
                [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(REDACTOR_PATH), "-InputPath", str(input_path), "-OutputPath", str(output_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, "redaction routine must accept a valid synthetic wrapper")
            redacted = output_path.read_bytes()
            self.assertEqual(redacted[16:32], SENTINEL)
            self.assertEqual(len(redacted), len(input_path.read_bytes()))
            self.assertNotIn(PRIVATE_UUID, redacted)
            self.assertEqual(validator.validate_smbios(redacted), [])
            self.assertNotIn(PRIVATE_UUID.hex(), result.stdout + result.stderr)

            capture_path = root / "capture.json"
            fixture_dir = root / "fixtures"
            capture_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "capture_type": "physical_hardware_fixture",
                        "metadata": {"label": "synthetic"},
                        "smbios": {
                            "raw_hex": redacted.hex(),
                            "summary": {
                                "structure_count": 3,
                                "type_histogram": {"1": 1, "3": 1, "127": 1},
                                "major_version": 3,
                                "minor_version": 6,
                                "capped": False,
                            },
                        },
                        "wmi_monitors": [
                            {
                                "active": True,
                                "manufacturer_name": "MFR0",
                                "manufacturer_name_array_length": 4,
                                "product_code": "PROD0",
                                "product_code_array_length": 5,
                                "serial": "SER0",
                                "serial_array_length": 4,
                                "week_of_manufacture": 1,
                                "year_of_manufacture": 2024,
                            }
                        ],
                        "chassis": {"types": [3], "class_counts": {"desktop": 1}},
                    }
                ),
                encoding="utf-8",
            )
            converted = subprocess.run(
                [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(CONVERTER_PATH), "-InputPath", str(capture_path), "-OutputDir", str(fixture_dir)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(converted.returncode, 0, "conversion must accept the redacted synthetic capture")
            self.assertEqual(validator.validate_fixture_dir(fixture_dir), [])
            parsed = subprocess.run(
                ["cargo", "test", "-p", "spotter-core", "parses_real_physical_smbios_fixture", "--quiet"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(parsed.returncode, 0, "the Rust physical fixture parser compatibility test must pass")

    def test_physical_validator_rejects_binary_uuid(self) -> None:
        """physical_validator_rejects_binary_uuid"""
        self.assertIn("smbios_uuid_not_redacted", validator.validate_smbios(wrapped_fixture()))

        short_type1 = bytearray(8)
        short_type1[4:8] = (6).to_bytes(4, "little")
        short_type1.extend(structure(1, bytes(4)))
        self.assertIn("smbios_type1_uuid_unavailable", validator.validate_smbios(bytes(short_type1)))

        malformed_wrapper = bytearray(wrapped_fixture(SENTINEL))
        malformed_wrapper[4:8] = (len(malformed_wrapper)).to_bytes(4, "little")
        self.assertEqual(validator.validate_smbios(bytes(malformed_wrapper)), ["smbios_invalid_wrapper"])

        unterminated = wrapped_fixture(SENTINEL)[:-2] + b"XY"
        self.assertIn("smbios_unterminated_strings", validator.validate_smbios(unterminated))

    def test_physical_validator_failures_are_value_free(self) -> None:
        """physical_validator_failures_are_value_free"""
        secret = "PRIVATE-SERIAL-987654"
        with tempfile.TemporaryDirectory(prefix="private-path-") as temporary_directory:
            root = Path(temporary_directory)
            (root / "smbios_fixture.bin").write_bytes(wrapped_fixture()[:-1])
            (root / "wmi_monitors.json").write_text(json.dumps([{"serial_number_id": secret, "manufacturer_name": secret, "product_code": secret}]), encoding="utf-8")
            errors = validator.validate_fixture_dir(root)
            rendered = "\n".join(errors)
            self.assertNotIn(secret, rendered)
            self.assertNotIn(str(root), rendered)
            self.assertLessEqual(len(errors), validator.MAX_DIAGNOSTICS)
            self.assertTrue(all(error in validator.ERROR_CATEGORIES for error in errors))


if __name__ == "__main__":
    unittest.main()
