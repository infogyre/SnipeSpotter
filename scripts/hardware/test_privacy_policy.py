"""Test the hosted hardware experiment privacy contract."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from privacy_policy import validate_json_bytes, validate_report


class PrivacyPolicyTests(unittest.TestCase):
    """Verify that only the bounded report schema is accepted."""

    def test_accepts_bounded_report(self) -> None:
        errors = validate_report(self.valid_report())
        self.assertEqual(errors, [])

    def test_rejects_raw_identifier_field(self) -> None:
        report = self.valid_report()
        report["smbios"]["serial"] = "raw-host-serial"
        errors = validate_report(report)
        self.assertTrue(any("unknown field" in error for error in errors))

    def test_rejects_token_like_value(self) -> None:
        report = self.valid_report()
        report["build"]["image_version"] = "ghp_not-a-token"
        errors = validate_report(report)
        self.assertTrue(any("token-like" in error for error in errors))

    def test_rejects_identifier_like_free_form_values(self) -> None:
        report = self.valid_report()
        report["build"]["image_version"] = "HOST-SERIAL-ABC123"
        errors = validate_report(report)
        self.assertTrue(any("identifier-like" in error for error in errors))

    def test_rejects_windows_path_like_metadata(self) -> None:
        report = self.valid_report()
        report["build"]["powershell_version"] = r"C:\Users\runner\pwsh.exe"
        errors = validate_report(report)
        self.assertTrue(any("path-like" in error for error in errors))

    def test_requires_image_alias_to_match_selected_image(self) -> None:
        report = self.valid_report()
        report["build"]["image_alias"] = "windows-latest"
        errors = validate_report(report)
        self.assertTrue(any("image_alias must match" in error for error in errors))

    def test_rejects_firmware_and_edid_payloads(self) -> None:
        report = self.valid_report()
        report["smbios"]["raw_firmware"] = "AA00"
        report["wmi"]["edid"] = "base64-data"
        errors = validate_report(report)
        self.assertGreaterEqual(len(errors), 2)
        self.assertTrue(any("unknown field" in error for error in errors))

    def test_rejects_environment_dump_and_exception_text(self) -> None:
        report = self.valid_report()
        report["environment"] = {"COMPUTERNAME": "host"}
        report["api_results"][0]["exception"] = "unbounded diagnostic text"
        errors = validate_report(report)
        self.assertGreaterEqual(len(errors), 2)
        self.assertTrue(any("unknown field" in error for error in errors))

    def test_rejects_oversized_serialized_report(self) -> None:
        errors = validate_report(self.valid_report(), serialized_size=32_769)
        self.assertTrue(any("maximum" in error for error in errors))

    def test_rejects_uploaded_hmac_key(self) -> None:
        report = self.valid_report()
        report["privacy"]["hmac_key_uploaded"] = True
        errors = validate_report(report)
        self.assertTrue(any("hmac_key_uploaded" in error for error in errors))

    def test_validates_exact_json_bytes(self) -> None:
        import json

        payload = json.dumps(self.valid_report(), separators=(",", ":")).encode("utf-8")
        self.assertEqual(validate_json_bytes(payload), [])
        self.assertTrue(validate_json_bytes(b"not-json"))

    def test_collector_uses_hmac_key_for_bounded_fragments(self) -> None:
        collector = (Path(__file__).resolve().parent / "collect_hardware.ps1").read_text(encoding="utf-8")
        self.assertIn("HMACSHA256", collector)
        self.assertIn("HmacKeyHex", collector)
        self.assertIn("ImageAlias", collector)
        self.assertIn("WindowsIdentity", collector)
        self.assertIn("NT AUTHORITY\\SYSTEM", collector)
        self.assertIn("runner_architecture", collector)
        self.assertIn("AMD64", collector)
        workflow = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "hardware-experiment.yml").read_text(encoding="utf-8")
        self.assertIn("GetCurrentProcess().SessionId", workflow)
        self.assertIn("-ImageAlias $env:IMAGE_ALIAS", workflow)
        self.assertIn("-ImageAlias $arguments.image_alias", workflow)
        self.assertIn("hmac_fragments", collector)

    def test_workflow_uses_one_key_for_both_contexts_and_cleans_it(self) -> None:
        workflow = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "hardware-experiment.yml").read_text(encoding="utf-8")
        direct = workflow.index("-Context interactive-admin")
        local_system = workflow.index("context = 'LocalSystem'")
        self.assertLess(direct, local_system)
        self.assertIn("key_path = $keyPath", workflow)
        self.assertIn("/inheritance:r", workflow)
        self.assertLess(workflow.index("Invoke-ReportValidation -Context LocalSystem"), workflow.index("Upload validated redacted reports"))
        self.assertIn("cleanup failed", workflow)

    def test_workflow_writes_collector_compatible_hex_hmac_key(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "hardware-experiment.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("ToHexString", workflow)
        self.assertNotIn("WriteAllBytes($keyPath", workflow)

    def test_rejects_context_and_runtime_identity_mismatch(self) -> None:
        report = self.valid_report()
        report["experiment"]["context"] = "LocalSystem"
        report["experiment"]["caller_class"] = "interactive-admin"
        errors = validate_report(report)
        self.assertTrue(any("caller_class" in error for error in errors))

    def test_rejects_non_numeric_session_id(self) -> None:
        report = self.valid_report()
        report["experiment"]["session_id"] = "0123456789abcdef0123456789abcdef"
        errors = validate_report(report)
        self.assertTrue(any("numeric session id" in error for error in errors))

    def test_workflow_derives_session_id_in_each_process_context(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "hardware-experiment.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(
            workflow.count("[Diagnostics.Process]::GetCurrentProcess().SessionId"),
            2,
        )
        self.assertIn(
            "-SessionId $directSessionId",
            workflow,
        )
        self.assertIn(
            "$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId",
            workflow,
        )
        self.assertIn("-SessionId $sessionId", workflow)
        self.assertNotIn("session_id = $sessionId", workflow)

    def test_workflow_records_machine_readable_optional_image_skip(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "hardware-experiment.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("skipped_images:", workflow)
        self.assertIn("GITHUB_OUTPUT", workflow)
        self.assertIn('selection_status=ready', workflow)
        self.assertIn('skipped_images=', workflow)
        self.assertIn("confirmed_optional_images", workflow)
        self.assertIn("selected = sorted(required | (set(requested) & confirmed_optional))", workflow)
        self.assertIn("skipped = sorted(optional - set(selected))", workflow)
        self.assertNotIn("optional labels must be explicitly confirmed", workflow)

    def test_workflow_hosts_localsystem_and_retains_validated_report(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "hardware-experiment.yml"
        ).read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?i)(New-Service|sc\.exe\s+create|LocalSystem)")
        self.assertIn("upload-artifact@", workflow)
        self.assertIn("validate_report.py", workflow)

    def test_json_schema_matches_runtime_policy_boundaries(self) -> None:
        schema_path = Path(__file__).resolve().parent / "report-schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        wmi_lengths = schema["properties"]["wmi"]["properties"]["array_lengths"]
        self.assertFalse(wmi_lengths["additionalProperties"])
        build = schema["properties"]["build"]
        self.assertIn("image_alias", build["required"])
        self.assertIn("image_alias", build["properties"])
        self.assertEqual(
            set(wmi_lengths["properties"]),
            {
                "manufacturer_name",
                "product_code_id",
                "serial_number_id",
                "week_of_manufacture",
                "year_of_manufacture",
            },
        )
        fragment = schema["properties"]["hmac_fragments"]["items"]["properties"]["fragment"]
        self.assertEqual(fragment["pattern"], r"^(?!0{16}$)[0-9a-f]{16}$")

    def test_collector_preserves_per_api_durations_and_bounded_smbios_shape(self) -> None:
        collector = (Path(__file__).resolve().parent / "collect_hardware.ps1").read_text(encoding="utf-8")
        self.assertIn("duration_ms = $result.duration_ms", collector)
        self.assertIn("structure_count = $structureCount", collector)
        self.assertIn("type_histogram = $typeHistogram", collector)

    def test_collector_reads_ordered_dictionary_results_by_key(self) -> None:
        collector = (Path(__file__).resolve().parent / "collect_hardware.ps1").read_text(encoding="utf-8")
        self.assertIn("$smbiosResult['summary']", collector)
        self.assertIn("$wmiResult['summary']", collector)
        self.assertIn("$chassisResult['summary']", collector)
        self.assertNotIn("$smbiosResult.summary", collector)
        self.assertNotIn("$wmiResult.summary", collector)
        self.assertNotIn("$chassisResult.summary", collector)

    @staticmethod
    def valid_report() -> dict[str, object]:
        """Return the smallest complete report accepted by the policy."""
        return {
            "schema_version": 1,
            "experiment": {
                "image": "windows-2022",
                "context": "interactive-admin",
                "repetition": 1,
                "caller_class": "interactive-admin",
                "session_id": 1,
            },
            "build": {
                "image": "windows-2022",
                "image_alias": "windows-2022",
                "image_os": "win22",
                "image_version": "20250101.1",
                "os_build": 20348,
                "powershell_version": "7.4.6",
                "runner_architecture": "X64",
            },
            "process": {"bitness": 64},
            "privacy": {
                "hmac_algorithm": "HMAC-SHA256",
                "hmac_key_uploaded": False,
                "raw_identifiers_emitted": False,
                "raw_payloads_emitted": False,
                "max_report_bytes": 32768,
            },
            "api_results": [
                {
                    "api": "get_system_firmware_table",
                    "result": "ok",
                    "duration_ms": 12,
                },
                {"api": "wmi_monitor_identifier", "result": "ok", "duration_ms": 8},
                {"api": "system_enclosure", "result": "ok", "duration_ms": 5},
            ],
            "smbios": {
                "status": "ok",
                "length": 256,
                "structure_count": 7,
                "type_histogram": {"1": 1, "2": 1, "3": 1},
                "capped": False,
            },
            "wmi": {
                "status": "ok",
                "count": 2,
                "array_lengths": {
                    "manufacturer_name": [4, 4],
                    "product_code_id": [8, 8],
                    "serial_number_id": [12, 12],
                    "week_of_manufacture": [1, 1],
                    "year_of_manufacture": [1, 1],
                },
                "placeholder_classes": ["monitor_identifier"],
                "capped": False,
            },
            "chassis": {
                "status": "ok",
                "count": 1,
                "class_counts": {
                    "portable": 0,
                    "desktop": 1,
                    "server": 0,
                    "enclosure": 0,
                    "unknown": 0,
                },
                "capped": False,
            },
            "hmac_fragments": [
                {"kind": "machine", "fragment": "0123456789abcdef"},
                {"kind": "monitor", "fragment": "fedcba9876543210"},
            ],
        }


if __name__ == "__main__":
    unittest.main()
