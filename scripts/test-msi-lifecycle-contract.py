"""Static contract checks for the elevated MSI lifecycle harness."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).parent
SCRIPT = (ROOT / "test-msi-lifecycle.ps1").read_text(encoding="utf-8")
WAIT = (ROOT / "TestSupport" / "Wait.psm1").read_text(encoding="utf-8")


def _function_body(source: str, name: str) -> str:
    match = re.search(
        rf"function {re.escape(name)}\s*\{{(?P<body>.*?)\n\}}\n",
        source,
        re.DOTALL,
    )
    assert match, f"missing PowerShell function: {name}"
    return match.group("body")


def _function_text(source: str, name: str, next_name: str) -> str:
    start = source.index(f"function {name}")
    end = source.index(f"function {next_name}", start)
    return source[start:end]


def test_lifecycle_requires_sustained_running_service() -> None:
    assert "Running or Stopped" not in SCRIPT
    assert "Wait-ConditionStable" in SCRIPT
    assert "-StabilitySeconds $StableRunningSeconds" in SCRIPT
    assert "Import-Module (Join-Path $testSupportRoot 'Wait.psm1')" in SCRIPT
    assert "Wait-ForCondition" not in SCRIPT


def test_stability_wait_resets_after_a_non_running_sample() -> None:
    body = _function_body(WAIT, "Wait-ConditionStable")
    assert "Stopwatch]::GetTimestamp()" in body
    assert "$stableDeadline = $null" in body
    assert re.search(r"if \(\$value\).*?\$stableDeadline.*?else \{\s*\$stableDeadline = \$null", body, re.DOTALL)
    assert "StabilitySeconds" in body
    assert "TimeoutSeconds" in body


def test_lifecycle_checks_named_pipe_and_unconfigured_cli_status() -> None:
    assert "\\\\.\\pipe\\SnipeSpotter" in SCRIPT
    assert "spotter-cli.exe" in SCRIPT
    assert "@('--json', 'status')" in SCRIPT
    assert "Unconfigured" in SCRIPT


def test_lifecycle_uses_shared_support_modules() -> None:
    assert "Assert-ServiceRunsAsSystem -Name $serviceName" in SCRIPT
    assert "Write-BoundedDiagnostic" in SCRIPT
    assert "Invoke-FailureSafeCleanup" in SCRIPT
    assert "function Assert-RunningServiceOwner" not in SCRIPT
    assert "function Write-LifecycleDiagnostics" not in SCRIPT


def test_lifecycle_verifies_running_service_process_owner() -> None:
    assert "Assert-ServiceRunsAsSystem" in SCRIPT
    assert "Win32_Process" not in SCRIPT
    assert "Invoke-CimMethod -MethodName GetOwner" not in SCRIPT


def test_lifecycle_attempts_post_uninstall_cleanup_after_uninstall_failure() -> None:
    assert "if ($null -eq $cleanupError)" not in SCRIPT
    assert "post-uninstall-failure" in SCRIPT
    assert "if ($null -eq $primaryError)" in SCRIPT


def test_lifecycle_cli_failure_diagnostics_are_bounded() -> None:
    assert "Get-BoundedText" in SCRIPT
    assert "MaxCharacters" in SCRIPT
    assert "Get-Content -Raw -LiteralPath $stderrPath" not in SCRIPT


def test_failure_diagnostics_preserve_the_original_error_when_service_is_missing() -> None:
    assert "function Get-ServiceStatusForDiagnostic" in SCRIPT
    assert "Get-ServiceStatusForDiagnostic -Name $serviceName" in SCRIPT
    assert ".Status).Status" not in SCRIPT


def test_failure_diagnostics_cover_every_cleanup_boundary() -> None:
    assert SCRIPT.count("Get-ServiceStatusForDiagnostic -Name $serviceName") == 3


def test_service_logs_are_captured_before_failure_cleanup() -> None:
    assert "function Save-ServiceLogDiagnostic" in SCRIPT
    failure_capture = SCRIPT.index("Save-ServiceLogDiagnostic -DataRoot $dataRoot")
    cleanup_start = SCRIPT.index("} finally {", failure_capture)
    assert failure_capture < cleanup_start


def test_service_log_capture_is_bounded_best_effort_and_privacy_safe() -> None:
    helper = _function_text(SCRIPT, "Save-ServiceLogDiagnostic", "Get-MachinePathEntry")
    assert "$MaxServiceLogBytes = 32768" in SCRIPT
    assert "$MaxServiceLogFiles = 4" in SCRIPT
    assert "$MaxServiceLogTotalBytes = 65536" in SCRIPT
    assert "-Filter 'spotter-svc.log*'" in helper
    assert "-File" in helper
    assert "[IO.File]::OpenRead" in helper
    assert ".Read(" in helper
    assert "Set-Content" not in helper
    assert "Get-Content" not in helper
    assert "Get-ChildItem" in helper
    assert "Select-Object -First $MaxServiceLogFiles" in helper
    assert "if ($totalBytes -ge $MaxServiceLogTotalBytes)" in helper
    assert "if ($bytesToRead -le 0)" in helper
    assert "...[truncated]" in SCRIPT
    assert "$ServiceLogTruncationMarker" in helper
    assert "try {" in helper
    assert "catch {" in helper
    assert "$_.Name" not in helper
    assert "$logName = $log.Name" in helper
    assert "Write-Warning" in helper
    assert "return" in helper


def test_service_log_capture_preserves_primary_error_on_setup_failure() -> None:
    helper = _function_text(SCRIPT, "Save-ServiceLogDiagnostic", "Get-MachinePathEntry")
    invocation = "Save-ServiceLogDiagnostic -DataRoot $dataRoot -Destination $LogDirectory"
    assert invocation in SCRIPT
    assert "try {\n        Save-ServiceLogDiagnostic" in SCRIPT
    assert "Write-Warning \"service log capture failed:" in SCRIPT
    assert helper.count("try {") >= 2
    assert helper.count("catch {") >= 2
    assert "$primaryError = $_" in SCRIPT
    assert SCRIPT.index("$primaryError = $_") < SCRIPT.index(invocation)


def test_service_log_capture_behavior_with_temporary_files() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for the service log capture behavior probe"
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        data_root = root / "data"
        log_root = data_root / "logs"
        destination = root / "destination"
        log_root.mkdir(parents=True)
        (log_root / "spotter-svc.log.2026-06-01").write_bytes(b"A" * 40_000)
        (log_root / "spotter-svc.log").write_bytes(b"B" * 20_000)
        for day in range(2, 7):
            (log_root / f"spotter-svc.log.2026-06-{day:02d}").write_bytes(b"D" * 20_000)
        (log_root / "other.log").write_bytes(b"C" * 10)
        blocked_destination = root / "blocked-destination"
        blocked_destination.write_bytes(b"destination is not a directory")
        probe = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
""" + SCRIPT[SCRIPT.index("$MaxServiceLogBytes ="):SCRIPT.index("function Get-ServiceStatusForDiagnostic")] + _function_text(SCRIPT, "Save-ServiceLogDiagnostic", "Get-MachinePathEntry") + f"""
Save-ServiceLogDiagnostic -DataRoot '{data_root.as_posix()}' -Destination '{destination.as_posix()}'
$primary = 'sentinel primary error'
try {{
    Save-ServiceLogDiagnostic -DataRoot '{data_root.as_posix()}' -Destination '{blocked_destination.as_posix()}'
}} catch {{
    throw "capture replaced primary error: $($_.Exception.Message)"
}}
if (-not (Test-Path -LiteralPath '{(destination / 'spotter-svc.log.2026-06-01').as_posix()}' -PathType Leaf)) {{ throw 'daily service log was not captured' }}
if (Test-Path -LiteralPath '{(destination / 'other.log').as_posix()}') {{ throw 'unrelated log was captured' }}
$capturedFiles = @(Get-ChildItem -LiteralPath '{destination.as_posix()}' -File)
if ($capturedFiles.Count -gt 4) {{ throw "file count bound exceeded: $($capturedFiles.Count)" }}
$totalCapturedBytes = ($capturedFiles | Measure-Object -Property Length -Sum).Sum
if ($totalCapturedBytes -gt 65536) {{ throw "aggregate byte bound exceeded: $totalCapturedBytes" }}
$captured = [IO.File]::ReadAllBytes('{(destination / 'spotter-svc.log.2026-06-01').as_posix()}')
if ($captured.Length -gt 32768) {{ throw "per-file bound exceeded: $($captured.Length)" }}
if ($captured.Length -eq 32768 -and -not ([Text.Encoding]::UTF8.GetString($captured)).EndsWith('...[truncated]')) {{ throw 'bounded file lacks truncation marker' }}
Write-Output $primary
"""
        result = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert "sentinel primary error" in result.stdout


def test_elevated_source_artifact_producer_matches_packaged_consumer() -> None:
    workflow = (ROOT.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
    build = workflow[workflow.index("- name: Build source MSI") : workflow.index("- name: Validate MSI lifecycle")]
    validate = workflow[workflow.index("- name: Validate MSI lifecycle") : workflow.index("- name: Capture bounded lifecycle diagnostics")]
    assert "Join-Path (Resolve-Path -LiteralPath packaged).Path" in build
    assert "source-artifact package inventory must contain exactly the MSI consumed by validation" in build
    assert "Get-ChildItem -LiteralPath packaged -Filter '*.msi' -File" in validate
    assert "Join-Path (Get-Location) (Join-Path 'packaged' $resolvedName)" in validate


def test_ci_uses_reusable_elevated_result_or_successful_skip() -> None:
    workflow = (ROOT.parent / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "elevated_skip:" in workflow
    assert "needs: [changes, checks, elevated, elevated_skip]" in workflow
    assert "ELEVATED_SKIP_RESULT: ${{ needs.elevated_skip.result }}" in workflow
    assert "ELEVATED_OUTPUT: ${{ needs.elevated.outputs.lifecycle_result }}" in workflow
    assert "ELEVATED_SKIP_OUTPUT: ${{ needs.elevated_skip.outputs.elevated_result }}" in workflow
    assert 'test "${ELEVATED_RESULT}" = success' in workflow
    assert 'test "${ELEVATED_OUTPUT}" = success' in workflow
    assert 'test "${ELEVATED_SKIP_RESULT}" = success' in workflow
    assert 'test "${ELEVATED_SKIP_OUTPUT}" = skipped' in workflow


def test_elevated_source_artifact_contains_complete_msi_stage() -> None:
    workflow = (ROOT.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
    build = workflow[workflow.index("- name: Build source MSI") : workflow.index("- name: Validate MSI lifecycle")]
    assert "Remove-Item -LiteralPath installer/bin" in build
    assert "cargo install cargo-cyclonedx --locked" in build
    assert "cargo cyclonedx --manifest-path spotter-svc/Cargo.toml --format json" in build
    assert "cargo cyclonedx --manifest-path spotter-cli/Cargo.toml --format json" in build
    assert "Join-Path $stage 'sbom/spotter-svc.cdx.json'" in build
    assert "Join-Path $stage 'sbom/spotter-cli.cdx.json'" in build
    assert "expectedStageFiles" in build


def main() -> None:
    test_lifecycle_requires_sustained_running_service()
    test_lifecycle_checks_named_pipe_and_unconfigured_cli_status()
    test_lifecycle_uses_shared_support_modules()
    test_lifecycle_verifies_running_service_process_owner()
    test_lifecycle_attempts_post_uninstall_cleanup_after_uninstall_failure()
    test_lifecycle_cli_failure_diagnostics_are_bounded()
    test_failure_diagnostics_preserve_the_original_error_when_service_is_missing()
    test_failure_diagnostics_cover_every_cleanup_boundary()
    test_service_logs_are_captured_before_failure_cleanup()
    test_service_log_capture_is_bounded_best_effort_and_privacy_safe()
    test_service_log_capture_preserves_primary_error_on_setup_failure()
    test_service_log_capture_behavior_with_temporary_files()
    test_elevated_source_artifact_producer_matches_packaged_consumer()
    test_ci_uses_reusable_elevated_result_or_successful_skip()
    test_elevated_source_artifact_contains_complete_msi_stage()
    print("lifecycle contract: OK")


if __name__ == "__main__":
    main()
