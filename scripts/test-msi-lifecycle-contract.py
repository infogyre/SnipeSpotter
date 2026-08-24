"""Static contract checks for the elevated MSI lifecycle harness."""

from pathlib import Path
import re


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
    assert "Write-BoundedDiagnostics" in SCRIPT
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
    test_elevated_source_artifact_producer_matches_packaged_consumer()
    test_ci_uses_reusable_elevated_result_or_successful_skip()
    test_elevated_source_artifact_contains_complete_msi_stage()
    print("lifecycle contract: OK")


if __name__ == "__main__":
    main()
