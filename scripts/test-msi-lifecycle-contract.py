"""Static contract checks for the elevated MSI lifecycle harness."""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
SCRIPT = (ROOT / "test-msi-lifecycle.ps1").read_text(encoding="utf-8")
WAIT = (ROOT / "TestSupport" / "Wait.psm1").read_text(encoding="utf-8")
DIAGNOSTICS = (ROOT / "TestSupport" / "Diagnostics.psm1").read_text(encoding="utf-8")
SECURITY = (ROOT / "TestSupport" / "Security.psm1").read_text(encoding="utf-8")
ACL = (ROOT / "TestSupport" / "Acl.psm1").read_text(encoding="utf-8")
SERVICE = (ROOT.parent / "spotter-svc" / "src" / "service.rs").read_text(encoding="utf-8")
ATOMIC_FILE = (ROOT.parent / "spotter-svc" / "src" / "atomic_file.rs").read_text(encoding="utf-8")
WINDOWS_ACL = (ROOT.parent / "spotter-svc" / "src" / "windows_acl.rs").read_text(encoding="utf-8") if (ROOT.parent / "spotter-svc" / "src" / "windows_acl.rs").is_file() else ""
PRODUCT_WXS = (ROOT.parent / "installer" / "Product.wxs").read_text(encoding="utf-8")
DIRECT_SCM = (ROOT / "test-direct-scm-lifecycle.ps1").read_text(encoding="utf-8") if (ROOT / "test-direct-scm-lifecycle.ps1").is_file() else ""


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


def _text_until(source: str, name: str, marker: str) -> str:
    start = source.index(f"function {name}")
    end = source.index(marker, start)
    return source[start:end]


def test_lifecycle_requires_sustained_running_service() -> None:
    assert "Running or Stopped" not in SCRIPT
    assert "Wait-ConditionStable" in SCRIPT
    assert "-StabilitySeconds $StableRunningSeconds" in SCRIPT
    assert "Import-Module (Join-Path $testSupportRoot 'Wait.psm1')" in SCRIPT
    assert "Wait-ForCondition" not in SCRIPT


def test_lifecycle_imports_wait_helpers_after_scm_module() -> None:
    scm_import = SCRIPT.index("Import-Module (Join-Path $testSupportRoot 'Scm.psm1')")
    wait_import = SCRIPT.index("Import-Module (Join-Path $testSupportRoot 'Wait.psm1')")
    assert wait_import > scm_import


def test_service_enters_runtime_before_fsm_spawn() -> None:
    runtime_creation = SERVICE.index("let tokio_runtime = tokio::runtime::Builder")
    runtime_enter = SERVICE.index("let _runtime_guard = tokio_runtime.enter()")
    fsm_spawn = SERVICE.index("let fsm = crate::fsm::spawn")
    assert runtime_creation < runtime_enter < fsm_spawn


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


def test_lifecycle_uses_valid_test_path_types() -> None:
    assert "Type = 'Leaf'" in SCRIPT
    assert "Type = 'Container'" in SCRIPT
    assert "Type = 'File'" not in SCRIPT
    assert "Type = 'Directory'" not in SCRIPT
    assert "-PathType $artifact.Type" in SCRIPT
    assert not re.search(r"-PathType\s+(?:File|Directory)\b", SCRIPT)


def test_lifecycle_starts_service_before_runtime_artifact_waits() -> None:
    start = SCRIPT.index("Start-Service -Name $serviceName")
    service_ready = SCRIPT.index("Wait-ServiceState -Name $serviceName", start)
    pipe_ready = SCRIPT.index("Wait-Condition -Description 'SnipeSpotter named pipe'", service_ready)
    status_ready = SCRIPT.index("Wait-Condition -Description 'SnipeSpotter status response'", pipe_ready)
    artifact_wait = SCRIPT.index("$runtimeArtifacts = @(")
    assert start < service_ready < pipe_ready < status_ready < artifact_wait
    assert "Wait-Condition -Description 'SnipeSpotter service registration'" in SCRIPT
    assert "Wait-ConditionStable" in SCRIPT


def test_lifecycle_collects_only_present_runtime_artifacts_and_uses_scoped_acl_commands() -> None:
    acl_import = SCRIPT.index("Import-Module (Join-Path $testSupportRoot 'Acl.psm1')")
    artifact_wait = SCRIPT.index("$runtimeArtifacts = @(")
    required_artifact_block_end = SCRIPT.index("    foreach ($artifact in $runtimeArtifacts)", artifact_wait)
    required_artifact_block = SCRIPT[artifact_wait:required_artifact_block_end]
    validation = SCRIPT.index("Acl\\Assert-AclContract", artifact_wait)
    repair = SCRIPT.index("Acl\\Set-AclContract")

    assert acl_import < artifact_wait < validation < repair
    for required_artifact in (
        "[pscustomobject]@{ Path = $dataRoot; Type = 'Container' }",
        "[pscustomobject]@{ Path = $settingsPath; Type = 'Leaf' }",
        "state-hmac-key.bin",
        "[pscustomobject]@{ Path = (Join-Path $dataRoot 'logs'); Type = 'Container' }",
    ):
        assert required_artifact in required_artifact_block
    assert "state.toml" not in required_artifact_block
    assert "operations.jsonl" not in required_artifact_block
    assert "foreach ($optionalArtifact in @('state.toml', 'operations.jsonl'))" in SCRIPT
    assert "if (Test-Path -LiteralPath $optionalPath -PathType Leaf)" in SCRIPT
    assert "Get-ChildItem -LiteralPath (Join-Path $dataRoot 'logs') -Filter 'spotter-svc.log*' -File" in SCRIPT
    assert "Wait-Condition -Description 'service rolling log file'" not in SCRIPT
    assert "Acl\\Assert-AclContract -Path $dataRoot" in SCRIPT
    assert "Acl\\Set-AclContract -Path $dataRoot" in SCRIPT
    assert "Ensure-AclContract" not in SCRIPT
    assert not re.search(r"(?<!\\)Assert-AclContract -Path \$dataRoot", SCRIPT)


def test_lifecycle_asserts_child_probe_result_not_parent_token() -> None:
    probe = SCRIPT.index("Assert-StandardUserCannotReadWrite")
    child_assertion = SCRIPT.index("Assert-ChildIsStandardUser -Result", probe)
    artifact_loop = SCRIPT.index("foreach ($artifact in $runtimeArtifacts)", probe)
    assert child_assertion < artifact_loop
    assert "Get-TokenProof" not in SCRIPT[probe:child_assertion]


def test_standard_user_helper_returns_the_child_probe_result_once() -> None:
    helper = _function_body(SECURITY, "Assert-StandardUserCannotReadWrite")
    assert "Assert-ChildIsStandardUser -Result $result" in helper
    assert "[void](Assert-ChildIsStandardUser -Result $result)" in helper
    assert helper.count("Assert-ChildIsStandardUser -Result $result") == 2
    assert "return $result" in helper
    assert "Invoke-AsStandardUser" in helper
    assert "Get-TokenProof" not in helper


def test_child_probe_proves_unprivileged_token_and_denied_access() -> None:
    helper = _function_body(SECURITY, "Assert-StandardUserCannotReadWrite")
    for field in (
        "child_is_administrator=$isAdministrator",
        "child_is_system=$isSystem",
        "child_is_standard_user=$(-not $isSystem -and -not $isAdministrator)",
        "read_denied=$readDenied",
        "write_denied=$writeDenied",
    ):
        assert field in helper
    assert "if (-not $readDenied -or -not $writeDenied)" in helper
    assert "exit 20" in helper
    assert "exit 21" in helper


def test_product_and_atomic_writer_apply_the_same_protected_acl_contract() -> None:
    assert '<Directory Id="DataFolder" Name="SnipeSpotter" />' in PRODUCT_WXS
    assert '<File Id="SettingsTemplate" Source="settings.toml" Name="settings.toml" KeyPath="yes">' in PRODUCT_WXS
    assert PRODUCT_WXS.count('<util:PermissionEx User="SYSTEM" GenericAll="yes" Inheritable="no" />') == 2
    assert PRODUCT_WXS.count('<util:PermissionEx User="Administrators" GenericAll="yes" Inheritable="no" />') == 2
    assert "SecureObjects" not in PRODUCT_WXS
    assert "Sddl=" not in PRODUCT_WXS
    assert "User=\"Everyone\"" not in PRODUCT_WXS
    assert "User=\"Users\"" not in PRODUCT_WXS
    assert "SetAccessRuleProtection" not in SCRIPT
    assert "apply_runtime_acl_contract(&root)" in SERVICE
    assert "apply_acl_contract(&temporary)" in ATOMIC_FILE
    assert "apply_acl_contract(path)" in ATOMIC_FILE
    assert 'pub const DATA_ACL_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";' in WINDOWS_ACL
    assert "SetNamedSecurityInfoW" in WINDOWS_ACL
    assert "DACL_SECURITY_INFORMATION" in WINDOWS_ACL
    assert "PROTECTED_DACL_SECURITY_INFORMATION" in WINDOWS_ACL


def test_startup_repairs_existing_runtime_artifact_acls_before_access() -> None:
    helper = SERVICE[SERVICE.index("fn apply_runtime_acl_contract"):SERVICE.index("fn service_main")]
    startup = SERVICE[SERVICE.index("fn run_service"):]
    assert "apply_runtime_acl_contract(&root)" in startup
    assert startup.index("apply_runtime_acl_contract(&root)") < startup.index('root.join("settings.toml")')
    for artifact in (
        'root.join("settings.toml")',
        'root.join("state.toml")',
        'root.join("state-hmac-key.bin")',
        'root.join("operations.jsonl")',
        'root.join("logs")',
    ):
        assert artifact in helper
    assert "fs::read_dir(&logs_dir)" in helper
    assert "SERVICE_LOG_PREFIX" in helper
    assert "starts_with(crate::logging::SERVICE_LOG_PREFIX)" in helper
    assert "file_type" in helper
    assert 'root.join("logs").join("spotter-svc.log")' not in helper


def test_lifecycle_discovers_actual_rolling_log_artifacts() -> None:
    log_directory = "Join-Path $dataRoot 'logs'"
    assert f"Get-ChildItem -LiteralPath ({log_directory}) -Filter 'spotter-svc.log*' -File" in SCRIPT
    assert "$logFiles = @(" in SCRIPT
    assert "Wait-Condition -Description 'service rolling log file'" not in SCRIPT
    assert "Path = $_.FullName" in SCRIPT
    assert "Join-Path $dataRoot 'logs\\spotter-svc.log'" not in SCRIPT


def test_preserved_settings_file_has_direct_wix_acl_entries() -> None:
    settings_start = PRODUCT_WXS.index('<File Id="SettingsTemplate"')
    settings_end = PRODUCT_WXS.index("</File>", settings_start) + len("</File>")
    settings_file = PRODUCT_WXS[settings_start:settings_end]
    assert '<util:PermissionEx User="SYSTEM" GenericAll="yes" Inheritable="no" />' in settings_file
    assert '<util:PermissionEx User="Administrators" GenericAll="yes" Inheritable="no" />' in settings_file


def test_acl_helper_validates_before_repair_and_uses_real_acl_contract() -> None:
    assert "function Assert-AclContract" in ACL
    assert "function Set-AclContract" in ACL
    validation = ACL.index("function Assert-AclContract")
    repair = ACL.index("function Set-AclContract")
    assert validation < repair
    assert "Get-AclContract -Path $Path -PathType $PathType" in ACL
    assert "Assert-AclRulesContract -Path $Path -PathType $PathType -Rules $contract.rules" in ACL
    assert "path_type = $PathType" in ACL
    assert "Set-Acl -LiteralPath $Path -AclObject $acl" in ACL
    assert "[ValidateSet('Leaf', 'Container')]" in ACL
    assert "$canonicalChildRightsMask = 268435456" in ACL
    assert "$canonicalChildPropagationMask" in ACL
    assert "AddAccessRule($rule)" in ACL
    assert "function Get-RequiredAclRule" in ACL


def test_acl_contract_repair_preserves_deny_rules() -> None:
    repair = ACL[ACL.index("function Set-AclContract") : ACL.index("function Assert-AclPrincipal")]
    assert "AccessControlType]::Allow)" in repair
    assert "AccessControlType]::Deny" not in repair
    assert "RemoveAccessRule($rule)" in repair


def test_acl_diagnostics_are_bounded_and_precede_any_repair() -> None:
    assert "function Get-AclDiagnostic" in ACL
    assert "function Write-AclDiagnostic" in ACL
    assert "function Save-AclFailureDiagnostic" in SCRIPT
    capture = SCRIPT.index("Acl\\Write-AclDiagnostic")
    repair = SCRIPT.index("Acl\\Set-AclContract")
    assert capture < repair
    assert SCRIPT.count("Acl\\Write-AclDiagnostic") == 2
    assert "-PathClass 'root'" in SCRIPT
    assert "-PathClass 'settings'" in SCRIPT
    assert "failure-acl-root.json" in SCRIPT
    assert "failure-acl-settings.json" in SCRIPT
    helper = _function_text(SCRIPT, "Save-AclFailureDiagnostic", "Get-MachinePathEntry")
    assert helper.count("try {") == 2
    assert helper.count("catch {") == 2
    assert helper.index("-PathClass 'root'") < helper.index("-PathClass 'settings'")
    assert helper.count("Test-Path -LiteralPath") == 2
    assert "Exception.Message" not in helper
    assert "Write-Warning 'ACL root diagnostic capture failed'" in helper
    assert "Write-Warning 'ACL settings diagnostic capture failed'" in helper


def test_acl_diagnostic_capture_attempts_settings_after_root_failure() -> None:
    helper = _function_text(SCRIPT, "Save-AclFailureDiagnostic", "Get-MachinePathEntry")
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for ACL diagnostic capture independence"
    with tempfile.TemporaryDirectory(prefix="acl-diagnostic-") as temporary_directory:
        root = Path(temporary_directory)
        data_root = root / "data"
        data_root.mkdir()
        settings_path = data_root / "settings.toml"
        settings_path.write_text("settings", encoding="utf-8")
        log_directory = root / "logs"
        probe = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Acl\\Write-AclDiagnostic {
    param(
        [string]$Path,
        [string]$PathClass,
        [string]$OutputPath
    )
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
    Add-Content -LiteralPath $OutputPath -Value $PathClass
    if ($PathClass -eq 'root') { throw 'root capture failed' }
}
""" + helper + """
$dataRoot = $env:SPOTTER_ACL_DATA_ROOT
$settingsPath = $env:SPOTTER_ACL_SETTINGS_PATH
$LogDirectory = $env:SPOTTER_ACL_LOG_DIRECTORY
Save-AclFailureDiagnostic
if (-not (Test-Path -LiteralPath (Join-Path $LogDirectory 'failure-acl-settings.json') -PathType Leaf)) {
    throw 'settings ACL diagnostic was not attempted after root failure'
}
Write-Output 'independent ACL captures accepted'
"""
        environment = os.environ | {
            "SPOTTER_ACL_DATA_ROOT": str(data_root),
            "SPOTTER_ACL_SETTINGS_PATH": str(settings_path),
            "SPOTTER_ACL_LOG_DIRECTORY": str(log_directory),
        }
        result = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert "independent ACL captures accepted" in result.stdout


def test_atomic_windows_contract_applies_acl_to_temporary_and_replaced_files() -> None:
    assert "#[cfg(all(windows, feature = \"test-support\"))]" in ATOMIC_FILE
    assert "apply_acl_contract(&temporary)" in ATOMIC_FILE
    assert "apply_acl_contract(path)" in ATOMIC_FILE


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


def test_bounded_text_accepts_empty_files() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for the empty diagnostic file probe"
    with tempfile.TemporaryDirectory(prefix="fixture's-") as temporary_directory:
        empty_file = Path(temporary_directory) / "empty.txt"
        empty_file.write_bytes(b"")
        module = ROOT / "TestSupport" / "Diagnostics.psm1"
        probe = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_DIAGNOSTICS_MODULE -Force
$result = Get-BoundedText -Path $env:SPOTTER_EMPTY_DIAGNOSTIC_FILE -MaxCharacters 512
if ($result -ne '') { throw "empty diagnostic file returned unexpected text: $result" }
Write-Output 'empty diagnostic file accepted'
"""
        environment = os.environ | {
            "SPOTTER_DIAGNOSTICS_MODULE": str(module),
            "SPOTTER_EMPTY_DIAGNOSTIC_FILE": str(empty_file),
        }
        result = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert "empty diagnostic file accepted" in result.stdout


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
    assert "[int64](Get-Item -LiteralPath $log.FullName -Force -ErrorAction Stop).Length" in helper
    assert "$log.Length" not in helper
    assert "$source.Length" not in helper
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
    observed_acl = SCRIPT.index("[void](Acl\\Assert-AclContract -Path $dataRoot -PathType Container)")
    assert observed_acl < SCRIPT.index(invocation)
    assert "Write-Warning \"service log capture failed:" in SCRIPT
    assert helper.count("try {") >= 2
    assert helper.count("catch {") >= 2
    assert "$primaryError = $_" in SCRIPT
    assert SCRIPT.index("$primaryError = $_") < SCRIPT.index(invocation)


def test_service_log_capture_behavior_with_temporary_files() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for the service log capture behavior probe"
    with tempfile.TemporaryDirectory(prefix="fixture's-") as temporary_directory:
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
""" + SCRIPT[SCRIPT.index("$MaxServiceLogBytes ="):SCRIPT.index("function Get-ServiceStatusForDiagnostic")] + _function_text(SCRIPT, "Save-ServiceLogDiagnostic", "Get-MachinePathEntry") + """
Save-ServiceLogDiagnostic -DataRoot $env:SPOTTER_DATA_ROOT -Destination $env:SPOTTER_DESTINATION
$primary = 'sentinel primary error'
try {
    Save-ServiceLogDiagnostic -DataRoot $env:SPOTTER_DATA_ROOT -Destination $env:SPOTTER_BLOCKED_DESTINATION
} catch {
    throw "capture replaced primary error: $($_.Exception.Message)"
}
if (-not (Test-Path -LiteralPath $env:SPOTTER_CAPTURED_DAILY_LOG -PathType Leaf)) { throw 'daily service log was not captured' }
if (Test-Path -LiteralPath $env:SPOTTER_UNRELATED_LOG) { throw 'unrelated log was captured' }
$capturedFiles = @(Get-ChildItem -LiteralPath $env:SPOTTER_DESTINATION -File)
if ($capturedFiles.Count -gt 4) { throw "file count bound exceeded: $($capturedFiles.Count)" }
$totalCapturedBytes = ($capturedFiles | Measure-Object -Property Length -Sum).Sum
if ($totalCapturedBytes -gt 65536) { throw "aggregate byte bound exceeded: $totalCapturedBytes" }
$captured = [IO.File]::ReadAllBytes($env:SPOTTER_CAPTURED_DAILY_LOG)
if ($captured.Length -gt 32768) { throw "per-file bound exceeded: $($captured.Length)" }
if ($captured.Length -eq 32768 -and -not ([Text.Encoding]::UTF8.GetString($captured)).EndsWith('...[truncated]')) { throw 'bounded file lacks truncation marker' }
Write-Output $primary
"""
        environment = os.environ | {
            "SPOTTER_DATA_ROOT": str(data_root),
            "SPOTTER_DESTINATION": str(destination),
            "SPOTTER_BLOCKED_DESTINATION": str(blocked_destination),
            "SPOTTER_CAPTURED_DAILY_LOG": str(destination / "spotter-svc.log.2026-06-01"),
            "SPOTTER_UNRELATED_LOG": str(destination / "other.log"),
        }
        result = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
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


def test_direct_scm_lifecycle_contract_is_separate_and_condition_based() -> None:
    assert DIRECT_SCM, "missing direct SCM lifecycle script"
    for required in (
        "test-support",
        "ServiceInstall",
        "Start-Service",
        "Get-CimInstance Win32_Service",
        "already installed",
        "not installed",
        "Assert-ServiceRunsAsSystem",
        "Wait-ServiceState",
        "Wait-ServiceRemoved",
        "Get-NormalizedAcl",
        "Invoke-FailureSafeCleanup",
    ):
        assert required in DIRECT_SCM, f"direct SCM script missing {required!r}"
    assert "Start-Sleep -Seconds 5" not in DIRECT_SCM
    assert "test-support CLI arguments" in DIRECT_SCM
    assert "SnipeSpotterDirect-" in DIRECT_SCM
    assert "SnipeSpotter\\\"" not in DIRECT_SCM
    workflow = (ROOT.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
    assert "--features test-support" in workflow
    assert "spotter-cli-test-support.exe" in workflow
    assert "direct-scm" in workflow
    assert "packaged/spotter-cli.exe" not in workflow[workflow.index("- name: Validate direct CLI SCM lifecycle") : workflow.index("- name: Capture bounded lifecycle diagnostics")]


def test_direct_scm_service_executable_is_staged_for_both_artifact_modes() -> None:
    workflow = (ROOT.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
    source_build = workflow[workflow.index("- name: Build source MSI") : workflow.index("- name: Validate MSI lifecycle")]
    direct_stage = workflow[workflow.index("- name: Stage direct SCM service executable") : workflow.index("- name: Build direct SCM test-support CLI")]
    direct_validation = workflow[workflow.index("- name: Validate direct CLI SCM lifecycle") : workflow.index("- name: Capture bounded lifecycle diagnostics")]

    assert "spotter-svc.exe" in source_build
    assert "Copy-Item" in source_build
    assert "Test-Path -LiteralPath $serviceSource -PathType Leaf" in direct_stage
    assert "Expand-Archive" in direct_stage
    assert "*-symbols.zip" in direct_stage
    assert "[int64](Get-Item -LiteralPath $serviceSource -Force).Length -le 0" in direct_stage
    assert "Test-Path -LiteralPath $servicePath -PathType Leaf" in direct_stage
    assert "[int64](Get-Item -LiteralPath $servicePath -Force).Length -le 0" in direct_stage
    assert "$servicePath = Join-Path (Resolve-Path -LiteralPath packaged).Path 'spotter-svc.exe'" in direct_validation


def test_direct_scm_process_timeout_covers_two_registrar_waits() -> None:
    assert "[ValidateRange(185, 1200)]" in DIRECT_SCM
    assert "[int]$ProcessTimeoutSeconds = 185" in DIRECT_SCM
    assert "$MinimumProcessTimeoutSeconds = ($RegistrarWaitTimeoutSeconds * 2) + 5" in DIRECT_SCM
    assert "$ProcessTimeoutSeconds -ge $MinimumProcessTimeoutSeconds" in DIRECT_SCM
    assert "ProcessTimeoutSeconds" in DIRECT_SCM
    workflow = (ROOT.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(encoding="utf-8")
    assert "-ProcessTimeoutSeconds" not in workflow


def test_direct_scm_probes_standard_user_after_runtime_artifacts_and_cleans_up() -> None:
    import_position = DIRECT_SCM.index("Import-Module (Join-Path $testSupportRoot 'Security.psm1')")
    start_position = DIRECT_SCM.index("Start-Service -Name $serviceName")
    artifacts_position = DIRECT_SCM.index("$runtimeArtifacts = @(")
    user_position = DIRECT_SCM.index("New-TemporaryStandardUser", artifacts_position)
    denial_position = DIRECT_SCM.index("Assert-StandardUserCannotReadWrite", user_position)
    cleanup_position = DIRECT_SCM.index("Remove-TemporaryStandardUser -User $standardUser", denial_position)
    assert import_position < start_position < artifacts_position < user_position < denial_position
    assert "Assert-ChildIsStandardUser -Result $probeResult" in DIRECT_SCM
    assert cleanup_position > denial_position
    assert "finally" in DIRECT_SCM[ user_position : cleanup_position + 120 ]
    assert "Get-TokenProof" not in DIRECT_SCM[user_position:]


def test_direct_scm_standard_user_name_fits_security_helper_contract() -> None:
    match = re.search(r'New-TemporaryStandardUser -Name \(\"([^\"]+)\"', DIRECT_SCM)
    assert match, "direct SCM script must generate a temporary standard-user name"
    assert len(match.group(1)) + 5 <= 20


def test_installed_cli_contract_accepts_empty_stderr_without_relaxing_other_parameters() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for the installed CLI stream contract probe"
    assert_true_body = _function_body(SCRIPT, "Assert-True")
    cli_contract_body = _function_body(SCRIPT, "Assert-InstalledCliContract")
    probe = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-True {
""" + assert_true_body + """
}
function Assert-InstalledCliContract {
""" + cli_contract_body + """
}
$result = [pscustomobject]@{
    ExitCode = 0
    Stdout = 'expected stdout'
    Stderr = ''
    Description = 'stream contract probe'
}
Assert-InstalledCliContract -Result $result -ExpectedExitCode 0 -ExpectedStdout 'expected stdout' -ExpectedStderr ''

$assertionFailures = 0
try {
    Assert-InstalledCliContract -Result $result -ExpectedExitCode 1 -ExpectedStdout 'expected stdout' -ExpectedStderr ''
} catch {
    $assertionFailures++
}
try {
    Assert-InstalledCliContract -Result $result -ExpectedExitCode 0 -ExpectedStdout 'wrong stdout' -ExpectedStderr ''
} catch {
    $assertionFailures++
}
try {
    Assert-InstalledCliContract -Result $result -ExpectedExitCode 0 -ExpectedStdout 'expected stdout' -ExpectedStderr 'unexpected stderr'
} catch {
    $assertionFailures++
}
if ($assertionFailures -ne 3) { throw "stream assertions accepted $assertionFailures invalid result(s)" }

$bindingFailures = 0
try {
    Assert-InstalledCliContract -ExpectedExitCode 0 -ExpectedStdout 'expected stdout' -ExpectedStderr ''
} catch {
    $bindingFailures++
}
try {
    Assert-InstalledCliContract -Result $result -ExpectedExitCode 0 -ExpectedStdout 'expected stdout'
} catch {
    $bindingFailures++
}
try {
    Assert-InstalledCliContract -Result $result -ExpectedExitCode 0 -ExpectedStdout '' -ExpectedStderr ''
} catch {
    $bindingFailures++
}
if ($bindingFailures -ne 3) { throw "required stream parameters rejected $bindingFailures invalid call(s)" }
Write-Output 'installed CLI stream contract accepted'
"""
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "installed CLI stream contract accepted" in result.stdout


def test_msi_acl_replacement_uses_installed_atomic_config_writer_and_exact_cli_contract() -> None:
    assert "Add-Content -LiteralPath $settingsPath -Value \"`n$replacementMarker\"" not in SCRIPT
    update = "Invoke-InstalledCli -Arguments @('config', 'set', 'polling.interval_hours', $replacementInterval)"
    assert update in SCRIPT
    assert "Assert-InstalledCliContract" in SCRIPT
    assert "ExpectedStdout 'updated polling.interval_hours'" in SCRIPT
    assert "ExpectedStderr ''" in SCRIPT
    assert "Wait-Condition -Description 'settings committed by CLI'" in SCRIPT
    assert "Compare-Object $artifactAclBefore[$settingsPath] $candidate" in SCRIPT
    update_position = SCRIPT.index(update)
    committed_position = SCRIPT.index("settings committed by CLI", update_position)
    denial_position = SCRIPT.index("Assert-StandardUserCannotReadWrite", committed_position)
    assert update_position < committed_position < denial_position
    assert "lifecycle-preservation-marker" in SCRIPT
    assert SCRIPT.index("lifecycle-preservation-marker") < update_position


def main() -> None:
    test_lifecycle_requires_sustained_running_service()
    test_lifecycle_imports_wait_helpers_after_scm_module()
    test_service_enters_runtime_before_fsm_spawn()
    test_lifecycle_checks_named_pipe_and_unconfigured_cli_status()
    test_lifecycle_uses_valid_test_path_types()
    test_lifecycle_starts_service_before_runtime_artifact_waits()
    test_lifecycle_collects_only_present_runtime_artifacts_and_uses_scoped_acl_commands()
    test_lifecycle_asserts_child_probe_result_not_parent_token()
    test_product_and_atomic_writer_apply_the_same_protected_acl_contract()
    test_acl_diagnostics_are_bounded_and_precede_any_repair()
    test_acl_diagnostic_capture_attempts_settings_after_root_failure()
    test_startup_repairs_existing_runtime_artifact_acls_before_access()
    test_preserved_settings_file_has_direct_wix_acl_entries()
    test_acl_contract_repair_preserves_deny_rules()
    test_atomic_windows_contract_applies_acl_to_temporary_and_replaced_files()
    test_lifecycle_uses_shared_support_modules()
    test_lifecycle_verifies_running_service_process_owner()
    test_lifecycle_attempts_post_uninstall_cleanup_after_uninstall_failure()
    test_lifecycle_cli_failure_diagnostics_are_bounded()
    test_bounded_text_accepts_empty_files()
    test_failure_diagnostics_preserve_the_original_error_when_service_is_missing()
    test_failure_diagnostics_cover_every_cleanup_boundary()
    test_service_logs_are_captured_before_failure_cleanup()
    test_service_log_capture_is_bounded_best_effort_and_privacy_safe()
    test_service_log_capture_preserves_primary_error_on_setup_failure()
    test_service_log_capture_behavior_with_temporary_files()
    test_elevated_source_artifact_producer_matches_packaged_consumer()
    test_ci_uses_reusable_elevated_result_or_successful_skip()
    test_elevated_source_artifact_contains_complete_msi_stage()
    test_direct_scm_lifecycle_contract_is_separate_and_condition_based()
    test_direct_scm_service_executable_is_staged_for_both_artifact_modes()
    test_direct_scm_process_timeout_covers_two_registrar_waits()
    test_direct_scm_probes_standard_user_after_runtime_artifacts_and_cleans_up()
    test_direct_scm_standard_user_name_fits_security_helper_contract()
    test_installed_cli_contract_accepts_empty_stderr_without_relaxing_other_parameters()
    test_msi_acl_replacement_uses_installed_atomic_config_writer_and_exact_cli_contract()
    print("lifecycle contract: OK")


if __name__ == "__main__":
    main()
