"""Static contract checks for Windows lifecycle test-support modules."""

from pathlib import Path


ROOT = Path(__file__).parent / "TestSupport"


def read_module(name: str) -> str:
    path = ROOT / name
    assert path.is_file(), f"missing test-support module: {path}"
    return path.read_text(encoding="utf-8")


def test_required_modules_exist() -> None:
    for name in (
        "Wait.psm1",
        "Scm.psm1",
        "Acl.psm1",
        "Diagnostics.psm1",
        "Cleanup.psm1",
    ):
        read_module(name)


def test_wait_module_is_deadline_and_condition_based() -> None:
    module = read_module("Wait.psm1")
    assert "function Wait-Condition" in module
    assert "AddSeconds" in module
    assert "DateTime]::UtcNow" in module
    assert "Start-Sleep" in module
    assert "function Wait-ConditionStable" in module
    assert "Stopwatch]::GetTimestamp()" in module
    assert "StabilitySeconds" in module
    assert "Export-ModuleMember -Function Wait-Condition, Wait-ConditionStable" in module


def test_scm_module_proves_runtime_owner_and_bounded_state_waits() -> None:
    module = read_module("Scm.psm1")
    assert "function Get-ServiceProcessOwner" in module
    assert "Win32_Process" in module
    assert "Invoke-CimMethod -MethodName GetOwner" in module
    assert "NT AUTHORITY\\SYSTEM" in module
    assert "Wait-Condition" in module
    assert "function Assert-ServiceRunsAsSystem" in module
    assert "function Wait-ServiceState" in module
    assert "function Wait-ServiceRemoved" in module


def test_acl_module_normalizes_identity_and_inheritance_metadata() -> None:
    module = read_module("Acl.psm1")
    assert "function Get-NormalizedAcl" in module
    assert "Get-Acl" in module
    assert "IdentityReference" in module
    assert "FileSystemRights" in module
    assert "InheritanceFlags" in module
    assert "PropagationFlags" in module
    assert "function Assert-AclPrincipal" in module


def test_diagnostics_are_allowlisted_and_size_bounded() -> None:
    module = read_module("Diagnostics.psm1")
    assert "function Get-BoundedText" in module
    assert "MaxCharacters" in module
    assert "ValidateRange(1, 65536)" in module
    assert "function Write-BoundedDiagnostics" in module
    assert "MaxBytes" in module
    assert "ConvertTo-Json" in module
    assert "Get-ChildItem Env:" not in module
    assert "GetEnvironmentVariables" not in module


def test_cleanup_runs_every_action_and_reports_failures() -> None:
    module = read_module("Cleanup.psm1")
    assert "function Invoke-FailureSafeCleanup" in module
    assert "foreach ($action in $Actions)" in module
    assert "try" in module and "catch" in module
    assert "cleanup failed" in module


def main() -> None:
    test_required_modules_exist()
    test_wait_module_is_deadline_and_condition_based()
    test_scm_module_proves_runtime_owner_and_bounded_state_waits()
    test_acl_module_normalizes_identity_and_inheritance_metadata()
    test_diagnostics_are_allowlisted_and_size_bounded()
    test_cleanup_runs_every_action_and_reports_failures()
    print("test-support contract: OK")


if __name__ == "__main__":
    main()
