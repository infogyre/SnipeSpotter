"""Static contract checks for Windows lifecycle test-support modules."""

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).parent / "TestSupport"
LIFECYCLE = ROOT.parent / "test-msi-lifecycle.ps1"
DIRECT_SCM = ROOT.parent / "test-direct-scm-lifecycle.ps1"
WORKFLOW = ROOT.parent.parent / ".github" / "workflows" / "elevated-windows.yml"


def read_module(name: str) -> str:
    path = ROOT / name
    assert path.is_file(), f"missing test-support module: {path}"
    return path.read_text(encoding="utf-8")


def test_required_modules_exist() -> None:
    for name in (
        "Wait.psm1",
        "Scm.psm1",
        "Acl.psm1",
        "Security.psm1",
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


def test_acl_contract_is_sid_based_and_rejects_broad_allows() -> None:
    module = read_module("Acl.psm1")
    for required in (
        "function Get-AclContract",
        "function Ensure-AclContract",
        "function Assert-AclContract",
        "S-1-5-18",
        "S-1-5-32-544",
        "$canonicalAllowSids",
        "$canonicalRightsMask",
        "$canonicalInheritanceMask",
        "$canonicalPropagationMask",
        "AccessControlType]::Allow",
        "SetAccessRuleProtection",
        "ContainerInherit",
        "ObjectInherit",
        "PropagationFlags",
        "rights_mask",
        "inheritance_mask",
        "propagation_mask",
        "ConvertTo-SecurityIdentifier",
    ):
        assert required in module, f"ACL contract is missing {required!r}"
    assert "NT AUTHORITY\\SYSTEM" not in module
    assert "\\Administrators" not in module
    assert "Users" not in module
    assert "Everyone" not in module
    assert "Authenticated Users" not in module
    assert "Export-ModuleMember -Function Get-NormalizedAcl, Assert-AclPrincipal, Get-AclContract, Ensure-AclContract, Assert-AclContract" in module


def test_acl_fixture_rejects_arbitrary_extra_allow_but_preserves_deny_rules() -> None:
    module = read_module("Acl.psm1")
    fixture = (
        {"sid": "S-1-5-18", "type": "Allow"},
        {"sid": "S-1-5-32-544", "type": "Allow"},
        {"sid": "S-1-5-21-424242-424242-424242-4242", "type": "Allow"},
        {"sid": "S-1-5-21-424242-424242-424242-4242", "type": "Deny"},
    )
    allow_sids = {
        rule["sid"] for rule in fixture if rule["type"] == "Allow"
    }
    canonical_sids = {"S-1-5-18", "S-1-5-32-544"}
    extra_allow_sids = allow_sids - canonical_sids

    assert extra_allow_sids == {"S-1-5-21-424242-424242-424242-4242"}
    repair = module[module.index("function Ensure-AclContract"):module.index("function Assert-AclPrincipal")]
    assert "-not $canonicalAllowSids.Contains($sid)" in repair
    assert repair.count("AccessControlType]::Allow") == repair.count("RemoveAccessRule") + 1
    assert repair.count("RemoveAccessRule") == 2
    assert "$owner = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner" in repair
    assert "$updatedOwner -ne $owner" in module
    assert "SetOwner" not in module


def test_direct_scm_acl_assertion_uses_exact_normalized_contract() -> None:
    script = DIRECT_SCM.read_text(encoding="utf-8")
    start = script.index("function Assert-DirectRuntimeAcl")
    end = script.index("$identity =", start)
    assertion = script[start:end]

    assert "Assert-AclContract -Path $DataRoot" in assertion
    assert "Assert-AclPrincipal" not in assertion
    assert "NT AUTHORITY\\SYSTEM" not in assertion
    assert "Administrators" not in assertion
    assert "-match" not in assertion


def test_elevated_result_requires_msi_and_direct_scm_success_in_both_modes() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    result_start = workflow.index("- name: Publish lifecycle result")
    result_end = workflow.index("- name: Upload MSI lifecycle logs", result_start)
    result = workflow[result_start:result_end]

    assert "id: direct_scm" in workflow
    assert "MSI_OUTCOME: ${{ steps.validate.outcome }}" in result
    assert "DIRECT_SCM_OUTCOME: ${{ steps.direct_scm.outcome }}" in result
    assert "$msiPassed = $env:MSI_OUTCOME -eq 'success'" in result
    assert "$directScmPassed = $env:DIRECT_SCM_OUTCOME -eq 'success'" in result
    assert "$result = if ($msiPassed -and $directScmPassed)" in result
    assert '"lifecycle_result=$result"' in result
    assert '"lifecycle_result=$env:VALIDATE_OUTCOME"' not in result

    download_start = workflow.index("- name: Download packaged MSI")
    source_start = workflow.index("- name: Build source MSI")
    validate_start = workflow.index("- name: Validate MSI lifecycle")
    direct_start = workflow.index("- name: Validate direct CLI SCM lifecycle")
    result_start = workflow.index("- name: Publish lifecycle result")
    packaged_mode = workflow[download_start:source_start]
    source_mode = workflow[source_start:validate_start]
    assert "if: ${{ !inputs.source_artifact }}" in packaged_mode
    assert "if: ${{ inputs.source_artifact }}" in source_mode
    assert download_start < source_start < validate_start < direct_start < result_start
    assert "steps.validate.outcome" in result
    assert "steps.direct_scm.outcome" in result


def test_security_module_proves_standard_user_token_and_access_denials() -> None:
    module = read_module("Security.psm1")
    for required in (
        "function New-TemporaryStandardUser",
        "function Remove-TemporaryStandardUser",
        "function Invoke-AsStandardUser",
        "function Get-TokenProof",
        "function Assert-StandardUserToken",
        "function Assert-ChildIsStandardUser",
        "WindowsIdentity",
        "WindowsPrincipal",
        "Administrator",
        "S-1-5-18",
        "AccessDenied",
        "UnauthorizedAccessException",
        "read_denied",
        "write_denied",
        "finally",
    ):
        assert required in module, f"security module missing {required!r}"
    assert "Get-Content -Raw" not in module
    assert "Get-ChildItem Env:" not in module
    assert "PathType = 'Leaf'" in module
    assert "ValidateSet('Leaf', 'Container')" in module
    assert "identity-class=standard-user" in module
    assert "access=read-write-denied" in module


def test_diagnostics_are_allowlisted_and_size_bounded() -> None:
    module = read_module("Diagnostics.psm1")
    assert "function Get-BoundedText" in module
    assert "MaxCharacters" in module
    assert "ValidateRange(1, 65536)" in module
    assert "function Write-BoundedDiagnostic" in module
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


def test_cleanup_persists_bounded_failure_diagnostics() -> None:
    module = read_module("Cleanup.psm1")
    for required in (
        "DiagnosticPath",
        "MaxDiagnosticBytes",
        "ConvertTo-Json",
        "WriteAllText",
        "Substring",
    ):
        assert required in module, f"cleanup module missing {required!r}"


def test_lifecycle_applies_acl_contract_and_covers_runtime_artifacts() -> None:
    script = LIFECYCLE.read_text(encoding="utf-8")
    for required in (
        "Ensure-AclContract",
        "Assert-AclContract",
        "Assert-ChildIsStandardUser",
        "state.toml",
        "operations.jsonl",
        "spotter-svc.log",
    ):
        assert required in script, f"MSI lifecycle script missing {required!r}"
    validate_position = script.index("Assert-AclContract -Path $dataRoot")
    repair_position = script.index("Ensure-AclContract")
    assert validate_position < repair_position
    assert "Get-TokenProof" not in script
    assert "-PathType $artifact.Type" in script
    assert "Type = 'Leaf'" in script
    assert "Type = 'Container'" in script


def test_security_probe_is_required_for_direct_runtime_artifacts() -> None:
    script = DIRECT_SCM.read_text(encoding="utf-8")
    assert "Import-Module (Join-Path $testSupportRoot 'Security.psm1')" in script
    artifacts = script.index("$runtimeArtifacts = @(")
    standard_user = script.index("New-TemporaryStandardUser", artifacts)
    probe = script.index("Assert-StandardUserCannotReadWrite", standard_user)
    assert artifacts < standard_user < probe
    assert "Assert-ChildIsStandardUser -Result $probeResult" in script
    assert "finally" in script[standard_user:]
    assert "Remove-TemporaryStandardUser -User $standardUser" in script


def test_msi_uses_cli_writer_and_checks_stream_contract_without_secret_output() -> None:
    script = LIFECYCLE.read_text(encoding="utf-8")
    assert "Add-Content -LiteralPath $settingsPath -Value \"`n$replacementMarker\"" not in script
    assert "config', 'set', 'polling.interval_hours'" in script
    assert "Assert-InstalledCliContract" in script
    assert "ExpectedStdout 'updated polling.interval_hours'" in script
    assert "ExpectedStderr ''" in script
    assert "settings committed by CLI" in script
    assert "lifecycle-preservation-marker" in script
    assert "set-token" not in script[script.index("settings committed by CLI"):]


def test_windows_acl_inspection_imports_are_test_support_gated() -> None:
    windows_acl = (ROOT.parent.parent / "spotter-svc" / "src" / "windows_acl.rs").read_text(encoding="utf-8")
    import_start = windows_acl.index('#[cfg(feature = "test-support")]')
    import_end = windows_acl.index("/// The non-inherited data contract", import_start)
    inspection_imports = windows_acl[import_start:import_end]
    for symbol in (
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        "GetNamedSecurityInfoW",
        "PWSTR",
    ):
        assert symbol in inspection_imports, f"inspection import is not feature-gated: {symbol}"
    assert "#[cfg(all(test, feature = \"test-support\"))]" in windows_acl


_WIX_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
_UTIL_PERMISSION_TAG = "{http://wixtoolset.org/schemas/v4/wxs/util}PermissionEx"
_CANONICAL_PERMISSION_RULES = tuple(
    sorted(
        tuple(sorted(attributes.items()))
        for attributes in (
            {"User": "SYSTEM", "GenericAll": "yes", "Inheritable": "no"},
            {"User": "Administrators", "GenericAll": "yes", "Inheritable": "no"},
        )
    )
)
_BROAD_PRINCIPALS = {"Everyone", "Users", "Authenticated Users", "Guests"}


def _local_wix_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _direct_wix_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if _local_wix_name(child.tag) == name]


def _permission_rules(element: ET.Element) -> tuple[tuple[tuple[str, str], ...], ...]:
    return tuple(
        sorted(
            tuple(sorted(permission.attrib.items()))
            for permission in _direct_wix_children(element, "PermissionEx")
        )
    )


def _validate_wix_permission_targets(product: str) -> None:
    root = ET.fromstring(product)
    assert root.tag == f"{{{_WIX_NAMESPACE}}}Wix"

    for element in root.iter():
        assert not any(_local_wix_name(name) == "Sddl" for name in element.attrib)

    permission_elements = [
        element
        for element in root.iter()
        if _local_wix_name(element.tag) == "PermissionEx"
    ]
    assert all(element.tag == _UTIL_PERMISSION_TAG for element in permission_elements)
    assert all(
        element.attrib.get("User") not in _BROAD_PRINCIPALS
        for element in permission_elements
    )

    data_directories = [
        element
        for element in root.iter()
        if _local_wix_name(element.tag) == "Directory"
        and element.attrib.get("Id") == "DataFolder"
    ]
    assert len(data_directories) == 1

    data_components = [
        element
        for element in root.iter()
        if _local_wix_name(element.tag) == "Component"
        and element.attrib.get("Directory") == "DataFolder"
    ]
    assert len(data_components) == 1
    data_component = data_components[0]
    create_folders = _direct_wix_children(data_component, "CreateFolder")
    assert len(create_folders) == 1
    data_target = create_folders[0]
    assert _permission_rules(data_target) == _CANONICAL_PERMISSION_RULES

    settings_files = [
        element
        for element in _direct_wix_children(data_component, "File")
        if element.attrib.get("Id") == "SettingsTemplate"
    ]
    assert len(settings_files) == 1
    settings_target = settings_files[0]
    assert settings_target.attrib.get("Name") == "settings.toml"
    assert _permission_rules(settings_target) == _CANONICAL_PERMISSION_RULES

    expected_permission_ids = {
        id(permission)
        for target in (data_target, settings_target)
        for permission in _direct_wix_children(target, "PermissionEx")
    }
    assert {id(permission) for permission in permission_elements} == expected_permission_ids


def test_wix_permission_targets_are_structural_and_per_target() -> None:
    root = LIFECYCLE.parent.parent
    product = (root / "installer" / "Product.wxs").read_text(encoding="utf-8")
    _validate_wix_permission_targets(product)

    canonical_permission = (
        '          <util:PermissionEx User="SYSTEM" GenericAll="yes" Inheritable="no" />\n'
    )
    extra = product.replace(
        "        </CreateFolder>",
        f"{canonical_permission}        </CreateFolder>",
        1,
    )
    misplaced = product.replace(
        '          <util:PermissionEx User="Administrators" GenericAll="yes" Inheritable="no" />\n'
        "        </CreateFolder>",
        "        </CreateFolder>",
        1,
    ).replace(
        '          <File Id="ServiceExe" Source="$(var.StageDir)\\spotter-svc.exe" KeyPath="yes" />',
        '          <File Id="ServiceExe" Source="$(var.StageDir)\\spotter-svc.exe" KeyPath="yes">\n'
        '            <util:PermissionEx User="Administrators" GenericAll="yes" Inheritable="no" />\n'
        "          </File>",
        1,
    )
    broad = product.replace('User="Administrators"', 'User="Everyone"', 1)

    for label, fixture in (("extra", extra), ("misplaced", misplaced), ("broad", broad)):
        try:
            _validate_wix_permission_targets(fixture)
        except AssertionError:
            continue
        raise AssertionError(f"{label} WiX permission fixture was accepted")


def test_wix_authors_protected_data_acl_or_calls_the_production_acl_path() -> None:
    root = LIFECYCLE.parent.parent
    product = (root / "installer" / "Product.wxs").read_text(encoding="utf-8")
    service = (root / "spotter-svc" / "src" / "service.rs").read_text(encoding="utf-8")
    windows_acl = (root / "spotter-svc" / "src" / "windows_acl.rs").read_text(encoding="utf-8")

    assert (
        '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" '
        'xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util">'
    ) in product
    for forbidden in (
        'User="Everyone"',
        'User="Users"',
        'User="Authenticated Users"',
        'User="Guests"',
        'Sddl=',
    ):
        assert forbidden not in product

    assert 'pub const DATA_ACL_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";' in windows_acl
    assert "PROTECTED_DACL_SECURITY_INFORMATION" in windows_acl
    assert "crate::windows_acl::apply_acl_contract(&root)" in service
    assert "apply_data_acl_contract" not in service


def main() -> None:
    test_required_modules_exist()
    test_wait_module_is_deadline_and_condition_based()
    test_scm_module_proves_runtime_owner_and_bounded_state_waits()
    test_acl_module_normalizes_identity_and_inheritance_metadata()
    test_acl_contract_is_sid_based_and_rejects_broad_allows()
    test_acl_fixture_rejects_arbitrary_extra_allow_but_preserves_deny_rules()
    test_direct_scm_acl_assertion_uses_exact_normalized_contract()
    test_elevated_result_requires_msi_and_direct_scm_success_in_both_modes()
    test_security_module_proves_standard_user_token_and_access_denials()
    test_diagnostics_are_allowlisted_and_size_bounded()
    test_cleanup_runs_every_action_and_reports_failures()
    test_cleanup_persists_bounded_failure_diagnostics()
    test_lifecycle_applies_acl_contract_and_covers_runtime_artifacts()
    test_security_probe_is_required_for_direct_runtime_artifacts()
    test_msi_uses_cli_writer_and_checks_stream_contract_without_secret_output()
    test_windows_acl_inspection_imports_are_test_support_gated()
    test_wix_permission_targets_are_structural_and_per_target()
    test_wix_authors_protected_data_acl_or_calls_the_production_acl_path()
    print("test-support contract: OK")


if __name__ == "__main__":
    main()
