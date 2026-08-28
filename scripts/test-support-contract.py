"""Static contract checks for Windows lifecycle test-support modules."""

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parent / "TestSupport"
LIFECYCLE = ROOT.parent / "test-msi-lifecycle.ps1"
DIRECT_SCM = ROOT.parent / "test-direct-scm-lifecycle.ps1"
WORKFLOW = ROOT.parent.parent / ".github" / "workflows" / "elevated-windows.yml"
_ACL_DIAGNOSTIC_FIELDS = (
    "path_class",
    "sid",
    "access_type",
    "rights_mask",
    "inheritance_flags",
    "propagation_flags",
    "inherited",
)
_ACL_DIAGNOSTIC_FORBIDDEN_FIELDS = (
    "account_name",
    "identity",
    "path",
    "exception",
    "error",
    "message",
    "contents",
    "secret",
    "token",
)


def read_module(name: str) -> str:
    path = ROOT / name
    assert path.is_file(), f"missing test-support module: {path}"
    return path.read_text(encoding="utf-8")


def _acl_diagnostic_projection(source: str) -> tuple[tuple[str, ...], dict[str, str]]:
    start = source.index("function Get-AclDiagnostic")
    projection_start = source.index("[ordered]@{", start) + len("[ordered]@{")
    depth = 1
    end = projection_start
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    projection = source[projection_start : end - 1]
    assignments = re.findall(
        r"(?m)^\s*(?P<key>[A-Za-z_]\w*)\s*=\s*(?P<value>[^\r\n]+?)\s*$",
        projection,
    )
    assert assignments, "ACL diagnostic projection must contain ordered assignments"
    keys = tuple(key for key, _ in assignments)
    values = dict(assignments)
    assert len(keys) == len(values), "ACL diagnostic projection contains duplicate keys"
    return keys, values


def _assert_exact_acl_diagnostic_schema(source: str) -> None:
    keys, values = _acl_diagnostic_projection(source)
    assert keys == _ACL_DIAGNOSTIC_FIELDS
    assert values == {
        "path_class": "$PathClass",
        "sid": "ConvertTo-SecurityIdentifier -IdentityReference $_.IdentityReference",
        "access_type": "$_.AccessControlType.ToString()",
        "rights_mask": "[int]$_.FileSystemRights",
        "inheritance_flags": "$_.InheritanceFlags.ToString()",
        "propagation_flags": "$_.PropagationFlags.ToString()",
        "inherited": "[bool]$_.IsInherited",
    }


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


def test_acl_diagnostic_projection_is_exact_and_bounded() -> None:
    module = read_module("Acl.psm1")
    diagnostic_end = module.index("function Get-AclContract")
    diagnostic = module[module.index("function Get-AclDiagnostic") : diagnostic_end]
    _assert_exact_acl_diagnostic_schema(diagnostic)
    assert "ValidateSet('root', 'settings')" in diagnostic
    assert "[string]$PathClass" in diagnostic
    assert "[int]$MaxRules = 64" in diagnostic
    assert "Select-Object -First $MaxRules" in diagnostic
    assert "ValidateRange(1, 64)" in diagnostic
    assert "function Write-AclDiagnostic" in module
    writer = module[module.index("function Write-AclDiagnostic") : diagnostic_end]
    assert "MaxBytes" in writer
    assert "ConvertTo-Json -Compress" in writer
    assert "UTF8" in writer
    assert "WriteAllText" in writer


def test_acl_diagnostic_projection_rejects_privacy_schema_mutations() -> None:
    module = read_module("Acl.psm1")
    diagnostic_end = module.index("function Get-AclContract")
    diagnostic = module[module.index("function Get-AclDiagnostic") : diagnostic_end]
    for forbidden in _ACL_DIAGNOSTIC_FORBIDDEN_FIELDS:
        mutation = diagnostic.replace(
            "            path_class = $PathClass\n",
            f"            {forbidden} = 'forbidden'\n            path_class = $PathClass\n",
            1,
        )
        try:
            _assert_exact_acl_diagnostic_schema(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"ACL diagnostic privacy mutation was accepted: {forbidden}")


def test_acl_identity_normalization_uses_identity_reference_string_conversion() -> None:
    module = read_module("Acl.psm1")
    converter_start = module.index("function ConvertTo-SecurityIdentifier")
    converter_end = module.index("function Get-NormalizedAcl", converter_start)
    converter = module[converter_start:converter_end]
    normalized_start = module.index("function Get-NormalizedAcl")
    normalized_end = module.index("function Get-AclContract", normalized_start)
    normalized = module[normalized_start:normalized_end]

    non_sid_path = converter[converter.index("$identity = $IdentityReference.ToString()"):]
    assert "$identity = $IdentityReference.ToString()" in converter
    assert "[Security.Principal.NTAccount]$identity" in converter
    assert "Translate(\n            [Security.Principal.SecurityIdentifier]\n        ).Value" in converter
    assert "$IdentityReference.Value" not in non_sid_path
    assert "failed to translate ACL principal $identity to a SID" in converter
    assert "identity = $_.IdentityReference.ToString()" in normalized
    assert "identity = $_.IdentityReference.Value" not in normalized


def test_acl_contract_is_sid_based_and_rejects_broad_allows() -> None:
    module = read_module("Acl.psm1")
    for required in (
        "function Get-AclContract",
        "function Set-AclContract",
        "function Assert-AclContract",
        "S-1-5-18",
        "S-1-5-32-544",
        "$canonicalAllowSids",
        "$canonicalRightsMask",
        "$canonicalChildRightsMask",
        "$canonicalSelfInheritanceMask",
        "$canonicalInheritanceMask",
        "$canonicalPropagationMask",
        "$canonicalChildPropagationMask",
        "function Get-RequiredAclRule",
        "function Assert-AclRulesContract",
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
    assert "Export-ModuleMember -Function Get-NormalizedAcl, Get-AclDiagnostic, Write-AclDiagnostic, Assert-AclPrincipal, Get-AclContract, Set-AclContract, Assert-AclRulesContract, Assert-AclContract" in module
    assert "Ensure-AclContract" not in module
    assert "$matches =" not in module
    assert "[CmdletBinding(SupportsShouldProcess = $true)]" in module
    assert "$PSCmdlet.ShouldProcess($Path" in module
    assert "[ValidateSet('Leaf', 'Container')]" in module
    assert "-PathType $PathType" in module
    assert "AddAccessRule" in module
    assert "RemoveAccessRule" in module
    assert "if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)" in module
    assert "AccessControlType]::Deny" not in module


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
    repair = module[module.index("function Set-AclContract"):module.index("function Assert-AclPrincipal")]
    assert "AccessControlType]::Allow)" in repair
    assert "-not $canonicalAllowSids.Contains($sid)" not in repair
    assert "foreach ($requiredRule in @(Get-RequiredAclRule -PathType $PathType))" in repair
    assert "AddAccessRule($rule)" in repair
    assert "RemoveAccessRule($rule)" in repair
    assert "$owner = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner" in repair
    assert "$updatedOwner -ne $owner" in module
    assert "SetOwner" not in module


def test_acl_contract_matches_observed_windows_directory_and_file_semantics() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for semantic ACL contract fixtures"
    module = ROOT / "Acl.psm1"
    probe = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-FixtureRule {
    param(
        [string]$Sid,
        [int]$RightsMask,
        [int]$InheritanceMask,
        [int]$PropagationMask,
        [bool]$Inherited,
        [string]$Type = 'Allow'
    )
    [pscustomobject]@{
        sid = $Sid
        type = $Type
        rights_mask = $RightsMask
        inheritance_mask = $InheritanceMask
        propagation_mask = $PropagationMask
        inherited = $Inherited
    }
}

$system = 'S-1-5-18'
$administrators = 'S-1-5-32-544'
$other = 'S-1-5-21-424242-424242-424242-4242'
$fullControl = 2032127
$genericAll = 268435456
$noInheritance = 0
$containerAndObject = 3
$inheritOnly = 2
$selfRules = @(
    (New-FixtureRule $system $fullControl $noInheritance $noInheritance $false),
    (New-FixtureRule $administrators $fullControl $noInheritance $noInheritance $false)
)
$childRules = @(
    (New-FixtureRule $system $genericAll $containerAndObject $inheritOnly $false),
    (New-FixtureRule $administrators $genericAll $containerAndObject $inheritOnly $false)
)
$rootRules = @($selfRules + $childRules + @(
    (New-FixtureRule $other $fullControl $noInheritance $noInheritance $false 'Deny')
))
$settingsRules = @($selfRules)
$fixtures = @{
    root = $rootRules
    settings = $settingsRules
    unauthorized = @($rootRules + (New-FixtureRule $other $fullControl $noInheritance $noInheritance $false))
    duplicate = @($rootRules + (New-FixtureRule $system $fullControl $noInheritance $noInheritance $false))
    inherited = @($rootRules + (New-FixtureRule $system $fullControl $noInheritance $noInheritance $true))
    wrong_rights = @(
        (New-FixtureRule $system 1 $noInheritance $noInheritance $false),
        $selfRules[1], $childRules
    )
    wrong_inheritance = @(
        $selfRules,
        (New-FixtureRule $system $genericAll 1 $inheritOnly $false),
        $childRules[1]
    )
    wrong_propagation = @(
        $selfRules,
        (New-FixtureRule $system $genericAll $containerAndObject $noInheritance $false),
        $childRules[1]
    )
    missing = @($selfRules + $childRules[0])
}
Import-Module $env:SPOTTER_ACL_MODULE -Force
[void](Assert-AclRulesContract -Path 'root' -PathType Container -Rules $fixtures.root)
[void](Assert-AclRulesContract -Path 'settings' -PathType Leaf -Rules $fixtures.settings)
foreach ($invalid in @('unauthorized', 'duplicate', 'inherited', 'wrong_rights', 'wrong_inheritance', 'wrong_propagation', 'missing')) {
    $rejected = $false
    try {
        [void](Assert-AclRulesContract -Path $invalid -PathType Container -Rules $fixtures[$invalid])
    } catch {
        $rejected = $true
    }
    if (-not $rejected) { throw "invalid fixture was accepted: $invalid" }
}
$rejected = $false
try {
    [void](Assert-AclRulesContract -Path 'root-as-leaf' -PathType Leaf -Rules $fixtures.root)
} catch {
    $rejected = $true
}
if (-not $rejected) { throw 'directory fixture was accepted as a leaf' }
$rejected = $false
try {
    [void](Assert-AclRulesContract -Path 'settings-as-directory' -PathType Container -Rules $fixtures.settings)
} catch {
    $rejected = $true
}
if (-not $rejected) { throw 'file fixture was accepted as a directory' }
Write-Output 'semantic ACL fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_ACL_MODULE": str(module)},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "semantic ACL fixtures accepted" in result.stdout


def test_direct_scm_acl_assertion_uses_exact_normalized_contract() -> None:
    script = DIRECT_SCM.read_text(encoding="utf-8")
    start = script.index("function Assert-DirectRuntimeAcl")
    end = script.index("$identity =", start)
    assertion = script[start:end]

    assert "Assert-AclContract -Path $DataRoot -PathType Container" in assertion
    assert "Assert-AclContract -Path $artifact.Path -PathType $artifact.Type" in assertion
    assert "Assert-AclPrincipal" not in assertion
    assert "NT AUTHORITY\\SYSTEM" not in assertion
    assert "Administrators" not in assertion
    assert "-match" not in assertion


def test_acl_contract_callers_pass_declared_path_kinds_everywhere() -> None:
    for source in (DIRECT_SCM, LIFECYCLE):
        script = source.read_text(encoding="utf-8")
        for match in re.finditer(r"(?:Get|Set|Assert)-AclContract\s+-Path[^\r\n]*", script):
            assert "-PathType" in match.group(0), match.group(0)
    assert "[void](Acl\\Assert-AclContract -Path $dataRoot -PathType Container)" in LIFECYCLE.read_text(encoding="utf-8")
    assert "Acl\\Set-AclContract -Path $dataRoot -PathType Container" in LIFECYCLE.read_text(encoding="utf-8")


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
    assert "ConvertTo-SecureString" not in module
    assert "[Security.SecureString]::new()" in module
    assert "AppendChar" in module
    assert module.count("[CmdletBinding(SupportsShouldProcess = $true)]") == 2
    assert "$PSCmdlet.ShouldProcess($Name" in module
    assert "$PSCmdlet.ShouldProcess($User.Name" in module
    assert "$PSCmdlet.ShouldProcess($userProfile" in module
    assert "$profile =" not in module
    assert "foreach ($profile" not in module
    probe_start = module.index("$probe = @'")
    assert "$AccessDeniedHResult = -2147024891" not in module[:probe_start]


def test_credentialed_process_does_not_request_ignored_window_suppression() -> None:
    module = read_module("Security.psm1")
    start_info_start = module.index("$startInfo = [Diagnostics.ProcessStartInfo]::new()")
    process_start = module.index("$process = [Diagnostics.Process]::new()", start_info_start)
    start_info = module[start_info_start:process_start]
    assert "$startInfo.UserName" in start_info
    assert "$startInfo.Password" in start_info
    assert "$startInfo.CreateNoWindow" not in start_info


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
        "Acl\\Set-AclContract",
        "Assert-AclContract",
        "Assert-ChildIsStandardUser",
        "state.toml",
        "operations.jsonl",
        "spotter-svc.log",
    ):
        assert required in script, f"MSI lifecycle script missing {required!r}"
    validate_position = script.index("Assert-AclContract -Path $dataRoot")
    repair_position = script.index("Acl\\Set-AclContract")
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

    _validate_wix_permission_targets(product)
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
    test_acl_diagnostic_projection_is_exact_and_bounded()
    test_acl_diagnostic_projection_rejects_privacy_schema_mutations()
    test_acl_identity_normalization_uses_identity_reference_string_conversion()
    test_acl_contract_is_sid_based_and_rejects_broad_allows()
    test_acl_fixture_rejects_arbitrary_extra_allow_but_preserves_deny_rules()
    test_acl_contract_matches_observed_windows_directory_and_file_semantics()
    test_direct_scm_acl_assertion_uses_exact_normalized_contract()
    test_acl_contract_callers_pass_declared_path_kinds_everywhere()
    test_elevated_result_requires_msi_and_direct_scm_success_in_both_modes()
    test_security_module_proves_standard_user_token_and_access_denials()
    test_credentialed_process_does_not_request_ignored_window_suppression()
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
