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
_CREDENTIAL_LAUNCH_DIAGNOSTIC_FIELDS = (
    "launch_stage",
    "failure_kind",
    "failed_field",
    "has_username",
    "has_domain",
    "has_secure_password",
    "use_shell_execute",
    "redirects",
    "has_working_directory",
    "load_user_profile",
    "argument_count",
    "executable_class",
    "native_error_code",
    "hresult",
    "native_probe",
)
_CREDENTIAL_LAUNCH_DIAGNOSTIC_FORBIDDEN_FIELDS = (
    "username",
    "domain",
    "password",
    "arguments",
    "path",
    "file_path",
    "environment",
    "token",
    "exception",
    "exception_class",
    "message",
)
_CREDENTIAL_LAUNCH_PROBE_FIELDS = (
    "case",
    "success",
    "native_error",
    "length_bucket",
)
_CREDENTIAL_LAUNCH_PROBE_CASES = (
    "short_null_application",
    "long_null_application",
    "short_explicit_application",
)
_CREDENTIAL_LAUNCH_PROBE_LENGTH_BUCKETS = (
    "short",
    "over_1024",
)
_CREDENTIAL_LAUNCH_PROBE_FORBIDDEN_FIELDS = (
    "username",
    "domain",
    "password",
    "path",
    "file_path",
    "command",
    "command_line",
    "payload",
    "environment",
    "exception",
    "message",
    "handle",
)
_CREDENTIAL_LAUNCH_PROBE_UNAVAILABLE = "probe_unavailable"


def read_module(name: str) -> str:
    path = ROOT / name
    assert path.is_file(), f"missing test-support module: {path}"
    return path.read_text(encoding="utf-8")


def _ordered_projection(source: str, function_name: str) -> tuple[tuple[str, ...], dict[str, str]]:
    start = source.index(f"function {function_name}")
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
    assert assignments, f"{function_name} projection must contain ordered assignments"
    keys = tuple(key for key, _ in assignments)
    values = dict(assignments)
    assert len(keys) == len(values), f"{function_name} projection contains duplicate keys"
    return keys, values


def _acl_diagnostic_projection(source: str) -> tuple[tuple[str, ...], dict[str, str]]:
    return _ordered_projection(source, "Get-AclDiagnostic")


def _credential_launch_diagnostic_projection(
    source: str,
) -> tuple[tuple[str, ...], dict[str, str]]:
    return _ordered_projection(source, "Get-CredentialLaunchDiagnostic")


_CREDENTIAL_LAUNCH_TUPLE_RE = re.compile(
    r"Get-CredentialLaunchDiagnostic\s+"
    r"-LaunchStage\s+'(?P<launch_stage>[^']+)'\s+"
    r"-FailureKind\s+'(?P<failure_kind>[^']+)'\s+"
    r"-FailedField\s+(?P<failed_field>\$[A-Za-z_]\w*)"
)
_CREDENTIAL_LAUNCH_FAILURES = (
    (
        "$startInfo.FileName = $FilePath",
        "file_name",
        ("configuration", "configuration", "file_name"),
    ),
    (
        "$process.StartInfo = $startInfo",
        "process_start_info",
        ("configuration", "configuration", "process_start_info"),
    ),
    (
        "$process.Start()",
        "process_start",
        ("native_start", "native", "process_start"),
    ),
)


def _powershell_braced_block_end(source: str, opening_brace: int) -> int:
    depth = 0
    quote: str | None = None
    index = opening_brace
    while index < len(source):
        character = source[index]
        if quote == "'":
            if character == "'":
                if index + 1 < len(source) and source[index + 1] == "'":
                    index += 2
                    continue
                quote = None
        elif quote == '"':
            if character == "`":
                index += 2
                continue
            if character == '"':
                if index + 1 < len(source) and source[index + 1] == '"':
                    index += 2
                    continue
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == "#":
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline
            continue
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise AssertionError("unclosed PowerShell brace")


def _powershell_catch_blocks(source: str) -> tuple[str, ...]:
    blocks = []
    for match in re.finditer(r"\bcatch\s*\{", source):
        end = _powershell_braced_block_end(source, match.end() - 1)
        blocks.append(source[match.start() : end])
    return tuple(blocks)


def _powershell_try_catch_spans(source: str) -> tuple[tuple[int, int, int, int], ...]:
    spans = []
    for match in re.finditer(r"\btry\s*\{", source):
        try_end = _powershell_braced_block_end(source, match.end() - 1)
        catch_match = re.match(r"\s*(catch)\s*\{", source[try_end:])
        if catch_match is None:
            continue
        catch_start = try_end + catch_match.start(1)
        catch_end = _powershell_braced_block_end(
            source, try_end + catch_match.end() - 1
        )
        spans.append((match.start(), try_end, catch_start, catch_end))
    return tuple(spans)


def _credential_launch_catch_spans(source: str) -> tuple[tuple[int, int], ...]:
    invoke_start = source.index("function Invoke-AsStandardUser")
    invoke_end = source.index("function Assert-StandardUserCannotReadWrite")
    invoke = source[invoke_start:invoke_end]
    pairs = _powershell_try_catch_spans(invoke)
    spans = []
    for marker, failed_field, _ in _CREDENTIAL_LAUNCH_FAILURES:
        matches = [
            (catch_start, catch_end)
            for try_start, try_end, catch_start, catch_end in pairs
            if marker in invoke[try_start:try_end]
            and f"$failedField = '{failed_field}'" in invoke[try_start:try_end]
        ]
        assert len(matches) == 1, f"missing unique launch catch for {marker!r}"
        catch_start, catch_end = matches[0]
        spans.append((invoke_start + catch_start, invoke_start + catch_end))
    return tuple(spans)


def _credential_launch_failure_tuples(source: str) -> tuple[tuple[str, str, str], ...]:
    tuples = []
    for (catch_start, catch_end), (_, failed_field, _) in zip(
        _credential_launch_catch_spans(source), _CREDENTIAL_LAUNCH_FAILURES
    ):
        catch_block = source[catch_start:catch_end]
        matches = tuple(_CREDENTIAL_LAUNCH_TUPLE_RE.finditer(catch_block))
        assert len(matches) == 1
        match = matches[0]
        tuples.append((match["launch_stage"], match["failure_kind"], failed_field))
    return tuple(tuples)


def _assert_exact_credential_launch_failure_tuples(source: str) -> None:
    spans = _credential_launch_catch_spans(source)
    assert all(
        "-FailedField $failedField" in source[start:end] for start, end in spans
    )
    actual = _credential_launch_failure_tuples(source)
    expected = tuple(expected for _, _, expected in _CREDENTIAL_LAUNCH_FAILURES)
    assert actual == expected


def _mutate_credential_launch_catch(
    source: str,
    catch_index: int,
    replacement: tuple[str, str, str],
) -> str:
    catch_start, catch_end = _credential_launch_catch_spans(source)[catch_index]
    catch_block = source[catch_start:catch_end]
    match = _CREDENTIAL_LAUNCH_TUPLE_RE.search(catch_block)
    assert match is not None
    replacement_text = (
        "Get-CredentialLaunchDiagnostic "
        f"-LaunchStage '{replacement[0]}' "
        f"-FailureKind '{replacement[1]}' "
        f"-FailedField {replacement[2]}"
    )
    catch_start, catch_end = _credential_launch_catch_spans(source)[catch_index]
    mutated_block = (
        source[catch_start : catch_start + match.start()]
        + replacement_text
        + source[catch_start + match.end() : catch_end]
    )
    return source[:catch_start] + mutated_block + source[catch_end:]


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


def test_credentialed_launch_diagnostic_schema_is_exact_and_bounded() -> None:
    module = read_module("Security.psm1")
    projection = module[
        module.index("function Get-CredentialLaunchDiagnostic") : module.index(
            "if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))"
        )
    ]
    keys, values = _credential_launch_diagnostic_projection(projection)
    assert keys == _CREDENTIAL_LAUNCH_DIAGNOSTIC_FIELDS
    assert values == {
        "launch_stage": "$LaunchStage",
        "failure_kind": "$FailureKind",
        "failed_field": "$FailedField",
        "has_username": "-not [string]::IsNullOrEmpty($StartInfo.UserName)",
        "has_domain": "-not [string]::IsNullOrEmpty($StartInfo.Domain)",
        "has_secure_password": "$null -ne $StartInfo.Password",
        "use_shell_execute": "[bool]$StartInfo.UseShellExecute",
        "redirects": "$redirects",
        "has_working_directory": "-not [string]::IsNullOrEmpty($StartInfo.WorkingDirectory)",
        "load_user_profile": "[bool]$StartInfo.LoadUserProfile",
        "argument_count": "$ArgumentCount",
        "executable_class": "$executableClass",
        "native_error_code": "$nativeErrorCode",
        "hresult": "$hresult",
        "native_probe": "$NativeProbe",
    }
    assert "if ($bytes.Length -gt 8192)" in projection
    assert "ConvertTo-Json -Compress -Depth 3" in projection
    assert "[Text.Encoding]::UTF8" in projection
    assert "New-Object byte[]" not in projection
    assert "Exception.Message" not in projection
    assert "InnerException" in projection
    assert "native_probe = $NativeProbe" in projection
    assert "if ($LaunchStage -ne 'native_start')" in projection
    assert ".Remove('native_probe')" in projection


def test_credentialed_launch_diagnostic_schema_rejects_privacy_mutations() -> None:
    module = read_module("Security.psm1")
    projection = module[
        module.index("function Get-CredentialLaunchDiagnostic") : module.index(
            "if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))"
        )
    ]
    mutation = projection.replace(
        "launch_stage = $LaunchStage\n",
        "credential_value = 'forbidden'\n        launch_stage = $LaunchStage\n",
        1,
    )
    keys, _ = _credential_launch_diagnostic_projection(mutation)
    assert keys != _CREDENTIAL_LAUNCH_DIAGNOSTIC_FIELDS
    assert not any(
        re.search(rf"(?m)^\s*{re.escape(forbidden)}\s*=", projection)
        for forbidden in _CREDENTIAL_LAUNCH_DIAGNOSTIC_FORBIDDEN_FIELDS
    )
    for sensitive_value in ("$User.Name", "$User.Domain", "$FilePath", "$ArgumentList"):
        assert sensitive_value not in projection
    assert "native_probe = $User" not in projection
    assert "native_probe = @{" not in projection
    assert "ConvertTo-Json -Compress -Depth 3" in projection


def test_credentialed_launch_catches_have_exact_failure_tuples() -> None:
    module = read_module("Security.psm1")
    _assert_exact_credential_launch_failure_tuples(module)


def test_credentialed_launch_catch_tuple_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    expected = tuple(expected for _, _, expected in _CREDENTIAL_LAUNCH_FAILURES)
    mutations = []
    for index, (_, _, expected_tuple) in enumerate(_CREDENTIAL_LAUNCH_FAILURES):
        for component, replacement in enumerate(
            (
                ("native_start", expected_tuple[1], expected_tuple[2]),
                (expected_tuple[0], "native", expected_tuple[2]),
                (expected_tuple[0], expected_tuple[1], "$wrongField"),
            )
        ):
            if replacement == expected_tuple:
                continue
            mutations.append(
                (
                    f"catch {index} component {component}",
                    _mutate_credential_launch_catch(module, index, replacement),
                )
            )
    for left, right in ((0, 2), (1, 2)):
        left_tuple = _CREDENTIAL_LAUNCH_FAILURES[left][2]
        right_tuple = _CREDENTIAL_LAUNCH_FAILURES[right][2]
        mutations.append(
            (
                f"swap catches {left} and {right}",
                _mutate_credential_launch_catch(
                    _mutate_credential_launch_catch(module, left, right_tuple),
                    right,
                    left_tuple,
                ),
            )
        )
    for label, mutation in mutations:
        try:
            _assert_exact_credential_launch_failure_tuples(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"credential launch tuple mutation was accepted: {label}")
    assert _credential_launch_failure_tuples(module) == expected


def test_credentialed_launch_classifies_configuration_and_native_failures() -> None:
    module = read_module("Security.psm1")
    helper = module[
        module.index("function Get-CredentialLaunchDiagnostic") : module.index(
            "function Invoke-AsStandardUser"
        )
    ]
    invoke = module[module.index("function Invoke-AsStandardUser") : module.index("function Assert-StandardUserCannotReadWrite")]
    for required in (
        "-LaunchStage 'configuration'",
        "-LaunchStage 'native_start'",
        "-FailureKind 'configuration'",
        "-FailureKind 'native'",
        "$failedField = 'process_start'",
        "-FailedField $failedField",
        "NativeErrorCode",
        "HResult",
        "Get-CredentialLaunchDiagnostic",
        "throw \"credentialed launch failed: $diagnostic\"",
    ):
        assert required in helper or required in invoke, f"missing credential launch classification {required!r}"
    assert "Assert-ChildIsStandardUser" in module
    assert "read_denied" in module and "write_denied" in module
    assert invoke.index("$startInfo.UserName") < invoke.index("$process.StartInfo = $startInfo")
    assert invoke.index("$process.StartInfo = $startInfo") < invoke.index("$process.Start()")
    assert "CreateNoWindow" not in invoke


def _credential_launch_probe_text(source: str) -> str:
    return source[
        source.index("function Invoke-CredentialLaunchProbe") : source.index(
            "function Invoke-AsStandardUser"
        )
    ]


def _credential_launch_probe_projection(
    source: str,
) -> tuple[tuple[str, ...], dict[str, str]]:
    return _ordered_projection(_credential_launch_probe_text(source), "Invoke-CredentialLaunchProbe")


def _assert_exact_credential_launch_probe_cases(probe: str) -> None:
    expected = (
        ("short_null_application", "$shortCommand", "$null"),
        ("long_null_application", "$longCommand", "$null"),
        ("short_explicit_application", "$explicitCommand", "$commandExecutable"),
    )
    case_block_start = probe.index("$cases = @(")
    case_block_end = probe.index("\n    )", case_block_start)
    case_block = probe[case_block_start:case_block_end]
    actual = tuple(
        re.findall(
            r"Case = '([^']+)'\s*;\s*Command = (\$[A-Za-z_]\w*)\s*;\s*"
            r"ApplicationName = (\$null|\$[A-Za-z_]\w*)",
            case_block,
        )
    )
    assert actual == expected
    assert "$longCommand = $shortCommand + ('x' * 1100)" in probe
    assert "$lengthBucket = if ($command.Length -gt 1024)" in probe


def _assert_native_start_catch_saves_original_error(source: str) -> None:
    catch_start, catch_end = _credential_launch_catch_spans(source)[2]
    catch = source[catch_start:catch_end]
    assert re.search(
        r"catch\s*\{\s*\$nativeStartErrorRecord\s*=\s*\$_\s*"
        r"(?:(?!\$nativeProbe).)*?\$nativeProbe\s*=\s*'probe_unavailable'\s*"
        r"try\s*\{",
        catch,
        re.DOTALL,
    )
    assert catch.count("$nativeStartErrorRecord = $_") == 1
    assert catch.count("-ErrorRecord $nativeStartErrorRecord") == 1
    assert "-ErrorRecord $_" not in catch


def test_credentialed_native_start_catch_saves_original_error_record() -> None:
    module = read_module("Security.psm1")
    _assert_native_start_catch_saves_original_error(module)


def test_credentialed_native_start_error_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    mutations = (
        module.replace(
            "$nativeStartErrorRecord = $_",
            "$nativeStartErrorRecord = $replacementErrorRecord",
            1,
        ),
        module.replace(
            "-ErrorRecord $nativeStartErrorRecord",
            "-ErrorRecord $_",
            1,
        ),
        module.replace(
            "$nativeStartErrorRecord = $_",
            "$otherErrorRecord = $_",
            1,
        ).replace(
            "-ErrorRecord $nativeStartErrorRecord",
            "-ErrorRecord $otherErrorRecord",
            1,
        ),
    )
    for mutation in mutations:
        try:
            _assert_native_start_catch_saves_original_error(mutation)
        except AssertionError:
            continue
        raise AssertionError("native-start error-record mutation was accepted")


def _assert_native_probe_capture_contract(source: str) -> None:
    catch_start, catch_end = _credential_launch_catch_spans(source)[2]
    catch = source[catch_start:catch_end]
    assert catch.count("$nativeProbe =") == 3
    assert "Invoke-CredentialLaunchProbe -User $User" in catch
    assert "ConvertTo-CredentialLaunchProbeEvidence" in catch
    assert "probe_unavailable" in catch
    assert catch.index("$nativeStartErrorRecord = $_") < catch.index("$nativeProbe =")
    assert catch.index("$nativeProbe =") < catch.index("-NativeProbe $nativeProbe")
    assert "-NativeProbe $nativeProbe" in catch
    assert "-ErrorRecord $nativeStartErrorRecord" in catch
    assert "catch { $nativeProbe = 'probe_unavailable' }" in catch
    assert "catch { $nativeStartErrorRecord = $_" not in catch
    assert not _CREDENTIAL_LAUNCH_PROBE_OUTPUT_CHANNEL_RE.search(catch)
    invoke_start = source.index("function Invoke-AsStandardUser")
    invoke_end = source.index("function Assert-StandardUserCannotReadWrite", invoke_start)
    invoke = source[invoke_start:invoke_end]
    assert invoke.count("Invoke-CredentialLaunchProbe -User $User") == 1
    assert invoke.index("$process.Start()") < invoke.index("Invoke-CredentialLaunchProbe -User $User")


def test_credentialed_native_start_capture_preserves_probe_and_original_error() -> None:
    module = read_module("Security.psm1")
    _assert_native_probe_capture_contract(module)


def test_credentialed_native_start_capture_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    mutations = (
        module.replace(
            "$nativeProbe =",
            "$discardedProbe =",
            1,
        ),
        module.replace(
            "-NativeProbe $nativeProbe",
            "-NativeProbe $discardedProbe",
            1,
        ),
        module.replace(
            "catch { $nativeProbe = 'probe_unavailable' }",
            "catch { $nativeProbe = $_.Exception.Message }",
            1,
        ),
        module.replace(
            "-ErrorRecord $nativeStartErrorRecord",
            "-ErrorRecord $_",
            1,
        ),
    )
    for mutation in mutations:
        try:
            _assert_native_probe_capture_contract(mutation)
        except (AssertionError, ValueError):
            continue
        raise AssertionError("native-start probe capture mutation was accepted")


def _assert_credential_launch_probe_evidence_parser_contract(source: str) -> None:
    start = source.index("function ConvertTo-CredentialLaunchProbeEvidence")
    end = source.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", start)
    helper = source[start:end]
    assert "[string]$ProbeJson" in helper
    assert "ConvertFrom-Json" in helper
    assert "[Text.Encoding]::UTF8.GetBytes($ProbeJson)" in helper
    assert "if ($bytes.Length -gt 4096)" in helper
    for field in ("case", "success", "native_error", "length_bucket"):
        assert re.search(rf"(?m)^\s+{field}\s*=", helper)
    assert "-isnot [string]" in helper
    assert "-isnot [bool]" in helper
    assert "-isnot [long]" in helper
    assert "$nativeError = [int64]$record.native_error" in helper
    assert "if ($nativeError -lt 0 -or $nativeError -gt [int]::MaxValue)" in helper
    assert "short_null_application" in helper
    assert "long_null_application" in helper
    assert "short_explicit_application" in helper
    assert "$expectedLengthBucket = if ($index -eq 1)" in helper
    assert "[ordered]@{" in helper
    assert "return (, $normalized)" in helper
    assert "Exception.Message" not in helper
    for forbidden in _CREDENTIAL_LAUNCH_PROBE_FORBIDDEN_FIELDS:
        assert not re.search(rf"(?m)^\s*{re.escape(forbidden)}\s*=", helper)


def test_credential_launch_probe_evidence_parser_is_exact_and_bounded() -> None:
    module = read_module("Security.psm1")
    _assert_credential_launch_probe_evidence_parser_contract(module)


def test_credential_launch_probe_evidence_parser_enforces_int32_native_error_range() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for native error range fixtures"
    module = ROOT / "Security.psm1"
    probe = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$records = @(
    [ordered]@{
        case = 'short_null_application'
        success = $true
        native_error = 0
        length_bucket = 'short'
    },
    [ordered]@{
        case = 'long_null_application'
        success = $false
        native_error = 1
        length_bucket = 'over_1024'
    },
    [ordered]@{
        case = 'short_explicit_application'
        success = $true
        native_error = 0
        length_bucket = 'short'
    }
)
foreach ($fixture in @(
    @{ name = 'negative'; native_error = -1; success = $false; expected = 'probe_unavailable' },
    @{ name = 'zero'; native_error = 0; success = $true; expected = $null },
    @{ name = 'positive'; native_error = 1; success = $false; expected = $null },
    @{ name = 'int32_max'; native_error = [int]::MaxValue; success = $false; expected = $null },
    @{ name = 'oversized'; native_error = [int64]([int]::MaxValue + 1L); success = $false; expected = 'probe_unavailable' }
)) {
    $records[1].native_error = $fixture.native_error
    $records[1].success = $fixture.success
    $json = $records | ConvertTo-Json -Compress
    $result = & $securityModule {
        param($probeJson)
        ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $probeJson
    } $json
    if ($null -ne $fixture.expected) {
        if ($result -ne $fixture.expected) {
            throw "native error range fixture was not rejected: $($fixture.name)"
        }
        continue
    }
    if ($result.Count -ne 3) { throw "valid native error fixture changed record count: $($fixture.name)" }
    if ([bool]$result[1].success -ne [bool]$fixture.success) {
        throw "valid native error fixture changed success semantics: $($fixture.name)"
    }
    if ([int64]$result[1].native_error -ne [int64]$fixture.native_error) {
        throw "valid native error fixture changed native error: $($fixture.name)"
    }
}
Write-Output 'native error range fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", probe],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "native error range fixtures accepted" in result.stdout


def test_credential_launch_probe_evidence_parser_rejects_range_bound_mutations() -> None:
    module = read_module("Security.psm1")
    helper_start = module.index("function ConvertTo-CredentialLaunchProbeEvidence")
    helper_end = module.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", helper_start)
    helper = module[helper_start:helper_end]
    _assert_credential_launch_probe_evidence_parser_contract(module)
    for label, mutation in (
        ("lower", helper.replace(" -lt 0", "", 1)),
        ("upper", helper.replace(" -gt [int]::MaxValue", "", 1)),
    ):
        mutated_module = module[:helper_start] + mutation + module[helper_end:]
        try:
            _assert_credential_launch_probe_evidence_parser_contract(mutated_module)
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"native error range {label}-bound mutation was accepted")


def test_credential_launch_probe_evidence_parser_rejects_nested_mutations() -> None:
    module = read_module("Security.psm1")
    helper_start = module.index("function ConvertTo-CredentialLaunchProbeEvidence")
    helper_end = module.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", helper_start)
    helper = module[helper_start:helper_end]
    for mutation in (
        helper.replace(
            "case = [string]$record.case\n",
            "username = 'forbidden'\n                case = [string]$record.case\n",
            1,
        ),
        helper.replace(
            "return (, $normalized)",
            "return (, @([ordered]@{ case = $record.case; nested = @{ password = $record.native_error } }))",
            1,
        ),
        helper.replace(
            "return (, $normalized)",
            "Write-Output $ProbeJson\n    return (, $normalized)",
            1,
        ),
    ):
        try:
            _assert_credential_launch_probe_evidence_parser_contract(mutation)
        except (AssertionError, ValueError):
            continue
        raise AssertionError("credential launch probe evidence parser mutation was accepted")


def test_credential_launch_probe_evidence_capture_rejects_alternate_output_channels() -> None:
    module = read_module("Security.psm1")
    invoke_start = module.index("function Invoke-AsStandardUser")
    invoke_end = module.index("function Assert-StandardUserCannotReadWrite", invoke_start)
    invoke = module[invoke_start:invoke_end]
    for command in (
        "Write-Output",
        "Write-Host",
        "Write-Verbose",
        "Write-Debug",
        "Write-Information",
        "Write-Warning",
        "Write-Error",
        "[Console]::WriteLine",
        "[Console]::Error.WriteLine",
    ):
        mutation = invoke.replace(
            "$nativeProbe = ConvertTo-CredentialLaunchProbeEvidence -ProbeJson ([string]$probeJson)",
            f"{command} $User.Name\n            $nativeProbe = ConvertTo-CredentialLaunchProbeEvidence -ProbeJson ([string]$probeJson)",
            1,
        )
        assert mutation != invoke
        try:
            _assert_native_probe_capture_contract(module[:invoke_start] + mutation + module[invoke_end:])
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"native-start probe output-channel mutation was accepted: {command}")


def _assert_credential_launch_probe_wait_and_termination_contract(
    module: str,
) -> None:
    probe = _credential_launch_probe_text(module)
    for declaration in (
        "public const uint WAIT_OBJECT_0 = 0x00000000;",
        "public const uint WAIT_TIMEOUT = 0x00000102;",
        "public const uint WAIT_FAILED = 0xffffffff;",
        "public static extern bool TerminateProcess(",
    ):
        assert declaration in module, f"native wait contract is missing {declaration!r}"
    assert probe.count("WaitForSingleObject(") == 2
    assert (
        "$waitResult = "
        "[SnipeSpotter.CredentialLaunchNative]::WaitForSingleObject($processInfo.hProcess, 5000)"
    ) in probe
    assert (
        "$terminationWaitResult = "
        "[SnipeSpotter.CredentialLaunchNative]::WaitForSingleObject($processInfo.hProcess, 1000)"
    ) in probe
    for status in ("WAIT_OBJECT_0", "WAIT_TIMEOUT", "WAIT_FAILED"):
        assert f"::${status}" not in probe
        assert f"::{status}" in probe
    assert (
        "$terminateSucceeded = "
        "[SnipeSpotter.CredentialLaunchNative]::TerminateProcess($processInfo.hProcess, 1)"
    ) in probe
    assert (
        "$terminationWaitResult = "
        "[SnipeSpotter.CredentialLaunchNative]::WaitForSingleObject($processInfo.hProcess, 1000)"
    ) in probe
    assert "$nativeError = [int]$waitResult" in probe
    assert "$nativeError = [int]$terminationWaitResult" in probe
    for branch in (
        "if (-not $terminateSucceeded) {",
        "} elseif ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {",
        "} elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {",
    ):
        branch_start = probe.index(branch)
        branch_end = probe.index("throw ", branch_start)
        branch_body = probe[branch_start:branch_end]
        assert branch_body.count(
            "$nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()"
        ) == 1
    assert probe.index("$waitResult =") < probe.index("WAIT_TIMEOUT")
    assert probe.index("WAIT_TIMEOUT") < probe.index("TerminateProcess")
    assert probe.index("TerminateProcess") < probe.index("$terminationWaitResult =")
    assert probe.index("$terminationWaitResult =") < probe.index("$lengthBucket =")


def test_credential_launch_probe_models_bounded_wait_and_termination() -> None:
    module = read_module("Security.psm1")
    _assert_credential_launch_probe_wait_and_termination_contract(module)


def test_credential_launch_probe_wait_and_termination_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    mutations = (
        module.replace("WAIT_TIMEOUT", "WAIT_OBJECT_0", 1),
        module.replace("TerminateProcess", "CloseHandle", 1),
        module.replace("hProcess, 1", "hThread, 1", 1),
        module.replace(
            "} elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {\n"
            "                        $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()",
            "} elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {\n"
            "                        $nativeError = 1",
            1,
        ),
        module.replace(
            "hProcess, 1000)",
            "hProcess, 0)",
            1,
        ),
    )
    for mutation in mutations:
        try:
            _assert_credential_launch_probe_wait_and_termination_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError("native wait or termination mutation was accepted")


def _assert_credential_launch_probe_cleanup_contract(probe: str) -> None:
    case_start = probe.index("foreach ($case in $cases)")
    case_end = probe.index("$lengthBucket =", case_start)
    case_block = probe[case_start:case_end]
    assert case_block.count("finally {") == 1
    finally_start = case_block.index("finally {")
    cleanup = case_block[finally_start:]
    match = re.search(r"foreach \(\$handle in @\((?P<handles>.*?)\)\)", cleanup, re.DOTALL)
    assert match is not None
    handles = tuple(
        re.findall(r"(?m)^\s*(\$[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?),?\s*$", match["handles"])
    )
    assert handles == (
        "$hInputRead",
        "$hInputWrite",
        "$hOutputRead",
        "$hOutputWrite",
        "$hErrorRead",
        "$hErrorWrite",
        "$processInfo.hProcess",
        "$processInfo.hThread",
    )
    assert cleanup.count("CloseHandle($handle)") == 1
    assert cleanup.count("FreeHGlobal($commandPointer)") == 1
    assert "ZeroFreeBSTR($passwordPointer)" not in cleanup
    assert probe.count("CloseHandle($handle)") == 1
    assert probe.count("FreeHGlobal($commandPointer)") == 1
    outer_cleanup = probe[probe.index("} finally {", case_end) :]
    assert "ZeroFreeBSTR($passwordPointer)" in outer_cleanup
    assert "FreeHGlobal($commandPointer)" not in outer_cleanup


def test_credential_launch_probe_has_exact_cleanup_scopes_and_handles() -> None:
    module = read_module("Security.psm1")
    _assert_credential_launch_probe_cleanup_contract(_credential_launch_probe_text(module))


def test_credential_launch_probe_cleanup_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    expected = (
        "$hInputRead",
        "$hInputWrite",
        "$hOutputRead",
        "$hOutputWrite",
        "$hErrorRead",
        "$hErrorWrite",
        "$processInfo.hProcess",
        "$processInfo.hThread",
    )
    mutations = (
        probe.replace("                    $hErrorWrite,\n", "", 1),
        probe.replace("                    $processInfo.hProcess,\n", "                    $processInfo.hThread,\n", 1),
        probe.replace("                    $hInputRead,\n", "                    $extraHandle,\n                    $hInputRead,\n", 1),
        probe.replace(
            "ZeroFreeBSTR($passwordPointer)",
            "FreeHGlobal($passwordPointer)",
            1,
        ),
    )
    assert expected[-1] in probe
    for mutation in mutations:
        try:
            _assert_credential_launch_probe_cleanup_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError("native probe cleanup mutation was accepted")


_CREDENTIAL_LAUNCH_PROBE_OUTPUT_CHANNEL_RE = re.compile(
    r"(?i)\bWrite-(?:Output|Host|Verbose|Debug|Information|Warning|Error)\b"
    r"|\[Console\]\s*::"
)


def _assert_credential_launch_probe_privacy_contract(probe: str) -> None:
    assert not _CREDENTIAL_LAUNCH_PROBE_OUTPUT_CHANNEL_RE.search(probe)
    assert probe.count("return $json") == 1
    bounded_check = probe.index("if ($bytes.Length -gt 4096)")
    assert bounded_check < probe.index("return $json")
    assert probe.rstrip().endswith("return $json\n}")


def test_credential_launch_probe_rejects_all_alternate_output_channels() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    _assert_credential_launch_probe_privacy_contract(probe)
    for command in (
        "Write-Output",
        "Write-Host",
        "Write-Verbose",
        "Write-Debug",
        "Write-Information",
        "Write-Warning",
        "Write-Error",
        "[Console]::WriteLine",
        "[Console]::Error.WriteLine",
    ):
        mutation = probe.replace(
            "            $records += [ordered]@{",
            f"            {command} $User.Name\n            $records += [ordered]@{{",
            1,
        )
        try:
            _assert_credential_launch_probe_privacy_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"credential probe output-channel mutation was accepted: {command}")


def test_credential_launch_probe_rejects_sensitive_console_mutations() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    for command in ("Write-Output", "[Console]::WriteLine"):
        mutation = probe.replace(
            "            $records += [ordered]@{",
            f"            {command} $User.Password\n            $records += [ordered]@{{",
            1,
        )
        try:
            _assert_credential_launch_probe_privacy_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"sensitive probe output mutation was accepted: {command}")
    inline_mutation = probe.replace(
        "            $records += [ordered]@{",
        "            $records += [ordered]@{}; Write-Output $User.Name\n"
        "            $records += [ordered]@{",
        1,
    )
    try:
        _assert_credential_launch_probe_privacy_contract(inline_mutation)
    except AssertionError:
        pass
    else:
        raise AssertionError("inline sensitive probe output mutation was accepted")


def test_credential_launch_probe_has_exact_privacy_safe_schema() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    keys, values = _credential_launch_probe_projection(module)
    assert keys == _CREDENTIAL_LAUNCH_PROBE_FIELDS
    assert values == {
        "case": "$case.Case",
        "success": "$success",
        "native_error": "$nativeError",
        "length_bucket": "$lengthBucket",
    }
    assert "ConvertTo-Json -Compress" in probe
    assert "[Text.Encoding]::UTF8.GetBytes" in probe
    assert "if ($bytes.Length -gt 4096)" in probe
    assert "return $json" in probe
    for forbidden in _CREDENTIAL_LAUNCH_PROBE_FORBIDDEN_FIELDS:
        assert not re.search(rf"(?m)^\s*{re.escape(forbidden)}\s*=", probe)
    assert "Exception.Message" not in probe
    assert "Write-Output $User" not in probe
    assert "Write-Output $command" not in probe


def test_credential_launch_probe_schema_rejects_privacy_mutations() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    for forbidden in _CREDENTIAL_LAUNCH_PROBE_FORBIDDEN_FIELDS:
        mutation = probe.replace(
            "            case = $case.Case\n",
            f"            {forbidden} = 'forbidden'\n            case = $case.Case\n",
            1,
        )
        try:
            keys, _ = _credential_launch_probe_projection(mutation)
            assert keys == _CREDENTIAL_LAUNCH_PROBE_FIELDS
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"credential launch probe privacy mutation was accepted: {forbidden}")


def test_credential_launch_probe_cases_are_exact_and_mutation_aware() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    _assert_exact_credential_launch_probe_cases(probe)
    mutations = (
        probe.replace("long_null_application", "short_null_application", 1),
        probe.replace("ApplicationName = $null", "ApplicationName = $commandExecutable", 1),
        probe.replace("$command.Length -gt 1024", "$command.Length -gt 1023", 1),
        probe.replace("$longCommand = $shortCommand + ('x' * 1100)", "$longCommand = $shortCommand", 1),
    )
    for mutation in mutations:
        try:
            _assert_exact_credential_launch_probe_cases(mutation)
        except AssertionError:
            continue
        raise AssertionError("credential launch probe case mutation was accepted")
    assert "('x' * 1100)" in probe
    assert "$lengthBucket = if ($command.Length -gt 1024)" in probe


def test_credential_launch_probe_preserves_native_credential_and_handle_contract() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    for required in (
        "CreateProcessWithLogonW",
        "CreatePipe",
        "SetHandleInformation",
        "STARTF_USESTDHANDLES",
        "$User.Name",
        "$User.Domain",
        "$User.Password",
        "$logonFlags = 0",
        "$null",
        "[IntPtr]::Zero",
        "StringToHGlobalUni",
        "ZeroFreeBSTR",
        "FreeHGlobal",
        "CloseHandle",
        "hStdOutput",
        "hStdError",
        "hStdInput",
        "$bInheritHandles = $true",
        "finally",
    ):
        assert required in probe, f"native probe is missing {required!r}"
    assert "CREATE_NO_WINDOW" not in probe
    assert "dwCreationFlags = 0" in probe
    assert "$bInheritHandles = $true" in probe
    assert "$lpEnvironment = [IntPtr]::Zero" in probe
    assert "$lpCurrentDirectory = $null" in probe
    assert probe.index("$passwordPointer =") < probe.index("foreach ($case in $cases)")
    assert probe.index("ZeroFreeBSTR") > probe.index("foreach ($case in $cases)")
    assert probe.count("CloseHandle") == 1
    assert probe.count("CreateProcessWithLogonW") == 1
    assert module.count("CreateProcessWithLogonW") == 2
    assert "public static extern bool CreateProcessWithLogonW" in module
    assert "::CreateProcessWithLogonW" in probe


def _assert_exact_credential_launch_probe_native_contract(probe: str) -> None:
    required = (
        "$logonFlags = 0",
        "$dwCreationFlags = 0",
        "$lpEnvironment = [IntPtr]::Zero",
        "$lpCurrentDirectory = $null",
        "$bInheritHandles = $true",
        "[Runtime.InteropServices.Marshal]::StringToHGlobalUni($command)",
        "[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)",
        "[Runtime.InteropServices.Marshal]::FreeHGlobal($commandPointer)",
        "[SnipeSpotter.CredentialLaunchNative]::CloseHandle($handle)",
    )
    for required_text in required:
        assert required_text in probe, f"native probe contract is missing {required_text!r}"
    assert "CREATE_NO_WINDOW" not in probe
    assert "[ref]$startupInfo" in probe
    assert "[ref]$processInfo" in probe
    assert "[Runtime.InteropServices.Marshal]::GetLastWin32Error()" in probe
    assert "WaitForSingleObject($processInfo.hProcess, 5000)" in probe
    assert all(
        variable in probe
        for variable in (
            "$hInputRead",
            "$hInputWrite",
            "$hOutputRead",
            "$hOutputWrite",
            "$hErrorRead",
            "$hErrorWrite",
            "$processInfo.hProcess",
            "$processInfo.hThread",
        )
    )


def test_credential_launch_probe_native_contract_mutations_are_rejected() -> None:
    module = read_module("Security.psm1")
    probe = _credential_launch_probe_text(module)
    _assert_exact_credential_launch_probe_native_contract(probe)
    required_pairs = (
        ("$logonFlags = 0", "$logonFlags = 2"),
        ("$dwCreationFlags = 0", "$dwCreationFlags = 16"),
        ("$lpEnvironment = [IntPtr]::Zero", "$lpEnvironment = $environment"),
        ("$lpCurrentDirectory = $null", "$lpCurrentDirectory = $workingDirectory"),
        ("ZeroFreeBSTR($passwordPointer)", "FreeBSTR($passwordPointer)"),
        ("StringToHGlobalUni($command)", "StringToCoTaskMemUni($command)"),
    )
    for expected, replacement in required_pairs:
        mutation = probe.replace(expected, replacement, 1)
        assert expected in probe
        assert replacement in mutation
        try:
            _assert_exact_credential_launch_probe_native_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"credential launch native contract mutation was accepted: {expected}")


def test_credential_launch_probe_runs_only_at_native_start_failure_boundary() -> None:
    module = read_module("Security.psm1")
    spans = _credential_launch_catch_spans(module)
    assert len(spans) == 3
    catches = tuple(module[start:end] for start, end in spans)
    assert catches[2].count("Invoke-CredentialLaunchProbe -User $User") == 1
    assert "Invoke-CredentialLaunchProbe" not in catches[0]
    assert "Invoke-CredentialLaunchProbe" not in catches[1]
    invoke_start = module.index("function Invoke-AsStandardUser")
    invoke_end = module.index("function Assert-StandardUserCannotReadWrite", invoke_start)
    invoke = module[invoke_start:invoke_end]
    assert invoke.count("Invoke-CredentialLaunchProbe") == 1
    assert invoke.index("Invoke-CredentialLaunchProbe") > invoke.index("$process.Start()")
    assert "Write-Output" not in catches[2]


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
    test_credentialed_launch_diagnostic_schema_is_exact_and_bounded()
    test_credentialed_launch_diagnostic_schema_rejects_privacy_mutations()
    test_credentialed_launch_catches_have_exact_failure_tuples()
    test_credentialed_launch_catch_tuple_mutations_are_rejected()
    test_credentialed_launch_classifies_configuration_and_native_failures()
    test_credentialed_native_start_catch_saves_original_error_record()
    test_credentialed_native_start_error_mutations_are_rejected()
    test_credentialed_native_start_capture_preserves_probe_and_original_error()
    test_credentialed_native_start_capture_mutations_are_rejected()
    test_credential_launch_probe_evidence_parser_is_exact_and_bounded()
    test_credential_launch_probe_evidence_parser_enforces_int32_native_error_range()
    test_credential_launch_probe_evidence_parser_rejects_range_bound_mutations()
    test_credential_launch_probe_evidence_parser_rejects_nested_mutations()
    test_credential_launch_probe_evidence_capture_rejects_alternate_output_channels()
    test_credential_launch_probe_models_bounded_wait_and_termination()
    test_credential_launch_probe_wait_and_termination_mutations_are_rejected()
    test_credential_launch_probe_has_exact_cleanup_scopes_and_handles()
    test_credential_launch_probe_cleanup_mutations_are_rejected()
    test_credential_launch_probe_rejects_all_alternate_output_channels()
    test_credential_launch_probe_rejects_sensitive_console_mutations()
    test_credential_launch_probe_has_exact_privacy_safe_schema()
    test_credential_launch_probe_schema_rejects_privacy_mutations()
    test_credential_launch_probe_cases_are_exact_and_mutation_aware()
    test_credential_launch_probe_preserves_native_credential_and_handle_contract()
    test_credential_launch_probe_native_contract_mutations_are_rejected()
    test_credential_launch_probe_runs_only_at_native_start_failure_boundary()
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
