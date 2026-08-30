"""Static contract checks for Windows lifecycle test-support modules."""

import base64
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parent / "TestSupport"
LIFECYCLE = ROOT.parent / "test-msi-lifecycle.ps1"
DIRECT_SCM = ROOT.parent / "test-direct-scm-lifecycle.ps1"
LOOPBACK = ROOT / "SnipeItLoopback.psm1"
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
    "native_probe_stage",
    "native_probe_rejection",
)
_CREDENTIAL_LAUNCH_PROBE_REJECTIONS = (
    "none",
    "size",
    "json",
    "envelope_schema",
    "stage",
    "record_count",
    "record_schema",
    "field_type",
    "native_error_range",
    "wait_outcome",
    "case",
    "success_error_relation",
    "length_bucket",
    "normalization",
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
    "wait_outcome",
    "length_bucket",
)
_CREDENTIAL_LAUNCH_PROBE_WAIT_OUTCOMES = (
    "none",
    "timeout",
    "wait_failed",
    "unexpected",
    "termination_timeout",
    "termination_wait_failed",
    "termination_unexpected",
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
_DIRECT_RESULT_SHAPE_FAILURE_SIGNAL = "direct result-shape schema assertion failed"
_DIRECT_RESULT_SHAPE_STAGES = (
    "ServiceUninstall",
    "StatusHealthCheck",
    "ServiceInstall",
    "DuplicateServiceInstall",
    "ConfigSet",
    "SetToken",
    "TriggerSync",
    "MissingServiceUninstall",
)
_DIRECT_RESULT_SHAPE_FILES = (
    "direct-cli-result-shape-service-uninstall.json",
    "direct-cli-result-shape-status-health-check.json",
    "direct-cli-result-shape-service-install.json",
    "direct-cli-result-shape-duplicate-service-install.json",
    "direct-cli-result-shape-config-set.json",
    "direct-cli-result-shape-set-token.json",
    "direct-cli-result-shape-trigger-sync.json",
    "direct-cli-result-shape-missing-service-uninstall.json",
)

_CREDENTIAL_LAUNCH_PROBE_STAGES = (
    "not_started",
    "password_bstr",
    "case_setup",
    "pipe_create",
    "handle_setup",
    "process_create",
    "wait",
    "terminate",
    "cleanup",
    "serialize",
    "parse",
    "complete",
)


def read_module(name: str) -> str:
    path = ROOT / name
    assert path.is_file(), f"missing test-support module: {path}"
    return path.read_text(encoding="utf-8")


def test_snipeit_loopback_fixture_is_private_and_evidence_only() -> None:
    source = read_module("SnipeItLoopback.psm1")
    assert "# pattern: Imperative Shell" in source
    assert "HttpListener" in source
    assert "127.0.0.1" in source
    assert "TcpListener" in source
    assert ", 0)" in source
    assert "GetContextAsync" in source
    assert "byserial" in source
    assert "manufacturers" in source
    assert "models" in source
    assert "if ($statusCode -eq 404 -and $route -eq 'hardware_byserial')" in source
    assert "elseif ($statusCode -eq 200)" in source
    assert "'{\"message\":\"not found\"}'" in source
    assert 'rows = @()' in source
    assert "Authorization" in source
    assert "Bearer " in source
    assert "authorized =" in source
    assert "token" not in source.lower().replace("authorization", "") or "sentinel" in source.lower()
    assert "mutation" in source.lower()
    assert "unexpected" in source.lower()
    assert "Stop" in source
    assert "Dispose" in source
    assert "Stop-SnipeItLoopbackFixture" in source


def test_direct_scm_exercises_installed_cli_to_service_sync_flow() -> None:
    assert DIRECT_SCM.is_file(), "missing direct SCM lifecycle script"
    source = DIRECT_SCM.read_text(encoding="utf-8")
    for required in (
        "SnipeItLoopback.psm1",
        "Start-SnipeItLoopbackFixture",
        "Stop-SnipeItLoopbackFixture",
        "Invoke-TokenCli",
        "RedirectStandardInput",
        "WriteAsync($Text)",
        "DisposeAsync()",
        "config', 'set",
        "snipeit.url",
        "snipeit.checkout_status_id",
        "snipeit.checkin_status_id",
        "config', 'set-token",
        "Restart-Service",
        "TriggerSync",
        "Assert-ServiceRunsAsSystem -Name $serviceName",
        "api_token_encrypted",
        "sentinel",
        "Get-ChildItem",
        "finally",
    ):
        assert required in source, f"direct AC.4 flow missing {required!r}"
    assert "Bearer $" not in source
    assert "Arguments @('-Token'" not in source
    assert "Arguments @('--token'" not in source
    assert "-Environment" not in source
    assert "Start-Sleep -Seconds 5" not in source


def test_direct_scm_result_shape_diagnostic_precedes_first_exit_code_consumer() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    diagnostic_name = "Write-DirectCliResultShapeDiagnostic"
    assert f"function {diagnostic_name}" in source
    diagnostic = _powershell_function(source, diagnostic_name)
    for required in (
        "result_count",
        "result_is_array",
        "record_${index}_has_exit_code",
        "record_${index}_has_stdout",
        "record_${index}_has_stderr",
        "record_${index}_has_description",
        "Write-BoundedDiagnostic",
    ):
        assert required in diagnostic
    for forbidden in (
        "result_value",
        "$Result.Stdout",
        "$Result.Stderr",
        "$Result.Description",
        "$Result.ExitCode",
        "Arguments",
        "$Token",
    ):
        assert forbidden not in diagnostic

    lifecycle_start = source.index("$install = Invoke-DirectCli")
    diagnostic_call = source.index(
        f"{diagnostic_name} -Result $install -Stage 'ServiceInstall'",
        lifecycle_start,
    )
    exit_code_consumer = source.index("$install.ExitCode", lifecycle_start)
    assert diagnostic_call < exit_code_consumer


def test_direct_scm_result_shape_diagnostic_covers_every_exit_code_consumer() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper = _powershell_function(source, "Write-DirectCliResultShapeDiagnostic")
    stage_match = re.search(
        r"\[ValidateSet\((?P<stages>'(?:[^']|'')+'(?:\s*,\s*'(?:[^']|'')+')*)\)\]\[string\]\$Stage",
        helper,
    )
    assert stage_match is not None
    assert tuple(re.findall(r"'([^']+)'", stage_match.group("stages"))) == _DIRECT_RESULT_SHAPE_STAGES
    for filename in _DIRECT_RESULT_SHAPE_FILES:
        assert f"'{filename}'" in helper
    assert helper.count("direct-cli-result-shape-") == len(_DIRECT_RESULT_SHAPE_FILES)
    assert "Join-Path $LogDirectory $Stage" not in helper
    assert "direct-cli-result-shape.json" not in helper

    consumer_specs = (
        ("Invoke-DirectUninstall", "$result = Invoke-DirectCli", "$result.ExitCode", "ServiceUninstall"),
        ("Get-DirectStatus", "$result = Invoke-DirectCli", "$result.ExitCode", "StatusHealthCheck"),
        ("lifecycle", "$install = Invoke-DirectCli", "$install.ExitCode", "ServiceInstall"),
        ("lifecycle", "$duplicate = Invoke-DirectCli", "$duplicate.ExitCode", "DuplicateServiceInstall"),
        ("lifecycle", "$result = Invoke-DirectCli", "$result.ExitCode", "ConfigSet"),
        ("lifecycle", "$tokenResult = Invoke-TokenCli", "$tokenResult.ExitCode", "SetToken"),
        ("lifecycle", "$sync = Invoke-DirectCli", "$sync.ExitCode", "TriggerSync"),
        ("lifecycle", "$missing = Invoke-DirectCli", "$missing.ExitCode", "MissingServiceUninstall"),
    )
    lifecycle_start = source.index("$identity =")
    calls = []
    for owner, assignment, consumer, stage in consumer_specs:
        owner_start = lifecycle_start if owner == "lifecycle" else source.index(f"function {owner}")
        assignment_position = source.index(assignment, owner_start)
        diagnostic_call = source.index(
            f"Write-DirectCliResultShapeDiagnostic -Result ${assignment.split('$')[1].split()[0]} -Stage '{stage}'",
            assignment_position,
        )
        consumer_position = source.index(consumer, assignment_position)
        between = source[diagnostic_call:consumer_position]
        assert assignment_position < diagnostic_call < consumer_position, (
            f"{stage} diagnostic must immediately precede its first ExitCode consumer"
        )
        assert between.count("\n") == 1, f"{stage} diagnostic is not immediately before its consumer"
        calls.append(stage)
    assert tuple(calls) == _DIRECT_RESULT_SHAPE_STAGES

    workflow = (ROOT.parent.parent / ".github" / "workflows" / "elevated-windows.yml").read_text(
        encoding="utf-8"
    )
    assert "-LogDirectory (Join-Path $env:RUNNER_TEMP 'snipespotter-msi-logs')" in workflow
    assert "path: ${{ runner.temp }}/snipespotter-msi-logs/*" in workflow


def _direct_result_shape_fixture(helper: str) -> str:
    diagnostics_module = str(ROOT / "Diagnostics.psm1").replace("'", "''")
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module '{diagnostics_module}' -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('direct-result-shape-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$LogDirectory = $root
$WarningPreference = 'SilentlyContinue'
{helper}

$schemaFailureSignal = '{_DIRECT_RESULT_SHAPE_FAILURE_SIGNAL}'
function Assert-Shape {{
    param(
        [Parameter(Mandatory = $true)][object]$Json,
        [Parameter(Mandatory = $true)][string[]]$ExpectedKeys,
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][bool]$ExpectedArray
    )
    $actualKeys = @($Json.PSObject.Properties.Name | Sort-Object)
    $expectedKeySet = @($ExpectedKeys | Sort-Object)
    if (($actualKeys -join '|') -cne ($expectedKeySet -join '|')) {{
        throw $schemaFailureSignal
    }}
    if ($Json.stage -isnot [string]) {{ throw $schemaFailureSignal }}
    if ($Json.result_count -isnot [int] -and $Json.result_count -isnot [long]) {{
        throw $schemaFailureSignal
    }}
    if ($Json.result_is_array -isnot [bool]) {{ throw $schemaFailureSignal }}
    if ([int]$Json.result_count -ne $ExpectedCount) {{ throw $schemaFailureSignal }}
    if ([bool]$Json.result_is_array -ne $ExpectedArray) {{ throw $schemaFailureSignal }}
    foreach ($key in @($ExpectedKeys | Where-Object {{ $_ -like 'record_*' }})) {{
        if ($Json.$key -isnot [bool]) {{ throw $schemaFailureSignal }}
    }}
}}

function Read-Diagnostic {{
    param([Parameter(Mandatory = $true)][ValidateSet(
        'ServiceUninstall', 'StatusHealthCheck', 'ServiceInstall', 'DuplicateServiceInstall',
        'ConfigSet', 'SetToken', 'TriggerSync', 'MissingServiceUninstall'
    )][string]$Stage)
    $paths = @{{
        ServiceUninstall = 'direct-cli-result-shape-service-uninstall.json'
        StatusHealthCheck = 'direct-cli-result-shape-status-health-check.json'
        ServiceInstall = 'direct-cli-result-shape-service-install.json'
        DuplicateServiceInstall = 'direct-cli-result-shape-duplicate-service-install.json'
        ConfigSet = 'direct-cli-result-shape-config-set.json'
        SetToken = 'direct-cli-result-shape-set-token.json'
        TriggerSync = 'direct-cli-result-shape-trigger-sync.json'
        MissingServiceUninstall = 'direct-cli-result-shape-missing-service-uninstall.json'
    }}
    $path = Join-Path $LogDirectory $paths[$Stage]
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{ throw $schemaFailureSignal }}
    $text = [IO.File]::ReadAllText($path)
    if ($text.Contains($sentinel, [StringComparison]::Ordinal)) {{ throw $schemaFailureSignal }}
    try {{
        $json = $text | ConvertFrom-Json
    }} catch {{
        throw $schemaFailureSignal
    }}
    return @{{ Text = $text; Json = $json }}
}}

try {{
$sentinel = 'direct-result-sensitive-sentinel'
$baseKeys = @('stage', 'result_count', 'result_is_array')
$recordKeys = @(
    'record_0_has_exit_code', 'record_0_has_stdout', 'record_0_has_stderr', 'record_0_has_description'
)
$scalar = [pscustomobject][ordered]@{{
    ExitCode = 0
    Stdout = "$sentinel-stdout"
    Stderr = "$sentinel-stderr"
    Description = "$sentinel-description"
    Password = "$sentinel-password"
    Exception = [Exception]::new($sentinel)
}}

Write-DirectCliResultShapeDiagnostic -Result $null -Stage 'ServiceUninstall'
$nullDiagnostic = Read-Diagnostic -Stage 'ServiceUninstall'
Assert-Shape -Json $nullDiagnostic.Json -ExpectedKeys $baseKeys -ExpectedCount 0 -ExpectedArray $false
if ([int][Text.Encoding]::UTF8.GetByteCount($nullDiagnostic.Text) -gt 32768) {{ throw $schemaFailureSignal }}

Write-DirectCliResultShapeDiagnostic -Result $scalar -Stage 'StatusHealthCheck'
$scalarDiagnostic = Read-Diagnostic -Stage 'StatusHealthCheck'
Assert-Shape -Json $scalarDiagnostic.Json -ExpectedKeys ($baseKeys + $recordKeys) -ExpectedCount 1 -ExpectedArray $false
if ($scalarDiagnostic.Json.record_0_has_exit_code -ne $true -or
    $scalarDiagnostic.Json.record_0_has_stdout -ne $true -or
    $scalarDiagnostic.Json.record_0_has_stderr -ne $true -or
    $scalarDiagnostic.Json.record_0_has_description -ne $true) {{
    throw $schemaFailureSignal
}}

$arrayResult = @(
    $scalar
    [pscustomobject][ordered]@{{
        ExitCode = 1
        Stdout = "$sentinel-array-stdout"
        Stderr = "$sentinel-array-stderr"
        Description = "$sentinel-array-description"
        'arbitrary.property' = $sentinel
    }}
)
$arrayKeys = @($baseKeys + $recordKeys + @(
    'record_1_has_exit_code', 'record_1_has_stdout', 'record_1_has_stderr', 'record_1_has_description'
))
Write-DirectCliResultShapeDiagnostic -Result $arrayResult -Stage 'ConfigSet'
$arrayDiagnostic = Read-Diagnostic -Stage 'ConfigSet'
Assert-Shape -Json $arrayDiagnostic.Json -ExpectedKeys $arrayKeys -ExpectedCount 2 -ExpectedArray $true

$oversizedResult = @()
for ($index = 0; $index -lt 32; $index++) {{ $oversizedResult += $scalar }}
$oversizedKeys = @($baseKeys)
for ($index = 0; $index -lt 4; $index++) {{
    $oversizedKeys += @(
        "record_$($index)_has_exit_code",
        "record_$($index)_has_stdout",
        "record_$($index)_has_stderr",
        "record_$($index)_has_description"
    )
}}
Write-DirectCliResultShapeDiagnostic -Result $oversizedResult -Stage 'MissingServiceUninstall'
$oversizedDiagnostic = Read-Diagnostic -Stage 'MissingServiceUninstall'
Assert-Shape -Json $oversizedDiagnostic.Json -ExpectedKeys $oversizedKeys -ExpectedCount 32 -ExpectedArray $true
if ([int][Text.Encoding]::UTF8.GetByteCount($oversizedDiagnostic.Text) -gt 32768) {{
    throw $schemaFailureSignal
}}
Write-Output 'direct result-shape fixture accepted'
}} catch {{
    [Console]::Error.WriteLine($schemaFailureSignal)
    exit 1
}}
"""


def test_direct_scm_result_shape_diagnostic_has_exact_bounded_schema() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper = _powershell_function(source, "Write-DirectCliResultShapeDiagnostic")
    assert "$MaxDiagnosticRecords = 4" in helper
    result = _run_powershell_fixture(_direct_result_shape_fixture(helper))
    assert result.returncode == 0, result.stderr or result.stdout
    assert "direct result-shape fixture accepted" in result.stdout


def test_direct_scm_result_shape_diagnostic_does_not_mask_original_failure() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper = _powershell_function(source, "Write-DirectCliResultShapeDiagnostic")
    diagnostics_module = str(ROOT / "Diagnostics.psm1").replace("'", "''")
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module '{diagnostics_module}' -Force
$root = Join-Path ([IO.Path]::GetTempPath()) ('direct-result-shape-failure-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$LogDirectory = Join-Path $root 'missing-diagnostic-directory'
{helper}
$record = [pscustomobject][ordered]@{{
    ExitCode = 1
    Stdout = 'oversized-stdout'
    Stderr = 'oversized-stderr'
    Description = 'oversized-description'
}}
$oversizedResult = @()
for ($index = 0; $index -lt 32; $index++) {{ $oversizedResult += $record }}
$primaryMessage = 'original lifecycle failure'
$caught = $null
try {{
    Write-DirectCliResultShapeDiagnostic -Result $oversizedResult -Stage 'ServiceInstall'
    throw $primaryMessage
}} catch {{
    $caught = $_
}}
if ($null -eq $caught -or $caught.Exception.Message -cne $primaryMessage) {{
    throw "original failure was masked: $($caught.Exception.Message)"
}}
Write-Output 'original failure preserved'
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "original failure preserved" in result.stdout


def test_direct_scm_result_shape_diagnostic_rejects_privacy_mutations() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper = _powershell_function(source, "Write-DirectCliResultShapeDiagnostic")
    expected_failure_signal = _DIRECT_RESULT_SHAPE_FAILURE_SIGNAL
    shared_forbidden_content = (
        str(ROOT),
        str(ROOT / "Diagnostics.psm1"),
        str(Path(tempfile.gettempdir())),
        "direct-result-shape-",
        *(_DIRECT_RESULT_SHAPE_FILES),
        "-Result",
        "-Stage",
        "Result",
        "Stage",
        "ExpectedKeys",
        "ExpectedCount",
        "ExpectedArray",
        "NullResult",
        "ScalarResult",
        "ArrayResult",
        "OversizedResult",
        "$null",
        "$scalar",
        "$arrayResult",
        "$oversizedResult",
        "ExitCode",
        "Stdout",
        "Stderr",
        "Description",
        "Password",
        "Exception",
        "record_0_has_exit_code",
        "record_0_has_stdout",
        "record_0_has_stderr",
        "record_0_has_description",
        "record_1_has_exit_code",
        "record_1_has_stdout",
        "record_1_has_stderr",
        "record_1_has_description",
        "direct-result-sensitive-sentinel",
        "direct-result-sensitive-sentinel-stdout",
        "direct-result-sensitive-sentinel-stderr",
        "direct-result-sensitive-sentinel-description",
        "direct-result-sensitive-sentinel-password",
        "direct-result-sensitive-sentinel-array-stdout",
        "direct-result-sensitive-sentinel-array-stderr",
        "direct-result-sensitive-sentinel-array-description",
        "arbitrary.property",
    )
    mutations = (
        (
            "extra key",
            helper.replace(
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                "        $values['extra'] = 'extra-sensitive-value'\n"
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                1,
            ),
            ("extra", "extra-sensitive-value"),
        ),
        (
            "record value",
            helper.replace(
                '        $values["record_${index}_has_description"] = $properties -contains \'Description\'\n',
                '        $values["record_${index}_has_description"] = $properties -contains \'Description\'\n'
                '        $values["record_${index}_value"] = $record\n',
                1,
            ),
            (
                "record_0_value",
                "ExitCode",
                "Stdout",
                "Stderr",
                "Description",
                "direct-result-sensitive-sentinel",
                "direct-result-sensitive-sentinel-stdout",
                "direct-result-sensitive-sentinel-stderr",
                "direct-result-sensitive-sentinel-description",
                "direct-result-sensitive-sentinel-password",
            ),
        ),
        (
            "exception value",
            helper.replace(
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                "        $values['exception'] = [Exception]::new('exception-sensitive-value')\n"
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                1,
            ),
            ("exception", "exception-sensitive-value", "System.Exception"),
        ),
        (
            "arbitrary property name",
            helper.replace(
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                "        $values['arbitrary.property'] = 'arbitrary-sensitive-value'\n"
                "        $diagnosticPath = Join-Path $LogDirectory $diagnosticFile\n",
                1,
            ),
            ("arbitrary.property", "arbitrary-sensitive-value"),
        ),
    )
    for label, mutation, injected_content in mutations:
        assert mutation != helper, f"{label} mutation was not applied"
        result = _run_powershell_fixture(_direct_result_shape_fixture(mutation))
        combined_output = result.stdout + result.stderr
        assert result.returncode != 0, f"{label} mutation was accepted"
        assert combined_output.strip() == expected_failure_signal, (
            f"{label} reported an unexpected failure reason"
        )
        for forbidden in (*shared_forbidden_content, *injected_content):
            assert forbidden not in combined_output, (
                f"{label} leaked forbidden fixture content {forbidden!r}"
            )


def test_direct_scm_waits_for_loopback_prefix_before_method_call() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    fixture_start = source.index("$fixture = Start-SnipeItLoopbackFixture")
    readiness_wait = source.index(
        "Wait-Condition -Description 'Snipe-IT loopback fixture readiness'",
        fixture_start,
    )
    prefix_method_call = source.index("$fixture.Prefix.StartsWith(", fixture_start)
    assert fixture_start < readiness_wait < prefix_method_call


def _run_powershell_fixture(
    script: str,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 30,
) -> subprocess.CompletedProcess[str]:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for executable AC.4 fixtures"
    return subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_seconds,
    )


def _powershell_function(source: str, name: str) -> str:
    marker = f"function {name}"
    start = source.index(marker)
    opening = source.index("{", start)
    return source[start : _powershell_braced_block_end(source, opening)]


def _stream_capture_fixture(helpers: str) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$sentinel = 'cross-chunk-sentinel'
$capture = [hashtable]::Synchronized(@{{
    Sentinel = $sentinel
    MaxCharacters = 65536
    Stdout = [Text.StringBuilder]::new()
    Stderr = [Text.StringBuilder]::new()
    StdoutScanTail = ''
    StderrScanTail = ''
    StdoutSentinelFound = $false
    StderrSentinelFound = $false
    StdoutRetainedTruncated = $false
    StderrRetainedTruncated = $false
    StdoutScanComplete = $false
    StderrScanComplete = $false
    ScanError = $false
}})
Write-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout' -Chunk (('x' * 65530) + 'cross-chunk-')
Write-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout' -Chunk ('sentinel' + ('y' * 100))
Write-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr' -Chunk ('z' * 65536)
Write-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr' -Chunk $sentinel
Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout'
Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr'
if (-not $capture.StdoutSentinelFound -or -not $capture.StderrSentinelFound) {{ throw 'cross-chunk or post-retention sentinel was missed' }}
if (-not $capture.StdoutRetainedTruncated -or -not $capture.StderrRetainedTruncated) {{ throw 'retained diagnostic truncation was not tracked' }}
try {{ Assert-BoundedProcessCaptureSafe -Capture $capture }} catch {{ $leakRejected = $true }}
if (-not $leakRejected) {{ throw 'sentinel-bearing output was accepted' }}
$capture.StdoutSentinelFound = $false
$capture.StderrSentinelFound = $false
Assert-BoundedProcessCaptureSafe -Capture $capture
$capture.StdoutScanComplete = $false
try {{ Assert-BoundedProcessCaptureSafe -Capture $capture }} catch {{ $incompleteRejected = $true }}
if (-not $incompleteRejected) {{ throw 'incompletely scanned output was accepted' }}
$capture.StdoutScanComplete = $true
$capture.StderrScanComplete = $true
$capture.ScanError = $true
try {{ Assert-BoundedProcessCaptureSafe -Capture $capture }} catch {{ $errorRejected = $true }}
if (-not $errorRejected) {{ throw 'scan error was accepted' }}
Write-Output 'stream capture fixture accepted'
"""


def _real_process_capture_fixture(helpers: str, child_command: str, assertions: str, post_process: str = "", skip_explicit_completion: bool = False) -> str:
    escaped_child_command = child_command.replace("'", "''")
    skip_completion_literal = "$true" if skip_explicit_completion else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$sentinel = 'real-handler-sentinel'
$capture = [hashtable]::Synchronized(@{{
    Sentinel = $sentinel
    MaxCharacters = 65536
    Stdout = [Text.StringBuilder]::new()
    Stderr = [Text.StringBuilder]::new()
    StdoutScanTail = ''
    StderrScanTail = ''
    StdoutSentinelFound = $false
    StderrSentinelFound = $false
    StdoutRetainedTruncated = $false
    StderrRetainedTruncated = $false
    StdoutScanComplete = $false
    StderrScanComplete = $false
    ScanError = $false
}})
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-NonInteractive')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add('{escaped_child_command}')
$process = [Diagnostics.Process]::new()
$process.StartInfo = $info
$handlers = Get-BoundedProcessCapture -Capture $capture
$skip_explicit_completion = {skip_completion_literal}
$process.add_OutputDataReceived($handlers.StdoutHandler)
$process.add_ErrorDataReceived($handlers.StderrHandler)
try {{
    if (-not $process.Start()) {{ throw 'child did not start' }}
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    if (-not $process.WaitForExit(10000)) {{ throw 'child did not exit' }}
    if (-not $process.WaitForExit(10000)) {{ throw 'child output did not drain' }}
    if (-not $skip_explicit_completion) {{
        Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout'
        Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr'
    }}
    {post_process}
    {assertions}
    Write-Output 'real handler fixture accepted'
}} finally {{
    try {{ $process.remove_OutputDataReceived($handlers.StdoutHandler) }} catch {{ }}
    try {{ $process.remove_ErrorDataReceived($handlers.StderrHandler) }} catch {{ }}
    if (-not $process.HasExited) {{ try {{ $process.Kill($true); $process.WaitForExit(1000) }} catch {{ }} }}
    $process.Dispose()
}}
"""


def test_ac4_real_capture_handlers_are_runspace_independent() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helpers = "\n".join(
        _powershell_function(source, name)
        for name in (
            "Assert-True",
            "Initialize-BoundedProcessCaptureType",
            "Sync-BoundedProcessCaptureState",
            "Write-BoundedProcessCaptureStream",
            "Complete-BoundedProcessCaptureStream",
            "Get-BoundedProcessCapture",
        )
    )
    child_command = (
        "[Console]::Out.WriteLine(\"clean-stdout\"); "
        "[Console]::Out.WriteLine((\"x\" * 65536) + \"real-handler-\"); "
        "[Console]::Out.WriteLine(\"sentinel\"); "
        "[Console]::Error.WriteLine(\"clean-stderr\")"
    )
    post_process = (
        "$capture.NativeCapture.Dispose(); "
        "$disposedArgs = [Activator]::CreateInstance([Diagnostics.DataReceivedEventArgs], [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic, $null, @(\"after-dispose\"), $null); "
        "$capture.NativeCapture.StdoutHandler.Invoke($null, $disposedArgs); "
        "Sync-BoundedProcessCaptureState -Capture $capture; "
        "$handlerErrorRejected = $false; "
        "try { Assert-BoundedProcessCaptureSafe -Capture $capture } catch { $handlerErrorRejected = $true }; "
        "if (-not $capture.ScanError -or -not $handlerErrorRejected) { throw \"handler error was accepted\" }"
    )
    assertions = (
        "if ($capture.Stdout.ToString().Length -gt 65536) { throw \"stdout retention exceeded the bound\" }; "
        "if ($capture.Stderr.ToString() -cne \"clean-stderr\") { throw \"clean stderr was not retained\" }; "
        "if (-not $capture.StdoutSentinelFound) { throw \"stdout cross-boundary sentinel was missed\" }; "
        "if ($capture.StderrSentinelFound) { throw \"clean stderr was reported as a sentinel\" }; "
        "if (-not $capture.StdoutRetainedTruncated) { throw \"stdout truncation was not tracked\" }; "
        "if ($capture.StderrRetainedTruncated) { throw \"clean stderr was reported as truncated\" }; "
        "if (-not $capture.StdoutScanComplete -or -not $capture.StderrScanComplete) { throw \"EOF completion was missed\" }; "
        "$rejected = $false; "
        "try { Assert-BoundedProcessCaptureSafe -Capture $capture } catch { $rejected = $true }; "
        "if (-not $rejected) { throw \"sentinel-bearing output was accepted\" }"
    )
    fixture = _real_process_capture_fixture(
        helpers,
        child_command,
        assertions,
        post_process,
        skip_explicit_completion=True,
    )
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "real handler fixture accepted" in result.stdout


def test_ac4_stream_capture_is_incremental_bounded_and_fail_closed() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    required = (
        "Write-BoundedProcessCaptureStream",
        "Complete-BoundedProcessCaptureStream",
        "Assert-BoundedProcessCaptureSafe",
    )
    assert all(name in source for name in required)
    fixture = _stream_capture_fixture(
        "\n".join(_powershell_function(source, name) for name in required)
    )
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "stream capture fixture accepted" in result.stdout


def test_ac4_stream_capture_mutations_are_rejected() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    update = _powershell_function(source, "Write-BoundedProcessCaptureStream")
    complete = _powershell_function(source, "Complete-BoundedProcessCaptureStream")
    assert_helper = _powershell_function(source, "Assert-BoundedProcessCaptureSafe")
    mutations = (
        update.replace("$combined.Contains([string]$Capture.Sentinel, [StringComparison]::Ordinal)", "$Chunk.Contains([string]$Capture.Sentinel, [StringComparison]::Ordinal)", 1),
        update.replace("$Capture[$foundName] = $true", "$Capture[$foundName] = $false", 1),
        update.replace("$Capture[$truncatedName] = $true", "$Capture[$truncatedName] = $false", 1),
        complete.replace("$Capture[\"${StreamName}ScanComplete\"] = $true", "$Capture[\"${StreamName}ScanComplete\"] = $false", 1),
    )
    for index, mutation in enumerate(mutations):
        assert mutation != (update if index < 3 else complete)
        helper_set = (mutation, complete, assert_helper) if index < 3 else (update, mutation, assert_helper)
        fixture = _stream_capture_fixture("\n".join(helper_set))
        result = _run_powershell_fixture(fixture)
        assert result.returncode != 0, f"stream mutation {index} was accepted"


def test_ac4_stream_capture_mutation_fixtures_are_registered_and_executable() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    assert "Invoke-BoundedStandardInput" in source
    helper = _powershell_function(source, "Invoke-BoundedStandardInput")
    remaining_helper = _powershell_function(source, "Get-BoundedRemainingMillisecond")
    stop_helper = _powershell_function(source, "Invoke-BoundedProcessStop")
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{remaining_helper}
{stop_helper}
{helper}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
$info.RedirectStandardInput = $true
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add('[Threading.Thread]::Sleep(10000)')
$p = [Diagnostics.Process]::new()
$p.StartInfo = $info
try {{
    if (-not $p.Start()) {{ throw 'child did not start' }}
    try {{ Invoke-BoundedStandardInput -Process $p -Text 'sentinel' -Deadline ([DateTime]::UtcNow.AddMilliseconds(-1)) }} catch {{ $rejected = $true }}
    if (-not $rejected -or -not $p.HasExited) {{ throw 'stdin deadline mutation was accepted' }}
    Write-Output 'stdin deadline fixture accepted'
}} finally {{
    if (-not $p.HasExited) {{ try {{ $p.Kill($true) }} catch {{ }} }}
    $p.Dispose()
}}
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "stdin deadline fixture accepted" in result.stdout


def test_ac4_artifact_scanner_handles_bytes_encodings_boundaries_and_fail_closed() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    required = (
        "Test-BytePatternInWindow",
        "Write-ByteSentinelScan",
        "Invoke-BoundedArtifactStreamScan",
        "Assert-NoSentinelInArtifact",
    )
    assert all(name in source for name in required)
    helpers = "\n".join(_powershell_function(source, name) for name in required)
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$root = Join-Path ([IO.Path]::GetTempPath()) ('ac4-artifact-' + [Guid]::NewGuid().ToString('N'))
$sentinel = 'boundary-π-sentinel'
try {{
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $encodings = @([Text.Encoding]::ASCII, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode)
    for ($i = 0; $i -lt $encodings.Count; $i++) {{
        $encoded = $encodings[$i].GetBytes($sentinel)
        $bytes = [byte[]]::new(65530 + $encoded.Length + 5)
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Copy($encoded, 0, $bytes, 65530, $encoded.Length)
        [IO.File]::WriteAllBytes((Join-Path $root ('hit-' + $i)), $bytes)
    }}
    $clean = [Text.Encoding]::UTF8.GetBytes(('q' * 65537))
    [IO.File]::WriteAllBytes((Join-Path $root 'clean'), $clean)
    try {{ Assert-NoSentinelInArtifact -Root $root -Sentinel $sentinel }} catch {{ $hitRejected = $true }}
    if (-not $hitRejected) {{ throw 'encoded sentinel was missed' }}
    Remove-Item -LiteralPath (Join-Path $root 'hit-0') -Force
    Remove-Item -LiteralPath (Join-Path $root 'hit-1') -Force
    Remove-Item -LiteralPath (Join-Path $root 'hit-2') -Force
    Remove-Item -LiteralPath (Join-Path $root 'hit-3') -Force
    Assert-NoSentinelInArtifact -Root $root -Sentinel $sentinel
    $oversized = Join-Path $root 'oversized'
    [IO.File]::WriteAllBytes($oversized, [byte[]]::new(8))
    try {{ Assert-NoSentinelInArtifact -Root $root -Sentinel $sentinel -MaxArtifactBytes 4 }} catch {{ $oversizeRejected = $true }}
    if (-not $oversizeRejected) {{ throw 'oversized artifact was accepted' }}
    $missingRoot = Join-Path $root 'missing'
    try {{ Assert-NoSentinelInArtifact -Root $missingRoot -Sentinel $sentinel }} catch {{ $unreadableRejected = $true }}
    if (-not $unreadableRejected) {{ throw 'unreadable artifact root was accepted' }}
    $failedScan = @{{ Patterns = @([Text.Encoding]::ASCII.GetBytes($sentinel)); MaxTailLength = 32; Tail = [byte[]]::new(0); Found = $false; Complete = $false }}
    $failedStream = [IO.MemoryStream]::new([byte[]](1, 2, 3))
    $failedStream.Dispose()
    try {{ Invoke-BoundedArtifactStreamScan -Stream $failedStream -ExpectedLength 3 -Scan $failedScan }} catch {{ $readFailureRejected = $true }}
    if (-not $readFailureRejected) {{ throw 'artifact read failure was accepted' }}
    Write-Output 'artifact byte fixture accepted'
}} finally {{
    if (Test-Path -LiteralPath $root) {{ Remove-Item -LiteralPath $root -Recurse -Force }}
}}
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "artifact byte fixture accepted" in result.stdout


def test_ac4_artifact_scanner_mutations_are_rejected() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    scanner = source[source.index("function Test-BytePatternInWindow") : source.index("function Invoke-DirectUninstall")]
    assert "$artifact.Length -gt $MaxArtifactBytes" in scanner
    assert "if (-not (Test-Path -LiteralPath $Root -PathType Container -ErrorAction SilentlyContinue))" in scanner
    assert "$Scan.Complete = $true" in scanner
    assert "[Text.Encoding]::ASCII.GetBytes($Sentinel)" in scanner
    assert "[Text.Encoding]::Unicode.GetBytes($Sentinel)" in scanner
    assert "[Text.Encoding]::BigEndianUnicode.GetBytes($Sentinel)" in scanner
    mutations = (
        scanner.replace("[Text.Encoding]::ASCII.GetBytes($Sentinel)", "[Text.Encoding]::Unicode.GetBytes($Sentinel)", 1),
        scanner.replace("[Text.Encoding]::Unicode.GetBytes($Sentinel)", "[Text.Encoding]::UTF8.GetBytes($Sentinel)", 1),
        scanner.replace("[Text.Encoding]::BigEndianUnicode.GetBytes($Sentinel)", "[Text.Encoding]::UTF8.GetBytes($Sentinel)", 1),
        scanner.replace("$Scan.Complete = $true", "$Scan.Complete = $false", 1),
        scanner.replace("if (-not [bool]$scan.Complete)", "if ($false)", 1),
        scanner.replace("if ($scan.Found)", "if ($false)", 1),
    )
    required = ("Test-BytePatternInWindow", "Write-ByteSentinelScan", "Invoke-BoundedArtifactStreamScan", "Assert-NoSentinelInArtifact")
    mutation_cases = (
        ("ascii", "byte-boundary-sentinel", "[Text.Encoding]::ASCII.GetBytes($sentinel)", 65537),
        ("utf16le", "byte-boundary-π-sentinel", "[Text.Encoding]::Unicode.GetBytes($sentinel)", 65537),
        ("utf16be", "byte-boundary-π-sentinel", "[Text.Encoding]::BigEndianUnicode.GetBytes($sentinel)", 65537),
        ("complete", "byte-boundary-sentinel", "[Text.Encoding]::ASCII.GetBytes($sentinel)", 65537),
        ("complete-guard", "byte-boundary-sentinel", "[Text.Encoding]::ASCII.GetBytes($sentinel)", 65537),
        ("hit-guard", "byte-boundary-sentinel", "[Text.Encoding]::ASCII.GetBytes($sentinel)", 65537),
    )
    for index, (_label, sentinel, encoded_expression, max_bytes) in enumerate(mutation_cases):
        mutation = mutations[index]
        assert mutation != scanner or index == 0
        helpers = "\n".join(
            _powershell_function(mutation, name) for name in required
        )
        artifact_setup = (
            "$bytes = [byte[]]::new(65530 + $encoded.Length + 5)\n"
            "[Array]::Copy($encoded, 0, $bytes, 65530, $encoded.Length)"
            if index < 3
            else "$bytes = [Text.Encoding]::UTF8.GetBytes(('q' * 65537))"
        )
        root_setup = "" if index != 4 else "$root = Join-Path $root 'missing'"
        artifact_write = "[IO.File]::WriteAllBytes((Join-Path $root 'artifact'), $bytes)" if index != 4 else ""
        scan_call = "" if index != 5 else "\n    $scan = @{ Patterns = @([Text.Encoding]::ASCII.GetBytes($sentinel)); MaxTailLength = 32; Tail = [byte[]]::new(0); Found = $false; Complete = $false }\n    $stream = [IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes($sentinel))\n    Invoke-BoundedArtifactStreamScan -Stream $stream -ExpectedLength $stream.Length -Scan $scan\n    $stream.Dispose()\n    if (-not $scan.Found) { throw 'artifact mutation accepted' }\n    Write-Output 'mutation rejected'\n    return\n"
        fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$root = Join-Path ([IO.Path]::GetTempPath()) ('ac4-artifact-mutation-' + [Guid]::NewGuid().ToString('N'))
try {{
    [IO.Directory]::CreateDirectory($root) | Out-Null
    {root_setup}
    $sentinel = '{sentinel}'
    $encoded = {encoded_expression}
    {artifact_setup}
    {artifact_write}
    {scan_call}
    $rejected = $false
    try {{ Assert-NoSentinelInArtifact -Root $root -Sentinel $sentinel -MaxArtifactBytes {max_bytes} }} catch {{ $rejected = $true }}
    if (-not $rejected) {{ throw 'artifact mutation accepted' }}
    Write-Output 'mutation rejected'
}} finally {{ if (Test-Path -LiteralPath $root) {{ Remove-Item -LiteralPath $root -Recurse -Force }} }}
"""
        result = _run_powershell_fixture(fixture)
        assert result.returncode == 0, f"artifact mutation {index} was accepted: {result.stdout} {result.stderr}"
        assert "mutation rejected" in result.stdout


def _loopback_behavioral_fixture() -> str:
    return r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_LOOPBACK_MODULE -Force
$sentinel = 'fixture-only-sentinel'
$fixture = $null
try {
    $fixture = Start-SnipeItLoopbackFixture -AuthorizationSentinel $sentinel
    if ($fixture.State.Ready) { throw 'fixture published readiness before listener setup' }
    $fixture.State.TestReadyGate = $true
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not $fixture.State.Ready -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 20 }
    if (-not $fixture.State.Ready -or $null -eq $fixture.State.Listener -or -not $fixture.State.Listener.IsListening) { throw 'fixture did not become ready after receive capability' }
    $client = [Net.Http.HttpClient]::new()
    try {
        $authorized = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $sentinel)
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, ([string]$fixture.Prefix) + 'api/v1/manufacturers?search=Maker&limit=100&offset=0')
        $request.Headers.Authorization = $authorized
        $response = $client.Send($request)
        if ($response.StatusCode -ne 200) { throw 'valid taxonomy query was rejected' }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, ([string]$fixture.Prefix) + 'api/v1/models?search=Model&limit=100&offset=100&offset=101')
        $request.Headers.Authorization = $authorized
        $response = $client.Send($request)
        if ([int]$response.StatusCode -ne 404) { throw 'duplicate query key was accepted' }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, ([string]$fixture.Prefix) + 'api/v1/hardware/byserial/SERIAL/extra')
        $request.Headers.Authorization = $authorized
        $response = $client.Send($request)
        if ([int]$response.StatusCode -ne 404) { throw 'malformed route was accepted' }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, ([string]$fixture.Prefix) + 'api/v1/unknown?search=Maker&limit=100&offset=0')
        $request.Headers.Authorization = $authorized
        $response = $client.Send($request)
        if ([int]$response.StatusCode -ne 404) { throw 'unexpected route was accepted' }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post, ([string]$fixture.Prefix) + 'api/v1/manufacturers?search=Maker&limit=100&offset=0')
        $request.Headers.Authorization = $authorized
        $response = $client.Send($request)
        if ([int]$response.StatusCode -ne 405) { throw 'mutation request was accepted' }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, ([string]$fixture.Prefix) + 'api/v1/hardware/byserial/SERIAL')
        $response = $client.Send($request)
        if ([int]$response.StatusCode -ne 401) { throw 'unauthorized request was accepted' }
    } finally { $client.Dispose() }
    $evidence = Get-SnipeItLoopbackEvidence -Fixture $fixture
    if (@($evidence.Requests | Where-Object { $_.route -eq 'unexpected' }).Count -lt 3) { throw 'unexpected route evidence was not recorded' }
    if (@($evidence.Requests | Where-Object { $_.query_valid -eq $false }).Count -lt 1) { throw 'invalid query evidence was not recorded' }
    if (@($evidence.Requests | Where-Object { $_.accepted -and -not $_.authorized }).Count -ne 0) { throw 'unauthorized evidence was accepted' }
    Write-Output 'loopback behavioral fixture accepted'
} finally {
    if ($null -ne $fixture) { Stop-SnipeItLoopbackFixture -Fixture $fixture -TimeoutSeconds 5 }
}
'''


def _test_gated_loopback_module(source: str) -> str:
    state_marker = "        BindAttempts = 0\n"
    publication_marker = "            $state.Ready = $true\n"
    assert state_marker in source
    gated_source = source.replace(
        state_marker,
        state_marker + "        TestReadyGate = $false\n",
        1,
    )
    if publication_marker in gated_source:
        gated_source = gated_source.replace(
            publication_marker,
            "            while (-not $state.TestReadyGate -and -not $state.StopRequested) { Start-Sleep -Milliseconds 10 }\n"
            + publication_marker,
            1,
        )
    return gated_source


def _run_loopback_fixture(module_source: str, fixture: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="ac4-loopback-") as module_directory:
        module_path = Path(module_directory) / "SnipeItLoopback.psm1"
        module_path.write_text(_test_gated_loopback_module(module_source), encoding="utf-8")
        return _run_powershell_fixture(
            fixture,
            os.environ | {"SPOTTER_LOOPBACK_MODULE": str(module_path)},
            timeout_seconds=20,
        )


def test_ac4_loopback_fixture_behaviorally_validates_routes_queries_and_readiness() -> None:
    result = _run_loopback_fixture(LOOPBACK.read_text(encoding="utf-8"), _loopback_behavioral_fixture())
    assert result.returncode == 0
    assert "loopback behavioral fixture accepted" in result.stdout


def test_ac4_loopback_mutations_remove_required_safety_contracts() -> None:
    source = LOOPBACK.read_text(encoding="utf-8")
    for expected, replacement in (
        ("Ready = $false", "Ready = $true"),
        ("$state.Ready = $true", "$state.Ready = $false"),
        ("query_valid = [bool]$queryValid", "query_valid = $true"),
        ("route = 'unexpected'", "route = 'manufacturers'"),
        ("$method -ne 'GET'", "$false"),
    ):
        assert expected in source
        mutation = source.replace(expected, replacement, 1)
        assert mutation != source
        result = _run_loopback_fixture(mutation, _loopback_behavioral_fixture())
        assert result.returncode != 0


def test_ac4_ciphertext_validation_is_structural_canonical_and_private() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    assert "function Assert-EncryptedTokenSetting" in source
    helper = _powershell_function(source, "Assert-EncryptedTokenSetting")
    assert "Write-Output $encoded" not in helper
    assert "Write-Output $SettingsText" not in helper
    assert "Write-Host" not in helper
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helper}
$prefix = [byte[]](1, 0, 0, 0, 0xd0, 0x8c, 0x9d, 0xdf, 1, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0, 0xc0, 0x4f, 0xc2, 0x97, 0xeb)
$blob = [byte[]]::new(48)
[Array]::Copy($prefix, $blob, $prefix.Length)
$canonical = [Convert]::ToBase64String($blob)
$valid = "[snipeit]`napi_token_encrypted = `"$canonical`"`n"
Assert-EncryptedTokenSetting -SettingsText $valid
$headerMutationOffsets = @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)
foreach ($offset in $headerMutationOffsets) {{
    $mutatedBlob = [byte[]]::new($blob.Length)
    [Array]::Copy($blob, $mutatedBlob, $blob.Length)
    $mutatedBlob[$offset] = [byte](($mutatedBlob[$offset] + 1) % 256)
    $mutatedEncoded = [Convert]::ToBase64String($mutatedBlob)
    $mutatedText = "[snipeit]`napi_token_encrypted = `"$mutatedEncoded`"`n"
    $accepted = $false
    try {{ Assert-EncryptedTokenSetting -SettingsText $mutatedText; $accepted = $true }} catch {{ }}
    if ($accepted) {{ throw "DPAPI header mutation at offset $offset was accepted" }}
}}
$noncanonicalBlob = [byte[]]::new(47)
[Array]::Copy($prefix, $noncanonicalBlob, $prefix.Length)
$noncanonicalCanonical = [Convert]::ToBase64String($noncanonicalBlob)
$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
$noncanonicalIndex = $noncanonicalCanonical.Length - 2
$noncanonicalValue = $alphabet.IndexOf([string]$noncanonicalCanonical[$noncanonicalIndex])
$noncanonical = $noncanonicalCanonical.Substring(0, $noncanonicalIndex) + $alphabet[($noncanonicalValue + 1)] + $noncanonicalCanonical.Substring($noncanonicalIndex + 1)
$empty = "[snipeit]`napi_token_encrypted = `"`"`n"
$invalidBase64 = "[snipeit]`napi_token_encrypted = `"not-base64`"`n"
$noncanonicalText = "[snipeit]`napi_token_encrypted = `"$noncanonical`"`n"
$tooShort = "[snipeit]`napi_token_encrypted = `"$([Convert]::ToBase64String([byte[]]::new(31)))`"`n"
$wrongKey = "[snipeit]`napi_token = `"$canonical`"`n"
$wrongSection = "[other]`napi_token_encrypted = `"$canonical`"`n"
$plaintext = "[snipeit]`napi_token_encrypted = `"plaintext-token-sentinel`"`n"
function Assert-InvalidCiphertextFixture {{
    param([Parameter(Mandatory = $true)][string]$Text)
    $accepted = $false
    try {{ Assert-EncryptedTokenSetting -SettingsText $Text; $accepted = $true }} catch {{ }}
    if ($accepted) {{ throw 'invalid ciphertext fixture was accepted' }}
}}
Assert-InvalidCiphertextFixture -Text $empty
Assert-InvalidCiphertextFixture -Text $invalidBase64
Assert-InvalidCiphertextFixture -Text $noncanonicalText
Assert-InvalidCiphertextFixture -Text $tooShort
Assert-InvalidCiphertextFixture -Text $wrongKey
Assert-InvalidCiphertextFixture -Text $wrongSection
Assert-InvalidCiphertextFixture -Text $plaintext
Write-Output 'ciphertext fixture accepted'
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "ciphertext fixture accepted" in result.stdout


def test_ac4_ciphertext_mutations_are_rejected() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper = _powershell_function(source, "Assert-EncryptedTokenSetting")
    prefix_setup = """
$prefix = [byte[]](1, 0, 0, 0, 0xd0, 0x8c, 0x9d, 0xdf, 1, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0, 0xc0, 0x4f, 0xc2, 0x97, 0xeb)
$blob = [byte[]]::new(48)
[Array]::Copy($prefix, $blob, $prefix.Length)
"""
    cases = (
        (
            "canonical",
            helper.replace("$canonical -cne $encoded", "$false", 1),
            prefix_setup
            + """
$shortBlob = [byte[]]::new(47)
[Array]::Copy($prefix, $shortBlob, $prefix.Length)
$canonical = [Convert]::ToBase64String($shortBlob)
$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
$index = $canonical.Length - 2
$value = $alphabet.IndexOf([string]$canonical[$index])
$encoded = $canonical.Substring(0, $index) + $alphabet[($value + 1)] + $canonical.Substring($index + 1)
$text = "[snipeit]`napi_token_encrypted = `"$encoded`"`n"
""",
        ),
        (
            "length",
            helper.replace("$bytes.Length -lt 32", "$bytes.Length -lt 1", 1),
            prefix_setup
            + """
$shortBlob = [byte[]]::new(31)
[Array]::Copy($prefix, $shortBlob, $prefix.Length)
$encoded = [Convert]::ToBase64String($shortBlob)
$text = "[snipeit]`napi_token_encrypted = `"$encoded`"`n"
""",
        ),
    )
    for label, mutation, setup in cases:
        assert mutation != helper
        fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{mutation}
{setup}
$accepted = $false
try {{ Assert-EncryptedTokenSetting -SettingsText $text; $accepted = $true }} catch {{ }}
if ($accepted) {{ throw 'ciphertext validation mutation was accepted' }}
Write-Output 'ciphertext mutation rejected'
"""
        result = _run_powershell_fixture(fixture)
        assert result.returncode != 0, f"ciphertext mutation {label} was accepted"
        assert "ciphertext validation mutation was accepted" in result.stderr

    header_mutation_target = "if ($bytes[$index] -ne $expectedHeader[$index]) {"
    assert header_mutation_target in helper
    for offset in range(20):
        mutation = helper.replace(
            header_mutation_target,
            f"if ($index -ne {offset} -and $bytes[$index] -ne $expectedHeader[$index]) {{",
            1,
        )
        assert mutation != helper
        setup = prefix_setup + f"""
$blob[{offset}] = [byte](($blob[{offset}] + 1) % 256)
$encoded = [Convert]::ToBase64String($blob)
$text = "[snipeit]`napi_token_encrypted = `"$encoded`"`n"
"""
        fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{mutation}
{setup}
$accepted = $false
try {{ Assert-EncryptedTokenSetting -SettingsText $text; $accepted = $true }} catch {{ }}
if ($accepted) {{ throw 'ciphertext validation mutation was accepted' }}
Write-Output 'ciphertext mutation rejected'
"""
        result = _run_powershell_fixture(fixture)
        assert result.returncode != 0, f"ciphertext header mutation {offset} was accepted"
        assert "ciphertext validation mutation was accepted" in result.stderr


def test_ac4_caller_successfully_closes_stdin_without_strict_mode_cleanup_failure() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper_names = (
        "Assert-True",
        "Initialize-BoundedProcessCaptureType",
        "Sync-BoundedProcessCaptureState",
        "Write-BoundedProcessCaptureStream",
        "Complete-BoundedProcessCaptureStream",
        "Assert-BoundedProcessCaptureSafe",
        "Get-BoundedProcessCapture",
        "Get-BoundedRemainingMillisecond",
        "Invoke-BoundedProcessStop",
        "Wait-BoundedTask",
        "Invoke-BoundedStandardInput",
        "Invoke-BoundedProcessCaptureCleanup",
        "Invoke-BoundedProcessCleanup",
        "Wait-BoundedProcessOutput",
        "Invoke-TokenCli",
    )
    helpers = "\n".join(
        _powershell_function(source, name) for name in helper_names
    )
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$CliPath = (Get-Command pwsh).Source
$ProcessTimeoutSeconds = 10
$result = @(Invoke-TokenCli -Arguments @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '$inputText = [Console]::In.ReadToEnd(); if ($inputText -cne ''caller-fixture-token'') {{ exit 17 }}; Write-Output ''caller fixture accepted'''
) -Token 'caller-fixture-token' -Description 'caller-success')[-1]
if ($result.ExitCode -ne 0) {{
    throw 'caller success fixture returned an invalid result'
}}
Write-Output 'caller stdin success fixture accepted'
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "caller stdin success fixture accepted" in result.stdout


def test_ac4_caller_lifecycle_fixtures_cover_failures_and_descendants() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper_names = (
        "Assert-True",
        "Initialize-BoundedProcessCaptureType",
        "Sync-BoundedProcessCaptureState",
        "Write-BoundedProcessCaptureStream",
        "Complete-BoundedProcessCaptureStream",
        "Assert-BoundedProcessCaptureSafe",
        "Get-BoundedProcessCapture",
        "Get-BoundedRemainingMillisecond",
        "Invoke-BoundedProcessStop",
        "Wait-BoundedTask",
        "Invoke-BoundedStandardInput",
        "Invoke-BoundedProcessCleanup",
        "Wait-BoundedProcessOutput",
        "Invoke-DirectCli",
        "Invoke-TokenCli",
    )
    helpers = "\n".join(
        _powershell_function(source, name) for name in helper_names
    )
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$CliPath = (Get-Command pwsh).Source
$ProcessTimeoutSeconds = 1
$token = 'lifecycle-fixture-token'
$tokenSentinel = 'direct-fixture-sentinel'
function Invoke-CallerFixture {{
    param([bool]$TokenMode, [string[]]$ChildArguments)
    $caught = $null
    try {{
        if ($TokenMode) {{
            [void](Invoke-TokenCli -Arguments $ChildArguments -Token $token -Description 'fixture-token')
        }} else {{
            [void](Invoke-DirectCli -Arguments $ChildArguments -Description 'fixture-direct')
        }}
    }} catch {{ $caught = $_ }}
    if ($null -eq $caught) {{ throw 'caller fixture accepted a failure' }}
    if ($caught.Exception.Message -notmatch 'did not exit|cleanup failed|operation failed') {{ throw 'caller fixture returned an unsafe diagnostic' }}
}}
$expired = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[Threading.Thread]::Sleep(10000)')
Invoke-CallerFixture -TokenMode $false -ChildArguments $expired
Invoke-CallerFixture -TokenMode $true -ChildArguments $expired
$root = Join-Path ([IO.Path]::GetTempPath()) ('ac4-descendant-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$marker = Join-Path $root 'descendant.pid'
$descendantCommand = '$grandchild = Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList @(''-NoLogo'', ''-NoProfile'', ''-NonInteractive'', ''-Command'', ''[Threading.Thread]::Sleep(10000)'') -PassThru; [IO.File]::WriteAllText(''' + $marker.Replace('''', '''''') + ''', $grandchild.Id.ToString()); [Threading.Thread]::Sleep(10000)'
$descendant = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $descendantCommand)
Invoke-CallerFixture -TokenMode $false -ChildArguments $descendant
$markerDeadline = [DateTime]::UtcNow.AddSeconds(5)
while (-not (Test-Path -LiteralPath $marker) -and [DateTime]::UtcNow -lt $markerDeadline) {{ Start-Sleep -Milliseconds 20 }}
if (-not (Test-Path -LiteralPath $marker)) {{ throw 'descendant fixture did not publish its marker' }}
$grandchildId = [int][IO.File]::ReadAllText($marker)
$gone = $false
$goneDeadline = [DateTime]::UtcNow.AddSeconds(5)
while (-not $gone -and [DateTime]::UtcNow -lt $goneDeadline) {{
    try {{ $candidate = [Diagnostics.Process]::GetProcessById($grandchildId); $candidate.Dispose() }} catch [ArgumentException] {{ $gone = $true }} catch [InvalidOperationException] {{ $gone = $true }}
    if (-not $gone) {{ Start-Sleep -Milliseconds 20 }}
}}
if (-not $gone) {{ throw 'descendant process survived caller cleanup' }}
if (Test-Path -LiteralPath $root) {{ Remove-Item -LiteralPath $root -Recurse -Force }}
Write-Output 'caller failure and descendant fixtures accepted'
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "caller failure and descendant fixtures accepted" in result.stdout


def test_ac4_caller_stdin_failure_fixtures_are_bounded_and_cleanup_processes() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper_names = (
        "Assert-True",
        "Initialize-BoundedProcessCaptureType",
        "Sync-BoundedProcessCaptureState",
        "Write-BoundedProcessCaptureStream",
        "Complete-BoundedProcessCaptureStream",
        "Assert-BoundedProcessCaptureSafe",
        "Get-BoundedProcessCapture",
        "Get-BoundedRemainingMillisecond",
        "Invoke-BoundedProcessStop",
        "Wait-BoundedTask",
        "Invoke-BoundedStandardInput",
        "Invoke-BoundedProcessCaptureCleanup",
        "Invoke-BoundedProcessCleanup",
        "Wait-BoundedProcessOutput",
        "Invoke-TokenCli",
    )
    helper = _powershell_function(source, "Invoke-BoundedStandardInput")
    mutations = (
        ("write", "$writeTask = $Process.StandardInput.WriteAsync($Text)", "$writeTask = [Threading.Tasks.Task]::FromException([Exception]::new('fixture'))"),
        ("flush", "$flushTask = $Process.StandardInput.FlushAsync()", "$flushTask = [Threading.Tasks.Task]::FromException([Exception]::new('fixture'))"),
        ("close", "$closeTask = $closeValueTask.AsTask()", "$closeTask = [Threading.Tasks.Task]::FromException([Exception]::new('fixture'))"),
    )
    for label, expected, replacement in mutations:
        mutated_helper = helper.replace(expected, replacement, 1)
        assert mutated_helper != helper
        helpers = "\n".join(
            mutated_helper if name == "Invoke-BoundedStandardInput" else _powershell_function(source, name)
            for name in helper_names
        )
        fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
$CliPath = (Get-Command pwsh).Source
$ProcessTimeoutSeconds = 5
$marker = Join-Path ([IO.Path]::GetTempPath()) ('ac4-stdin-' + [Guid]::NewGuid().ToString('N'))
$childCommand = '[IO.File]::WriteAllText(''' + $marker.Replace('''', '''''') + ''', $PID.ToString()); [Threading.Thread]::Sleep(10000)'
$arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $childCommand)
try {{
    $startedAt = [DateTime]::UtcNow
    $caught = $null
    try {{ [void](Invoke-TokenCli -Arguments $arguments -Token 'stdin-fixture-token' -Description 'stdin-fixture') }} catch {{ $caught = $_ }}
    $elapsedMilliseconds = ([DateTime]::UtcNow - $startedAt).TotalMilliseconds
    if ($null -eq $caught -or $caught.Exception.Message -notmatch 'child stdin (write|flush|close) failed or exceeded') {{ throw 'stdin failure was not rejected with a fixed diagnostic' }}
    if ($elapsedMilliseconds -gt 5000) {{ throw 'stdin failure was not deadline bounded' }}
    if (Test-Path -LiteralPath $marker) {{
        $childId = [int][IO.File]::ReadAllText($marker)
        $gone = $false
        $goneDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not $gone -and [DateTime]::UtcNow -lt $goneDeadline) {{
            try {{ $candidate = [Diagnostics.Process]::GetProcessById($childId); $candidate.Dispose() }} catch [ArgumentException] {{ $gone = $true }} catch [InvalidOperationException] {{ $gone = $true }}
            if (-not $gone) {{ Start-Sleep -Milliseconds 20 }}
        }}
        if (-not $gone) {{ throw 'stdin failure left the child alive' }}
    }}
    Write-Output 'stdin {label} failure fixture accepted'
}} finally {{ if (Test-Path -LiteralPath $marker) {{ Remove-Item -LiteralPath $marker -Force }} }}
"""
        result = _run_powershell_fixture(fixture)
        assert result.returncode == 0, f"stdin {label} fixture failed: {result.stdout} {result.stderr}"
        assert f"stdin {label} failure fixture accepted" in result.stdout


def test_ac4_stdin_operation_and_cleanup_failures_are_combined_without_leaks() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helper_names = (
        "Get-BoundedRemainingMillisecond",
        "Invoke-BoundedProcessStop",
        "Wait-BoundedTask",
        "Invoke-BoundedStandardInput",
    )
    helper = _powershell_function(source, "Invoke-BoundedStandardInput")
    helpers = "\n".join(
        _powershell_function(source, name) for name in helper_names
    )
    mutations = (
        ("primary capture", "$stdinError = $_", "$stdinError = $null"),
        ("cleanup capture", "$stdinCleanupError = $_", "$stdinCleanupError = $null"),
        (
            "combined branch",
            "if ($stdinError -and $stdinCleanupError) { throw 'child stdin operation failed and cleanup failed' }",
            "if ($stdinError -and $stdinCleanupError) { throw 'child stdin operation failed' }",
        ),
    )

    def fixture_for(helper_set: str) -> str:
        return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helper_set}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
$info.RedirectStandardInput = $true
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-NonInteractive')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add('[Threading.Thread]::Sleep(10000)')
$p = [Diagnostics.Process]::new()
$p.StartInfo = $info
$token = 'stdin-combined-token-secret'
$operationSecret = 'stdin-operation-secret'
$cleanupSecret = 'stdin-cleanup-secret'
try {{
    if (-not $p.Start()) {{ throw 'child did not start' }}
    function Wait-BoundedTask {{ throw $operationSecret }}
    function Invoke-BoundedProcessStop {{ throw $cleanupSecret }}
    $caught = $null
    try {{
        Invoke-BoundedStandardInput -Process $p -Text $token -Deadline ([DateTime]::UtcNow.AddMilliseconds(-1))
    }} catch {{ $caught = $_ }}
    if ($null -eq $caught) {{ throw 'combined stdin failure was accepted' }}
    if ($caught.Exception.Message -cne 'child stdin operation failed and cleanup failed') {{ throw 'combined stdin diagnostic mismatch' }}
    foreach ($secret in @($token, $operationSecret, $cleanupSecret)) {{
        if ($caught.Exception.ToString().Contains($secret, [StringComparison]::Ordinal)) {{ throw 'combined stdin diagnostic leaked a secret' }}
    }}
    Write-Output 'combined stdin failure fixture accepted'
}} finally {{
    if (-not $p.HasExited) {{ try {{ $p.Kill($true); $p.WaitForExit(1000) }} catch {{ }} }}
    $p.Dispose()
}}
"""

    result = _run_powershell_fixture(fixture_for(helpers))
    assert result.returncode == 0, result.stderr or result.stdout
    assert "combined stdin failure fixture accepted" in result.stdout

    for label, expected, replacement in mutations:
        mutated_helper = helper.replace(expected, replacement, 1)
        assert mutated_helper != helper, f"missing stdin {label} mutation target"
        mutated_helpers = "\n".join(
            mutated_helper if name == "Invoke-BoundedStandardInput" else _powershell_function(source, name)
            for name in helper_names
        )
        mutated_result = _run_powershell_fixture(fixture_for(mutated_helpers))
        assert mutated_result.returncode != 0, f"stdin {label} mutation was accepted"


def _caller_lifecycle_fixture(
    caller: str,
    caller_name: str,
    token_mode: bool,
    scenario: str,
) -> str:
    helper_names = (
        "Assert-True",
        "Initialize-BoundedProcessCaptureType",
        "Sync-BoundedProcessCaptureState",
        "Write-BoundedProcessCaptureStream",
        "Complete-BoundedProcessCaptureStream",
        "Assert-BoundedProcessCaptureSafe",
        "Get-BoundedProcessCapture",
        "Get-BoundedRemainingMillisecond",
        "Invoke-BoundedProcessStop",
        "Wait-BoundedTask",
        "Invoke-BoundedStandardInput",
        "Invoke-BoundedProcessCaptureCleanup",
        "Invoke-BoundedProcessCleanup",
        "Wait-BoundedProcessOutput",
    )
    source = DIRECT_SCM.read_text(encoding="utf-8")
    helpers = "\n".join(
        _powershell_function(source, name) for name in helper_names
    )
    mode = "$true" if token_mode else "$false"
    caller_invocation = (
        "[void](Invoke-TokenCli -Arguments $arguments -Token $token -Description 'fixture-token')"
        if token_mode
        else "[void](Invoke-DirectCli -Arguments $arguments -Description 'fixture-direct')"
    )
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helpers}
{caller}
$CliPath = (Get-Command pwsh).Source
$ProcessTimeoutSeconds = 1
$token = 'fixture-token'
$tokenSentinel = 'fixture-token-sentinel'
$TokenMode = {mode}
$Scenario = '{scenario}'
$marker = Join-Path ([IO.Path]::GetTempPath()) ('ac4-caller-' + [Guid]::NewGuid().ToString('N'))
$escapedMarker = $marker.Replace("'", "''")
$childTail = if ($Scenario -eq 'timeout') {{ '[Threading.Thread]::Sleep(10000)' }} elseif ($Scenario -eq 'primary_failure') {{ 'exit 7' }} else {{ "Write-Output 'fixture-child'" }}
$childCommand = if ($TokenMode) {{
    "`$null = [Console]::In.ReadToEnd(); [IO.File]::WriteAllText('$escapedMarker', `$PID.ToString()); $childTail"
}} else {{
    "[IO.File]::WriteAllText('$escapedMarker', `$PID.ToString()); $childTail"
}}
$arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $childCommand)

function Wait-FixtureMarker {{
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    while (-not (Test-Path -LiteralPath $marker) -and [DateTime]::UtcNow -lt $deadline) {{
        Start-Sleep -Milliseconds 20
    }}
    return (Test-Path -LiteralPath $marker)
}}

function Test-FixtureProcessGone {{
    if (-not (Test-Path -LiteralPath $marker)) {{ return $false }}
    $childId = [int][IO.File]::ReadAllText($marker)
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    while ([DateTime]::UtcNow -lt $deadline) {{
        try {{
            $candidate = [Diagnostics.Process]::GetProcessById($childId)
            $candidate.Dispose()
        }} catch [ArgumentException] {{ return $true }} catch [InvalidOperationException] {{ return $true }}
        Start-Sleep -Milliseconds 20
    }}
    return $false
}}

if ($Scenario -eq 'cleanup_failure') {{
    function Invoke-BoundedProcessCleanup {{ throw 'fixture cleanup failure' }}
}}
if ($Scenario -eq 'start_failure') {{
    $CliPath = Join-Path ([IO.Path]::GetTempPath()) ('ac4-missing-' + [Guid]::NewGuid().ToString('N'))
}}

$caught = $null
try {{
    try {{ {caller_invocation} }} catch {{ $caught = $_ }}
    if ($Scenario -eq 'start_failure') {{
        if ($null -eq $caught) {{ throw 'start failure was accepted' }}
        if ($caught.Exception.Message -match 'cleanup failed|operation failed') {{ throw 'start failure cleanup state was not preserved' }}
    }} elseif ($Scenario -eq 'timeout') {{
        if ($null -eq $caught) {{ throw 'timeout failure was not reported safely' }}
        if (-not (Wait-FixtureMarker)) {{ throw 'timeout child did not publish its marker' }}
        if (-not (Test-FixtureProcessGone)) {{ throw 'caller did not clean the timeout child' }}
    }} elseif ($Scenario -eq 'primary_failure') {{
        if ($null -eq $caught) {{ throw 'primary failure was not reported safely' }}
    }} elseif ($Scenario -eq 'cleanup_failure') {{
        if ($null -eq $caught -or $caught.Exception.Message -notmatch '^child process (cleanup failed|operation failed and cleanup failed)$') {{ throw 'cleanup failure was not reported safely' }}
    }}
    Write-Output 'caller lifecycle mutation fixture accepted'
}} finally {{
    if (Test-Path -LiteralPath $marker) {{
        try {{
            $childId = [int][IO.File]::ReadAllText($marker)
            $candidate = [Diagnostics.Process]::GetProcessById($childId)
            if (-not $candidate.HasExited) {{ $candidate.Kill($true); $candidate.WaitForExit(1000) }}
            $candidate.Dispose()
        }} catch {{ }}
        Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    }}
}}
"""


def _process_stop_fixture(stop_helper: str) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{stop_helper}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-NonInteractive')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add('[Threading.Thread]::Sleep(10000)')
$p = [Diagnostics.Process]::new()
$p.StartInfo = $info
try {{
    if (-not $p.Start()) {{ throw 'child did not start' }}
    $caught = $null
    try {{ Invoke-BoundedProcessStop -Process $p -WaitMilliseconds 1000 }} catch {{ $caught = $_ }}
    if ($null -ne $caught -or -not $p.HasExited) {{ throw 'process stop contract was not satisfied' }}
    Write-Output 'process stop fixture accepted'
}} finally {{
    try {{ if (-not $p.HasExited) {{ $p.Kill($true); $p.WaitForExit(1000) }} }} catch {{ }}
    $p.Dispose()
}}
"""


def _process_cleanup_disposal_fixture(cleanup_helper: str) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System.Diagnostics;
public sealed class Ac4TrackingProcess : Process {{
    public static int DisposeCount;
    protected override void Dispose(bool disposing) {{ DisposeCount++; base.Dispose(disposing); }}
}}
'@
{cleanup_helper}
$p = [Ac4TrackingProcess]::new()
try {{
    Invoke-BoundedProcessCleanup -Process $p -Started $false
    if ([Ac4TrackingProcess]::DisposeCount -ne 1) {{ throw 'process disposal was skipped' }}
    Write-Output 'process disposal fixture accepted'
}} finally {{ try {{ $p.Dispose() }} catch {{ }} }}
"""


def test_ac4_caller_lifecycle_mutations_are_rejected() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    caller_specs = (
        ("Invoke-DirectCli", "Get-CommonCliArgument", False),
        ("Invoke-TokenCli", "Assert-NoSentinelInText", True),
    )
    caller_mutations = (
        ("missing started initialization", "$started = $false", "", "start_failure"),
        ("moved started publication", "$started = $true", "$started = $false", "timeout"),
        (
            "bypassed cleanup",
            "Invoke-BoundedProcessCaptureCleanup -Process $process -Handlers $handlers\n        } catch {\n            $cleanupError = $_\n        }\n        try {\n            Invoke-BoundedProcessCleanup -Process $process -Started $started",
            "",
            "timeout",
        ),
        ("primary branch bypass", "if ($primaryError) { throw $primaryError }", "", "primary_failure"),
        (
            "cleanup branch bypass",
            "if ($cleanupError) { throw 'child process cleanup failed' }",
            "",
            "cleanup_failure",
        ),
    )

    for caller_name, next_name, token_mode in caller_specs:
        caller = source[source.index(f"function {caller_name}") : source.index(f"function {next_name}")]
        for _scenario in ("start_failure", "timeout", "cleanup_failure"):
            baseline = _run_powershell_fixture(
                _caller_lifecycle_fixture(caller, caller_name, token_mode, _scenario),
                timeout_seconds=15,
            )
            assert baseline.returncode == 0
            assert "caller lifecycle mutation fixture accepted" in baseline.stdout
        for label, expected, replacement, scenario in caller_mutations:
            assert expected in caller, f"missing caller mutation target: {caller_name} {label}"
            mutation = caller.replace(expected, replacement, 1)
            assert mutation != caller
            result = _run_powershell_fixture(
                _caller_lifecycle_fixture(mutation, caller_name, token_mode, scenario),
                timeout_seconds=15,
            )
            assert result.returncode != 0, f"caller mutation was accepted: {caller_name} {label}"

    stop = _powershell_function(source, "Invoke-BoundedProcessStop")
    for label, expected, replacement in (
        ("Kill", "$Process.Kill($true)", "$null = $Process.HasExited"),
        ("WaitForExit", "$Process.WaitForExit($WaitMilliseconds)", "$false"),
        ("final HasExited", "if (-not $Process.HasExited)", "if ($true)"),
    ):
        assert expected in stop, f"missing process stop mutation target: {label}"
        mutation = stop.replace(expected, replacement, 1)
        result = _run_powershell_fixture(_process_stop_fixture(mutation), timeout_seconds=15)
        assert result.returncode != 0, f"process stop mutation was accepted: {label}"

    cleanup = _powershell_function(source, "Invoke-BoundedProcessCleanup")
    expected = "$Process.Dispose()"
    assert expected in cleanup
    mutation = cleanup.replace(expected, "$null = $Process.HasExited", 1)
    result = _run_powershell_fixture(
        _process_cleanup_disposal_fixture(mutation),
        timeout_seconds=15,
    )
    assert result.returncode != 0, "process disposal mutation was accepted"



def test_ac4_timeout_cleanup_kills_child_and_requires_exit() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    assert "function Invoke-BoundedProcessStop" in source
    helper = _powershell_function(source, "Invoke-BoundedProcessStop")
    fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{helper}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add("Write-Output 'ready'; [Console]::Out.Flush(); [Threading.Thread]::Sleep(10000)")
$p = [Diagnostics.Process]::new()
$p.StartInfo = $info
try {{
    if (-not $p.Start()) {{ throw 'child did not start' }}
    if ($p.StandardOutput.ReadLine() -ne 'ready') {{ throw 'child was not ready' }}
    $started = [DateTime]::UtcNow
    Invoke-BoundedProcessStop -Process $p -WaitMilliseconds 1000
    $elapsed = ([DateTime]::UtcNow - $started).TotalMilliseconds
    if (-not $p.HasExited) {{ throw 'child remained alive after bounded cleanup' }}
    if ($elapsed -gt 3000) {{ throw 'termination wait was not bounded' }}
    Write-Output 'timeout cleanup fixture accepted'
}} finally {{
    if (-not $p.HasExited) {{ try {{ $p.Kill($true) }} catch {{ }} }}
    $p.Dispose()
}}
"""
    result = _run_powershell_fixture(fixture)
    assert result.returncode == 0, result.stderr or result.stdout
    assert "timeout cleanup fixture accepted" in result.stdout


def test_ac4_timeout_contract_is_deadline_bounded_and_mutation_aware() -> None:
    source = DIRECT_SCM.read_text(encoding="utf-8")
    invoke = source[source.index("function Invoke-DirectCli") : source.index("function Get-CommonCliArgument")]
    token_invoke = source[source.index("function Invoke-TokenCli") : source.index("function Assert-NoSentinelInText")]
    for text in (invoke, token_invoke):
        assert "$deadline = [DateTime]::UtcNow.AddSeconds($ProcessTimeoutSeconds)" in text
        assert "Wait-BoundedProcessOutput -Process $process -Deadline $deadline" in text
        assert "Invoke-BoundedProcessCleanup -Process $process -Started $started" in text
    assert "Invoke-BoundedStandardInput -Process $process -Text $Token -Deadline $deadline" in token_invoke
    cleanup = _powershell_function(source, "Invoke-BoundedProcessCleanup")
    for required in ("Invoke-BoundedProcessStop -Process $Process -WaitMilliseconds 5000", "$Process.Dispose()"):
        assert required in cleanup
    stop = _powershell_function(source, "Invoke-BoundedProcessStop")
    for required in ("$Process.Kill($true)", "$Process.WaitForExit($WaitMilliseconds)", "if (-not $Process.HasExited)"):
        assert required in stop
    assert "WriteAsync($Text)" in source
    assert "FlushAsync()" in source
    assert "DisposeAsync()" in source
    assert "StandardInput.Close()" not in source
    assert "$closeTask.Wait($remainingMilliseconds)" not in source
    stop = _powershell_function(source, "Invoke-BoundedProcessStop")
    for expected, replacement in (
        ("$Process.Kill($true)", "$null = $Process.HasExited"),
        ("$Process.WaitForExit($WaitMilliseconds)", "$false"),
    ):
        mutation = stop.replace(expected, replacement, 1)
        assert mutation != stop
        remaining = _powershell_function(source, "Get-BoundedRemainingMillisecond")
        fixture = f"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
{remaining}
{mutation}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Get-Command pwsh).Source
$info.UseShellExecute = $false
$info.RedirectStandardOutput = $true
[void]$info.ArgumentList.Add('-NoLogo')
[void]$info.ArgumentList.Add('-NoProfile')
[void]$info.ArgumentList.Add('-Command')
[void]$info.ArgumentList.Add("Write-Output 'ready'; [Console]::Out.Flush(); [Threading.Thread]::Sleep(10000)")
$p = [Diagnostics.Process]::new(); $p.StartInfo = $info
try {{
    if (-not $p.Start()) {{ throw 'child did not start' }}
    $ready = $p.StandardOutput.ReadLine()
    if ($ready -ne 'ready') {{ throw 'child was not ready' }}
    $rejected = $false
    try {{ Invoke-BoundedProcessStop -Process $p -WaitMilliseconds 100 }} catch {{ $rejected = $true }}
    $survived = -not $p.HasExited
    if (-not $rejected -and -not $survived) {{ throw 'timeout mutation was accepted' }}
    Write-Output 'timeout mutation rejected'
}} finally {{ if (-not $p.HasExited) {{ try {{ $p.Kill($true); $p.WaitForExit(1000) }} catch {{ }} }}; $p.Dispose() }}
"""
        result = _run_powershell_fixture(fixture)
        assert result.returncode == 0, f"timeout mutation accepted: {result.stdout} {result.stderr}"
        assert "timeout mutation rejected" in result.stdout


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
        "SnipeItLoopback.psm1",
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


def _assert_standard_user_acl_probe_transport_contract(module: str) -> None:
    helper = module[module.index("function Assert-StandardUserCannotReadWrite") :]
    assert "-EncodedCommand" not in helper
    for required in (
        "[Guid]::NewGuid().ToString('N')",
        "$temporaryRoot = Join-Path $env:SystemRoot 'Temp'",
        "artifact collision",
        "CreateNew",
        "FileShare]::None",
        "DirectorySecurity",
        "[Security.AccessControl.FileSecurity]::new()",
        "InheritanceFlags]::None",
        "SetAccessRuleProtection($true, $false)",
        "S-1-5-18",
        "S-1-5-32-544",
        "SecurityIdentifier",
        "ReadAndExecute",
        "SetAccessControl",
        "GetBytes($probe)",
        "-File",
        "$Path",
        "$PathType",
        "commandLine.Length",
        "-ge 1024",
        "finally",
        "Remove-Item -LiteralPath $probeDirectory -Recurse -Force -ErrorAction Stop",
        "throw 'standard-user ACL probe cleanup failed'",
    ):
        assert required in helper, f"standard-user ACL probe is missing {required!r}"
    assert "ConvertTo-SecureString" not in helper
    assert "ProgramData" not in helper
    assert "$inheritChildren" not in helper
    assert "throw \"standard-user ACL probe" not in helper
    assert "throw \"ACL target does not exist" not in helper
    assert "throw \"standard-user executable" not in helper
    assert helper.count("$userSid,") == 2
    assert helper.count("$userSid,\n                $readAndExecute,") == 2
    assert helper.count("$userSid,\n                $fullControl") == 0
    assert helper.count("$commandArguments = @(\n            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $probePath, $Path, $PathType\n        )") == 1
    assert helper.count("SetAccessRuleProtection($true, $false)") == 2
    protection_calls = [match.start() for match in re.finditer("SetAccessRuleProtection\\(\\$true, \\$false\\)", helper)]
    assert protection_calls[0] > helper.index("DirectorySecurity")
    assert protection_calls[0] < helper.index("FileSecurity")
    assert protection_calls[1] > helper.index("FileSecurity")
    cleanup_start = helper.rindex("    } finally {")
    setup_start = helper.index("    try {", helper.index("$probePath"))
    launch_start = helper.index("$result = Invoke-AsStandardUser")
    assert helper.index("$probeDirectory") < launch_start
    assert launch_start < cleanup_start
    assert helper.index("$Path, $PathType") < launch_start
    assert "$temporaryRoot = Join-Path $env:SystemRoot 'Temp'" in helper
    assert "$probeDirectory = Join-Path $temporaryRoot" in helper
    assert helper.index("[Guid]::NewGuid().ToString('N')") < helper.index("$probeDirectory = Join-Path $temporaryRoot")
    assert helper.index("$probePath = Join-Path $probeDirectory") < helper.index("CreateNew")
    assert helper.index("CreateNew") < helper.index("SetAccessControl")
    assert helper.index("SetAccessControl") < launch_start
    assert helper.index("throw 'standard-user ACL probe setup failed'") > setup_start
    assert helper.index("throw 'standard-user ACL probe setup failed'") < launch_start
    assert helper.index("Remove-Item -LiteralPath $probeDirectory") > cleanup_start


def test_standard_user_acl_probe_uses_bounded_secure_script_transport() -> None:
    _assert_standard_user_acl_probe_transport_contract(read_module("Security.psm1"))


def test_standard_user_acl_probe_uses_acl_aware_creation_and_acl_apis() -> None:
    helper = read_module("Security.psm1").split(
        "function Assert-StandardUserCannotReadWrite", 1
    )[1]
    assert (
        "[IO.Directory]::CreateDirectory($probeDirectory, $directorySecurity)"
        not in helper
    )
    assert "[IO.File]::SetAccessControl($probePath, $fileSecurity)" not in helper
    assert (
        "[IO.FileSystemAclExtensions]::CreateDirectory($directorySecurity, $probeDirectory)"
        in helper
    )
    assert (
        "[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($probePath), $fileSecurity)"
        in helper
    )


def test_standard_user_acl_probe_regresses_the_oversized_encoded_transport() -> None:
    module = read_module("Security.psm1")
    probe_start = module.index("$probe = @'") + len("$probe = @'\n")
    probe_end = module.index("\n'@", probe_start)
    probe = module[probe_start:probe_end]
    encoded_length = len(base64.b64encode(probe.encode("utf-16-le")).decode("ascii"))
    assert encoded_length > 1024
    helper = module[module.index("function Assert-StandardUserCannotReadWrite") :]
    assert "-EncodedCommand" not in helper
    command_section = helper[helper.index("$commandArguments") : helper.index("$result = Invoke-AsStandardUser")]
    assert re.search(r"(?<![A-Za-z])\$probe(?![A-Za-z])", command_section) is None
    assert "$probePath" in command_section
    assert "$Path" in command_section
    assert "$PathType" in helper[helper.index("$commandArguments") : helper.index("$result = Invoke-AsStandardUser")]


def test_standard_user_acl_probe_transport_contract_rejects_unsafe_mutations() -> None:
    module = read_module("Security.psm1")
    helper_start = module.index("function Assert-StandardUserCannotReadWrite")
    helper = module[helper_start:]
    cleanup_start = helper.rindex("    } finally {")
    cleanup = helper[cleanup_start:]
    mutations = (
        ("-File", "-EncodedCommand", helper),
        ("[Guid]::NewGuid().ToString('N')", "'fixed-probe'", helper),
        ("SetAccessRuleProtection($true, $false)", "SetAccessRuleProtection($false, $true)", helper[: helper.index("$fileSecurity")]),
        ("SetAccessRuleProtection($true, $false)", "SetAccessRuleProtection($false, $true)", helper[helper.index("$fileSecurity") :]),
        ("$userSid,\n                $readAndExecute,", "$userSid,\n                $userSidRights,", helper),
        ("-ge 1024", "-lt 1024", helper),
        ("    } finally {", "    }", cleanup),
        ("Remove-Item -LiteralPath $probeDirectory", "Write-Output 'cleanup'", cleanup),
    )
    for expected, replacement, source in mutations:
        assert expected in source
        mutation = source.replace(expected, replacement, 1)
        assert replacement in mutation
        mutated_module = module[:helper_start] + "function Assert-StandardUserCannotReadWrite" + mutation[len("function Assert-StandardUserCannotReadWrite") :]
        try:
            _assert_standard_user_acl_probe_transport_contract(mutated_module)
        except AssertionError:
            continue
        raise AssertionError(f"standard-user ACL probe transport mutation was accepted: {expected}")


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
        "native_probe_stage": "$NativeProbeStage",
        "native_probe_rejection": "$NativeProbeRejection",
    }
    assert "if ($bytes.Length -gt 8192)" in projection
    assert "ConvertTo-Json -Compress -Depth 3" in projection
    assert "[Text.Encoding]::UTF8" in projection
    assert "New-Object byte[]" not in projection
    assert "Exception.Message" not in projection
    assert "InnerException" in projection
    assert "native_probe = $NativeProbe" in projection
    assert "native_probe_stage = $NativeProbeStage" in projection
    assert "native_probe_rejection = $NativeProbeRejection" in projection
    native_probe_stage_match = re.search(
        r"\[ValidateSet\((?P<stages>'(?:[^']|'')+'(?:\s*,\s*'(?:[^']|'')+')*)\)\]\[string\]\$NativeProbeStage",
        projection,
    )
    assert native_probe_stage_match is not None
    assert tuple(re.findall(r"'([^']+)'", native_probe_stage_match.group("stages"))) == _CREDENTIAL_LAUNCH_PROBE_STAGES
    assert "terminate_wait" not in projection
    assert "if ($LaunchStage -ne 'native_start')" in projection
    assert ".Remove('native_probe')" in projection
    assert ".Remove('native_probe_stage')" in projection
    assert ".Remove('native_probe_rejection')" in projection
    native_probe_rejection_match = re.search(
        r"\[ValidateSet\((?P<rejections>'(?:[^']|'')+'(?:\s*,\s*'(?:[^']|'')+')*)\)\]\[string\]\$NativeProbeRejection",
        projection,
    )
    assert native_probe_rejection_match is not None
    assert tuple(re.findall(r"'([^']+)'", native_probe_rejection_match.group("rejections"))) == _CREDENTIAL_LAUNCH_PROBE_REJECTIONS


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
    assert "native_probe_stage = $User" not in projection
    assert "native_probe_stage = @{" not in projection
    assert "native_probe_rejection = $User" not in projection
    assert "native_probe_rejection = @{" not in projection
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
        r"(?:(?!\$nativeProbe(?!Stage)).)*?\$nativeProbe\s*=\s*'probe_unavailable'\s*"
        r"(?:(?!\bcatch\b).)*?try\s*\{",
        catch,
        re.DOTALL,
    )
    assert catch.count("$nativeStartErrorRecord = $_") == 1
    assert catch.count("-ErrorRecord $nativeStartErrorRecord") == 1
    assert "-ErrorRecord $_" not in catch


def _assert_native_probe_rejection_capture_contract(source: str) -> None:
    catch_start, catch_end = _credential_launch_catch_spans(source)[2]
    catch = source[catch_start:catch_end]
    assert "$nativeProbeRejection = 'none'" in catch
    assert "-Rejection ([ref]$nativeProbeRejection)" in catch
    assert "-NativeProbeRejection $nativeProbeRejection" in catch
    assert catch.index("$nativeProbeRejection = 'none'") < catch.index("ConvertTo-CredentialLaunchProbeEvidence")
    assert catch.index("ConvertTo-CredentialLaunchProbeEvidence") < catch.index("-NativeProbeRejection $nativeProbeRejection")
    assert "catch { $nativeProbe = 'probe_unavailable' }" in catch
    assert "catch { $nativeProbeRejection = $_.Exception.Message }" not in catch


def test_credentialed_native_start_capture_preserves_rejection_discriminator() -> None:
    module = read_module("Security.psm1")
    _assert_native_probe_rejection_capture_contract(module)
    invoke_start = module.index("function Invoke-AsStandardUser")
    invoke_end = module.index("function Assert-StandardUserCannotReadWrite", invoke_start)
    invoke = module[invoke_start:invoke_end]
    for mutation in (
        invoke.replace("$nativeProbeRejection = 'none'", "$discardedRejection = 'none'", 1),
        invoke.replace("-Rejection ([ref]$nativeProbeRejection)", "-Rejection ([ref]$discardedRejection)", 1),
        invoke.replace("-NativeProbeRejection $nativeProbeRejection", "-NativeProbeRejection $discardedRejection", 1),
    ):
        try:
            _assert_native_probe_rejection_capture_contract(module[:invoke_start] + mutation + module[invoke_end:])
        except (AssertionError, ValueError):
            continue
        raise AssertionError("native-start rejection capture mutation was accepted")


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
    assert "[ref]$Stage" in helper
    assert "ConvertFrom-Json" in helper
    assert "[Text.Encoding]::UTF8.GetBytes($ProbeJson)" in helper
    assert "if ($bytes.Length -gt 4096)" in helper
    allowed_match = re.search(r"\$allowedStages = @\((.*?)\n\s*\)", helper, re.DOTALL)
    assert allowed_match is not None
    assert tuple(re.findall(r"'([^']+)'", allowed_match.group(1))) == _CREDENTIAL_LAUNCH_PROBE_STAGES
    assert "$Stage.Value = 'parse'" in helper
    assert "records,stage" in helper
    assert "$probe.stage" in helper
    assert "$envelopeStage = [string]$probe.stage" in helper
    assert "$Stage.Value = $envelopeStage" in helper
    assert "$records = @($probe.records)" in helper
    for field in ("case", "success", "native_error", "wait_outcome", "length_bucket"):
        assert re.search(rf"(?m)^\s+{field}\s*=", helper)
    assert "-isnot [string]" in helper
    assert "-isnot [bool]" in helper
    assert "-isnot [long]" in helper
    assert "$nativeError = [int64]$record.native_error" in helper
    assert "if ($nativeError -lt [int]::MinValue -or $nativeError -gt [int]::MaxValue)" in helper
    assert "$waitOutcome -cnotin $allowedWaitOutcomes" in helper
    allowed_wait_outcomes_match = re.search(
        r"\$allowedWaitOutcomes = @\((.*?)\n\s*\)", helper, re.DOTALL
    )
    assert allowed_wait_outcomes_match is not None
    assert tuple(re.findall(r"'([^']+)'", allowed_wait_outcomes_match.group(1))) == _CREDENTIAL_LAUNCH_PROBE_WAIT_OUTCOMES
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


def _assert_credential_launch_probe_rejection_contract(source: str) -> None:
    start = source.index("function ConvertTo-CredentialLaunchProbeEvidence")
    end = source.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", start)
    helper = source[start:end]
    assert "[ref]$Rejection" in helper
    assert "$Rejection.Value = 'none'" in helper
    rejection_assignment_counts = {
        rejection: helper.count(f"$Rejection.Value = '{rejection}'")
        for rejection in _CREDENTIAL_LAUNCH_PROBE_REJECTIONS[1:]
    }
    assert rejection_assignment_counts == {
        **{rejection: 1 for rejection in _CREDENTIAL_LAUNCH_PROBE_REJECTIONS[1:] if rejection not in ("field_type", "success_error_relation")},
        "field_type": 3,
        "success_error_relation": 2,
    }
    assert "if ($null -ne $Rejection -and $Rejection.Value -eq 'none')" in helper
    assert "$Rejection.Value = 'normalization'" in helper
    guard_bindings = (
        ("if ($bytes.Length -gt 4096)", "size", "credential launch probe exceeded the bounded size"),
        ("if (($probeProperties -join ',') -cne 'records,stage')", "envelope_schema", "credential launch probe envelope schema was invalid"),
        ("if ($probe.stage -isnot [string] -or $probe.stage -cnotin $allowedStages)", "stage", "credential launch probe stage was invalid"),
        ("if ($records.Count -ne $expectedCases.Count)", "record_count", "credential launch probe record count was invalid"),
        ("if (($recordProperties -join ',') -cne 'case,length_bucket,native_error,success,wait_outcome')", "record_schema", "credential launch probe record schema was invalid"),
        ("if ($record.case -isnot [string] -or $record.length_bucket -isnot [string])", "field_type", "credential launch probe string fields were invalid"),
        ("if ($record.success -isnot [bool] -or $record.native_error -isnot [long])", "field_type", "credential launch probe numeric fields were invalid"),
        ("if ($record.wait_outcome -isnot [string])", "field_type", "credential launch probe wait outcome field was invalid"),
        ("if ($nativeError -lt [int]::MinValue -or $nativeError -gt [int]::MaxValue)", "native_error_range", "credential launch probe native error was outside the Int32 range"),
        ("if ($waitOutcome -cnotin $allowedWaitOutcomes)", "wait_outcome", "credential launch probe wait outcome was invalid"),
        ("if ([string]$record.case -cne $expectedCases[$index])", "case", "credential launch probe case was invalid"),
        ("if (-not [bool]$record.success -and ($waitOutcome -ne 'none' -or $nativeError -eq 0))", "success_error_relation", "credential launch probe failure record had an invalid outcome"),
        ("if ([bool]$record.success -and (($waitOutcome -eq 'none' -and $nativeError -ne 0) -or ($waitAllowsZeroError -and $nativeError -ne 0) -or ($waitRequiresError -and $nativeError -eq 0) -or (-not $waitAllowsZeroError -and -not $waitRequiresError -and $waitOutcome -ne 'none'))) {", "success_error_relation", "credential launch probe success record had an invalid outcome"),
        ("if ([string]$record.length_bucket -cne $expectedLengthBucket)", "length_bucket", "credential launch probe length bucket was invalid"),
    )
    for guard, rejection, message in guard_bindings:
        guard_index = helper.index(guard)
        assignment_index = helper.index(f"$Rejection.Value = '{rejection}'", guard_index)
        throw_index = helper.index(f"throw '{message}'", guard_index)
        assert guard_index < assignment_index < throw_index
        assert not any(
            assignment_index < helper.index(f"$Rejection.Value = '{other}'", guard_index)
            < throw_index
            for other in _CREDENTIAL_LAUNCH_PROBE_REJECTIONS[1:]
            if other != rejection and f"$Rejection.Value = '{other}'" in helper[guard_index:throw_index]
        )
    json_catch = helper[helper.index("$probe = ConvertFrom-Json") : helper.index("$probeProperties", helper.index("$probe = ConvertFrom-Json"))]
    assert "$Rejection.Value = 'json'" in json_catch
    assert "throw" in json_catch
    assert "-Rejection ([ref]$nativeProbeRejection)" not in helper


def test_credential_launch_probe_rejection_contract_is_exact_and_mutation_aware() -> None:
    module = read_module("Security.psm1")
    _assert_credential_launch_probe_rejection_contract(module)
    helper_start = module.index("function ConvertTo-CredentialLaunchProbeEvidence")
    helper_end = module.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", helper_start)
    helper = module[helper_start:helper_end]
    for rejection, assignment in (
        ("size", "$Rejection.Value = 'record_count'"),
        ("json", "$Rejection.Value = 'stage'"),
        ("envelope_schema", "$Rejection.Value = 'record_schema'"),
        ("stage", "$Rejection.Value = 'field_type'"),
        ("record_count", "$Rejection.Value = 'native_error_range'"),
        ("record_schema", "$Rejection.Value = 'field_type'"),
        ("field_type", "$Rejection.Value = 'wait_outcome'"),
        ("native_error_range", "$Rejection.Value = 'wait_outcome'"),
        ("wait_outcome", "$Rejection.Value = 'case'"),
        ("case", "$Rejection.Value = 'normalization'"),
        ("success_error_relation", "$Rejection.Value = 'size'"),
        ("length_bucket", "$Rejection.Value = 'json'"),
        ("normalization", "$Rejection.Value = 'none'"),
    ):
        mutation = helper.replace(
            f"$Rejection.Value = '{rejection}'",
            assignment,
            1,
        )
        mutated_module = module[:helper_start] + mutation + module[helper_end:]
        try:
            _assert_credential_launch_probe_rejection_contract(mutated_module)
        except AssertionError:
            continue
        raise AssertionError(f"native probe rejection mutation was accepted: {rejection}")


def test_credential_launch_probe_rejection_fixtures_are_exact() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for native probe rejection fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$baseRecords = @(
    [ordered]@{ case = 'short_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' },
    [ordered]@{ case = 'long_null_application'; success = $false; native_error = 1; wait_outcome = 'none'; length_bucket = 'over_1024' },
    [ordered]@{ case = 'short_explicit_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' }
)
function Parse-Fixture([string]$json) {
    $stage = 'not_started'
    $rejection = 'none'
    $evidence = & $securityModule {
        param($inputJson, $outputStage, $outputRejection)
        ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $inputJson -Stage $outputStage -Rejection $outputRejection
    } $json ([ref]$stage) ([ref]$rejection)
    [pscustomobject]@{ evidence = $evidence; stage = $stage; rejection = $rejection }
}
$fixtures = @(
    @{ name = 'valid'; expected = 'none' },
    @{ name = 'size'; expected = 'size' },
    @{ name = 'json'; expected = 'json' },
    @{ name = 'envelope_schema'; expected = 'envelope_schema' },
    @{ name = 'stage'; expected = 'stage' },
    @{ name = 'record_count'; expected = 'record_count' },
    @{ name = 'record_schema'; expected = 'record_schema' },
    @{ name = 'field_type'; expected = 'field_type' },
    @{ name = 'native_error_range'; expected = 'native_error_range' },
    @{ name = 'wait_outcome'; expected = 'wait_outcome' },
    @{ name = 'case'; expected = 'case' },
    @{ name = 'success_error_relation'; expected = 'success_error_relation' },
    @{ name = 'length_bucket'; expected = 'length_bucket' }
)
foreach ($fixture in $fixtures) {
    $records = @(
        [ordered]@{ case = 'short_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' },
        [ordered]@{ case = 'long_null_application'; success = $false; native_error = 1; wait_outcome = 'none'; length_bucket = 'over_1024' },
        [ordered]@{ case = 'short_explicit_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' }
    )
    switch ($fixture.name) {
        'valid' { $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'size' { $json = 'x' * 4097 }
        'json' { $json = '{malformed' }
        'envelope_schema' { $json = '{"stage":"complete","records":[],"extra":0}' }
        'stage' { $json = [pscustomobject]@{ stage = 'invalid'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'record_count' { $json = [pscustomobject]@{ stage = 'complete'; records = @($records[0], $records[1]) } | ConvertTo-Json -Compress -Depth 3 }
        'record_schema' { [void]$records[1].Remove('length_bucket'); $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'field_type' { $records[1].success = 'false'; $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'native_error_range' { $records[1].native_error = [int64]([int]::MaxValue + 1L); $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'wait_outcome' { $records[1].wait_outcome = 'raw_wait_status'; $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'case' { $records[1].case = 'wrong_case'; $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'success_error_relation' { $records[1].success = $true; $records[1].native_error = 258; $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
        'length_bucket' { $records[1].length_bucket = 'short'; $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3 }
    }
    $result = Parse-Fixture $json
    if ($fixture.expected -eq 'none') {
        if ($result.rejection -ne 'none' -or $result.stage -ne 'complete' -or $result.evidence.Count -ne 3) {
            throw "valid probe fixture changed evidence: $($fixture.name)"
        }
        continue
    }
    if ($result.rejection -ne $fixture.expected -or $result.stage -ne 'parse' -or $result.evidence -ne 'probe_unavailable') {
        throw "native probe rejection fixture was misclassified: $($fixture.name) ($($result.rejection), $($result.stage))"
    }
}
Write-Output 'native probe rejection fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "native probe rejection fixtures accepted" in result.stdout


def test_credential_launch_probe_evidence_parser_handles_unclassified_exception() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for normalization fallback fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$stage = 'not_started'
$rejection = 'none'
$evidence = & $securityModule {
    param($inputJson, $outputStage, $outputRejection)
    function Sort-Object {
        throw [InvalidOperationException]::new('fixture normalization failure')
    }
    ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $inputJson -Stage $outputStage -Rejection $outputRejection
} '{"stage":"complete","records":[]}' ([ref]$stage) ([ref]$rejection)
if ($evidence -ne 'probe_unavailable' -or $stage -ne 'parse' -or $rejection -ne 'normalization') {
    throw "normalization fallback was misclassified: evidence=$evidence, stage=$stage, rejection=$rejection"
}
Write-Output 'normalization fallback fixture accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "normalization fallback fixture accepted" in result.stdout


def test_credential_launch_probe_evidence_parser_rejects_fallback_rejection_mutation() -> None:
    module = read_module("Security.psm1")
    helper_start = module.index("function ConvertTo-CredentialLaunchProbeEvidence")
    helper_end = module.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", helper_start)
    helper = module[helper_start:helper_end]
    mutation = helper.replace(
        "$Rejection.Value = 'normalization'",
        "$Rejection.Value = 'none'",
        1,
    )
    mutated_module = module[:helper_start] + mutation + module[helper_end:]
    try:
        _assert_credential_launch_probe_rejection_contract(mutated_module)
    except AssertionError:
        return
    raise AssertionError("normalization fallback rejection mutation was accepted")


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
        wait_outcome = 'none'
        length_bucket = 'short'
    },
    [ordered]@{
        case = 'long_null_application'
        success = $false
        native_error = 1
        wait_outcome = 'none'
        length_bucket = 'over_1024'
    },
    [ordered]@{
        case = 'short_explicit_application'
        success = $true
        native_error = 0
        wait_outcome = 'none'
        length_bucket = 'short'
    }
)
foreach ($fixture in @(
    @{ name = 'negative'; native_error = -1; success = $false; wait_outcome = 'none'; expected = $null },
    @{ name = 'int32_min'; native_error = [int]::MinValue; success = $false; wait_outcome = 'none'; expected = $null },
    @{ name = 'zero'; native_error = 0; success = $true; wait_outcome = 'none'; expected = $null },
    @{ name = 'positive'; native_error = 1; success = $false; wait_outcome = 'none'; expected = $null },
    @{ name = 'int32_max'; native_error = [int]::MaxValue; success = $false; wait_outcome = 'none'; expected = $null },
    @{ name = 'oversized'; native_error = [int64]([int]::MaxValue + 1L); success = $false; wait_outcome = 'none'; expected = 'probe_unavailable' }
)) {
    $records[1].native_error = $fixture.native_error
    $records[1].success = $fixture.success
    $records[1].wait_outcome = $fixture.wait_outcome
    $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3
    $result = & $securityModule {
        param($probeJson)
        $stage = 'not_started'
        $evidence = ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $probeJson -Stage ([ref]$stage)
        [pscustomobject]@{ evidence = $evidence; stage = $stage }
    } $json
    if ($null -ne $fixture.expected) {
        if ($result.evidence -ne $fixture.expected -or $result.stage -ne 'parse') {
            throw "native error range fixture was not rejected: $($fixture.name)"
        }
        continue
    }
    if ($result.evidence.Count -ne 3 -or $result.stage -ne 'complete') {
        throw "valid native error fixture changed evidence: $($fixture.name)"
    }
    if ([bool]$result.evidence[1].success -ne [bool]$fixture.success) {
        throw "valid native error fixture changed success semantics: $($fixture.name)"
    }
    if ([int64]$result.evidence[1].native_error -ne [int64]$fixture.native_error) {
        throw "valid native error fixture changed native error: $($fixture.name)"
    }
    if ([string]$result.evidence[1].wait_outcome -cne [string]$fixture.wait_outcome) {
        throw "valid native error fixture changed wait outcome: $($fixture.name)"
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


def test_credential_launch_probe_record_semantics_are_exact() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for native probe record semantic fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
function New-Record([bool]$success, [long]$nativeError, [string]$waitOutcome) {
    [ordered]@{
        case = 'short_null_application'
        success = $true
        native_error = 0
        wait_outcome = 'none'
        length_bucket = 'short'
    }, [ordered]@{
        case = 'long_null_application'
        success = $success
        native_error = $nativeError
        wait_outcome = $waitOutcome
        length_bucket = 'over_1024'
    }, [ordered]@{
        case = 'short_explicit_application'
        success = $true
        native_error = 0
        wait_outcome = 'none'
        length_bucket = 'short'
    }
}
function Parse-Record([bool]$success, [long]$nativeError, [string]$waitOutcome) {
    $json = [pscustomobject]@{ stage = 'complete'; records = @(New-Record $success $nativeError $waitOutcome) } | ConvertTo-Json -Compress -Depth 3
    $stage = 'not_started'
    $rejection = 'none'
    $evidence = & $securityModule {
        param($probeJson, $outputStage, $outputRejection)
        ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $probeJson -Stage $outputStage -Rejection $outputRejection
    } $json ([ref]$stage) ([ref]$rejection)
    [pscustomobject]@{ evidence = $evidence; stage = $stage; rejection = $rejection }
}
$valid = @(
    @{ name = 'normal'; success = $true; native_error = 0; wait_outcome = 'none' },
    @{ name = 'process_failure'; success = $false; native_error = -5; wait_outcome = 'none' },
    @{ name = 'timeout'; success = $true; native_error = 0; wait_outcome = 'timeout' },
    @{ name = 'unexpected'; success = $true; native_error = 0; wait_outcome = 'unexpected' },
    @{ name = 'wait_failed'; success = $true; native_error = -5; wait_outcome = 'wait_failed' },
    @{ name = 'termination_timeout'; success = $true; native_error = 0; wait_outcome = 'termination_timeout' },
    @{ name = 'termination_wait_failed'; success = $true; native_error = -5; wait_outcome = 'termination_wait_failed' },
    @{ name = 'termination_unexpected'; success = $true; native_error = 0; wait_outcome = 'termination_unexpected' }
)
foreach ($fixture in $valid) {
    $result = Parse-Record $fixture.success $fixture.native_error $fixture.wait_outcome
    if ($result.stage -ne 'complete' -or $result.rejection -ne 'none' -or $result.evidence.Count -ne 3) {
        throw "valid semantic fixture was rejected: $($fixture.name) ($($result.stage), $($result.rejection))"
    }
    $record = $result.evidence[1]
    if ([bool]$record.success -ne [bool]$fixture.success -or [int]$record.native_error -ne [int]$fixture.native_error -or [string]$record.wait_outcome -cne $fixture.wait_outcome) {
        throw "valid semantic fixture changed: $($fixture.name)"
    }
    if ($record.native_error.GetType().FullName -ne 'System.Int32') {
        throw "native error was not normalized to Int32: $($fixture.name)"
    }
}
$invalid = @(
    @{ name = 'failed_without_error'; success = $false; native_error = 0; wait_outcome = 'none' },
    @{ name = 'failed_with_wait_outcome'; success = $false; native_error = -5; wait_outcome = 'timeout' },
    @{ name = 'normal_with_error'; success = $true; native_error = 5; wait_outcome = 'none' },
    @{ name = 'wait_failed_without_error'; success = $true; native_error = 0; wait_outcome = 'wait_failed' },
    @{ name = 'termination_wait_failed_without_error'; success = $true; native_error = 0; wait_outcome = 'termination_wait_failed' },
    @{ name = 'timeout_with_error'; success = $true; native_error = -5; wait_outcome = 'timeout' },
    @{ name = 'unexpected_with_error'; success = $true; native_error = 5; wait_outcome = 'unexpected' }
)
foreach ($fixture in $invalid) {
    $result = Parse-Record $fixture.success $fixture.native_error $fixture.wait_outcome
    if ($result.stage -ne 'parse' -or $result.rejection -ne 'success_error_relation' -or $result.evidence -ne 'probe_unavailable') {
        throw "invalid semantic fixture was accepted or misclassified: $($fixture.name) ($($result.stage), $($result.rejection))"
    }
}
Write-Output 'native probe record semantic fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "native probe record semantic fixtures accepted" in result.stdout


def test_credential_launch_probe_stage_fixtures_are_exact() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for native probe stage fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$records = @(
    [ordered]@{ case = 'short_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' },
    [ordered]@{ case = 'long_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'over_1024' },
    [ordered]@{ case = 'short_explicit_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' }
)
function Parse-Fixture([string]$json) {
    $stage = 'not_started'
    $evidence = & $securityModule {
        param($inputJson, $outputStage)
        ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $inputJson -Stage $outputStage
    } $json ([ref]$stage)
    [pscustomobject]@{ evidence = $evidence; stage = $stage }
}
$valid = Parse-Fixture ([pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3)
if ($valid.stage -ne 'complete' -or $valid.evidence.Count -ne 3) { throw 'valid probe fixture did not complete' }
$wait = Parse-Fixture ([pscustomobject]@{ stage = 'wait'; records = $records } | ConvertTo-Json -Compress -Depth 3)
if ($wait.stage -ne 'wait' -or $wait.evidence.Count -ne 3) { throw 'wait stage did not preserve valid probe evidence' }
$terminate = Parse-Fixture ([pscustomobject]@{ stage = 'terminate'; records = $records } | ConvertTo-Json -Compress -Depth 3)
if ($terminate.stage -ne 'terminate' -or $terminate.evidence.Count -ne 3) { throw 'termination stage did not preserve valid probe evidence' }
$malformed = Parse-Fixture '{malformed'
if ($malformed.stage -ne 'parse' -or $malformed.evidence -ne 'probe_unavailable') { throw 'malformed fixture was not parser-rejected' }
Write-Output 'native probe stage fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "native probe stage fixtures accepted" in result.stdout


def test_credential_launch_probe_rejects_malformed_complete_records_before_publishing_stage() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for malformed probe record fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$fixtures = @('missing_field', 'semantic_mismatch', 'invalid_wait_outcome', 'invalid_timeout_error')
foreach ($fixture in $fixtures) {
    $records = @(
        [ordered]@{ case = 'short_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' },
        [ordered]@{ case = 'long_null_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'over_1024' },
        [ordered]@{ case = 'short_explicit_application'; success = $true; native_error = 0; wait_outcome = 'none'; length_bucket = 'short' }
    )
    if ($fixture -eq 'missing_field') {
        [void]$records[1].Remove('length_bucket')
    } elseif ($fixture -eq 'semantic_mismatch') {
        $records[1].native_error = 17
    } elseif ($fixture -eq 'invalid_wait_outcome') {
        $records[1].wait_outcome = 'raw_wait_status'
    } else {
        $records[1].success = $false
        $records[1].native_error = 0
        $records[1].wait_outcome = 'timeout'
    }
    $json = [pscustomobject]@{ stage = 'complete'; records = $records } | ConvertTo-Json -Compress -Depth 3
    $result = & $securityModule {
        param($probeJson)
        $stage = 'not_started'
        $evidence = ConvertTo-CredentialLaunchProbeEvidence -ProbeJson $probeJson -Stage ([ref]$stage)
        [pscustomobject]@{ evidence = $evidence; stage = $stage }
    } $json
    if ($result.evidence -ne 'probe_unavailable' -or $result.stage -ne 'parse') {
        throw "malformed complete fixture published an invalid stage: $fixture ($($result.stage))"
    }
}
Write-Output 'malformed complete probe fixtures rejected'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "malformed complete probe fixtures rejected" in result.stdout


def _assert_credential_launch_probe_evidence_parser_stage_publication_contract(source: str) -> None:
    start = source.index("function ConvertTo-CredentialLaunchProbeEvidence")
    end = source.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", start)
    helper = source[start:end]
    parse_assignment = helper.index("$Stage.Value = 'parse'")
    envelope_assignment = helper.index("$Stage.Value = $envelopeStage")
    records_start = helper.index("$records = @($probe.records)")
    final_normalization = helper.rindex("            $normalized += [ordered]@{")
    return_statement = helper.index("        return (, $normalized)")
    assert parse_assignment < records_start
    assert final_normalization < envelope_assignment < return_statement


def test_credential_launch_probe_evidence_parser_stage_publication_is_mutation_aware() -> None:
    module = read_module("Security.psm1")
    _assert_credential_launch_probe_evidence_parser_stage_publication_contract(module)
    mutation = module.replace(
        "        $records = @($probe.records)\n",
        "        if ($null -ne $Stage) { $Stage.Value = $envelopeStage }\n        $records = @($probe.records)\n",
        1,
    )
    try:
        _assert_credential_launch_probe_evidence_parser_stage_publication_contract(mutation)
    except AssertionError:
        return
    raise AssertionError("probe parser accepted an early envelope-stage ref assignment")


def _assert_credential_launch_probe_stage_contract(probe: str) -> None:
    for stage in _CREDENTIAL_LAUNCH_PROBE_STAGES:
        if stage not in ('parse', 'complete'):
            assert f"$probeStage = '{stage}'" in probe
    required_order = (
        "$probeStage = 'not_started'",
        "$probeStage = 'password_bstr'",
        "$probeStage = 'case_setup'",
        "$probeStage = 'pipe_create'",
        "$probeStage = 'handle_setup'",
        "$probeStage = 'process_create'",
        "$probeStage = 'wait'",
        "$probeStage = 'terminate'",
        "$probeStage = 'cleanup'",
        "$probeStage = 'serialize'",
    )
    positions = tuple(probe.index(item) for item in required_order)
    assert positions == tuple(sorted(positions))
    assert "$probeFailureStage = $null" in probe
    assert "$probeFailureStage = $probeStage" in probe
    wait_timeout_start = probe.index("} elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT) {")
    wait_timeout_end = probe.index("$probeStage = 'terminate'", wait_timeout_start)
    assert "if ($null -eq $probeFailureStage) { $probeFailureStage = $probeStage }" in probe[wait_timeout_start:wait_timeout_end]
    termination_start = probe.index("$terminateSucceeded =")
    termination_end = probe.index("$terminationWaitResult =", termination_start)
    assert "$probeFailureStage = $probeStage" in probe[termination_start:termination_end]
    assert "if ($null -eq $probeFailureStage)" not in probe[termination_start:termination_end]
    assert "stage = $probeResultStage" in probe
    assert "$probeResultStage = if ($null -ne $probeFailureStage)" in probe
    process_failure_start = probe.index("if (-not $success) {")
    process_failure_end = probe.index("} else {", process_failure_start)
    assert "$probeFailureStage = $probeStage" in probe[process_failure_start:process_failure_end]
    wait_timeout_start = probe.index("} elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT) {")
    wait_timeout_end = probe.index("$probeStage = 'terminate'", wait_timeout_start)
    assert "$probeFailureStage = $probeStage" in probe[wait_timeout_start:wait_timeout_end]
    assert "records = $records" in probe
    assert "ConvertTo-Json -Compress -Depth 3" in probe


def test_credential_launch_probe_stage_contract_is_exact_and_mutation_aware() -> None:
    module = read_module("Security.psm1")
    probe_start = module.index("function Invoke-CredentialLaunchProbe")
    probe_end = module.index("function Invoke-AsStandardUser", probe_start)
    probe = module[probe_start:probe_end]
    _assert_credential_launch_probe_stage_contract(probe)
    for expected, replacement in (
        ("$probeStage = 'password_bstr'", "$probeStage = 'case_setup'"),
        ("$probeStage = 'pipe_create'", "$probeStage = 'handle_setup'"),
        ("$probeStage = 'process_create'", "$probeStage = 'wait'"),
        ("$probeStage = 'wait'", "$probeStage = 'cleanup'"),
        ("$probeStage = 'serialize'", "$probeStage = 'complete'"),
    ):
        mutation = probe.replace(expected, replacement, 1)
        try:
            _assert_credential_launch_probe_stage_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError(f"native probe stage mutation was accepted: {expected}")


def _assert_native_probe_stage_capture_contract(invoke: str) -> None:
    assert "$nativeProbeStage = 'not_started'" in invoke
    assert "-Stage ([ref]$nativeProbeStage)" in invoke
    assert "-NativeProbeStage $nativeProbeStage" in invoke
    assert invoke.index("$nativeStartErrorRecord = $_") < invoke.index("$nativeProbeStage = 'not_started'")
    assert invoke.index("Invoke-CredentialLaunchProbe -User $User") < invoke.index("-NativeProbeStage $nativeProbeStage")
    assert "catch { $nativeProbe = 'probe_unavailable' }" in invoke


def test_credential_launch_probe_stage_capture_preserves_probe_failure_boundary() -> None:
    module = read_module("Security.psm1")
    invoke_start = module.index("function Invoke-AsStandardUser")
    invoke_end = module.index("function Assert-StandardUserCannotReadWrite", invoke_start)
    invoke = module[invoke_start:invoke_end]
    _assert_native_probe_stage_capture_contract(invoke)
    for mutation in (
        invoke.replace("-NativeProbeStage $nativeProbeStage", "-NativeProbeStage $discardedStage", 1),
        invoke.replace("catch { $nativeProbe = 'probe_unavailable' }", "catch { $nativeProbe = $_.Exception.Message }", 1),
    ):
        try:
            _assert_native_probe_stage_capture_contract(mutation)
        except AssertionError:
            continue
        raise AssertionError("native probe stage capture mutation was accepted")


def test_credential_launch_diagnostic_stage_schema_fixtures() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for diagnostic stage fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = 'fixture.exe'
$securityModule = Get-Module Security
$configuration = & $securityModule {
    param($info)
    Get-CredentialLaunchDiagnostic -LaunchStage 'configuration' -FailureKind 'configuration' -FailedField 'file_name' -StartInfo $info -ArgumentCount 0 -ErrorRecord ([Exception]::new()) -NativeProbeStage 'not_started'
} $startInfo | ConvertFrom-Json
if ($configuration.PSObject.Properties.Name -contains 'native_probe' -or $configuration.PSObject.Properties.Name -contains 'native_probe_stage' -or $configuration.PSObject.Properties.Name -contains 'native_probe_rejection') { throw 'configuration schema changed' }
$native = & $securityModule {
    param($info)
    Get-CredentialLaunchDiagnostic -LaunchStage 'native_start' -FailureKind 'native' -FailedField 'process_start' -StartInfo $info -ArgumentCount 0 -ErrorRecord ([Exception]::new()) -NativeProbe 'probe_unavailable' -NativeProbeStage 'parse' -NativeProbeRejection 'json'
} $startInfo | ConvertFrom-Json
if ($native.native_probe -ne 'probe_unavailable' -or $native.native_probe_stage -ne 'parse' -or $native.native_probe_rejection -ne 'json') { throw 'native stage schema missing' }
Write-Output 'diagnostic stage schema fixtures accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "diagnostic stage schema fixtures accepted" in result.stdout


def test_credential_launch_probe_stage_fixtures_cover_pre_native_exception() -> None:
    pwsh = shutil.which("pwsh")
    assert pwsh, "pwsh is required for native probe exception fixtures"
    module = ROOT / "Security.psm1"
    fixture = r'''
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module $env:SPOTTER_SECURITY_MODULE -Force
$securityModule = Get-Module Security
$stage = 'not_started'
try {
    & $securityModule {
        param([ref]$outputStage)
        Invoke-CredentialLaunchProbe -User ([pscustomobject]@{ Password = $null }) -Stage $outputStage
    } ([ref]$stage)
} catch { }
if ($stage -ne 'password_bstr') { throw "probe exception stage was not preserved: $stage" }
Write-Output 'native probe exception fixture accepted'
'''
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", fixture],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"SPOTTER_SECURITY_MODULE": str(module.resolve())},
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "native probe exception fixture accepted" in result.stdout


def test_credential_launch_probe_evidence_parser_rejects_range_bound_mutations() -> None:
    module = read_module("Security.psm1")
    helper_start = module.index("function ConvertTo-CredentialLaunchProbeEvidence")
    helper_end = module.index("if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type]))", helper_start)
    helper = module[helper_start:helper_end]
    _assert_credential_launch_probe_evidence_parser_contract(module)
    for label, mutation in (
        ("lower", helper.replace(" -lt [int]::MinValue", "", 1)),
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


def _powershell_if_chain_branches(
    source: str, start_marker: str
) -> tuple[tuple[str, str], ...]:
    start = source.index(start_marker)
    opening_brace = source.index("{", start + len(start_marker) - 1)
    branches = []
    block_end = _powershell_braced_block_end(source, opening_brace)
    branches.append((start_marker.removesuffix(" {").strip(), source[opening_brace + 1 : block_end - 1]))
    cursor = block_end
    while True:
        continuation = re.match(
            r"\s*(?P<header>elseif\s*\(.*?\)|else)\s*\{",
            source[cursor:],
            re.DOTALL,
        )
        if continuation is None:
            break
        opening_brace = cursor + continuation.end() - 1
        block_end = _powershell_braced_block_end(source, opening_brace)
        branches.append(
            (
                continuation["header"],
                source[opening_brace + 1 : block_end - 1],
            )
        )
        cursor = block_end
    return tuple(branches)


def _assert_wait_branch_assignments(
    branch_body: str, expected_outcome: str, expected_native_error: str
) -> None:
    assignments = tuple(
        (name, value.strip())
        for name, value in re.findall(
            r"(?m)^\s*\$(waitOutcome|nativeError)\s*=\s*(.+?)\s*$",
            branch_body,
        )
    )
    assert assignments == (
        ("waitOutcome", f"'{expected_outcome}'"),
        ("nativeError", expected_native_error),
    )


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
    assert "$nativeError = [int]$waitResult" not in probe
    assert "$nativeError = [int]$terminationWaitResult" not in probe
    assert "$waitOutcome = 'timeout'" in probe
    assert "$waitOutcome = 'wait_failed'" in probe
    assert "$waitOutcome = 'unexpected'" in probe
    assert "$waitOutcome = 'termination_timeout'" in probe
    assert "$waitOutcome = 'termination_wait_failed'" in probe
    assert "$waitOutcome = 'termination_unexpected'" in probe
    assert "if ($nativeError -eq 0 -and $waitOutcome -eq 'none') { $nativeError = 1 }" in probe

    initial_wait_branches = _powershell_if_chain_branches(
        probe,
        "if ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0) {",
    )
    assert tuple(header for header, _ in initial_wait_branches) == (
        "if ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0)",
        "elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT)",
        "elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED)",
        "else",
    )
    assert not re.search(
        r"(?m)^\s*\$(?:waitOutcome|nativeError)\s*=", initial_wait_branches[0][1]
    )
    timeout_body, = (body for header, body in initial_wait_branches if "WAIT_TIMEOUT" in header)
    timeout_assignments_end = timeout_body.index("$probeStage = 'terminate'")
    _assert_wait_branch_assignments(
        timeout_body[:timeout_assignments_end], "timeout", "0"
    )
    wait_failed_body, = (
        body for header, body in initial_wait_branches if "WAIT_FAILED" in header
    )
    _assert_wait_branch_assignments(
        wait_failed_body,
        "wait_failed",
        "[Runtime.InteropServices.Marshal]::GetLastWin32Error()",
    )
    unexpected_body = initial_wait_branches[-1][1]
    _assert_wait_branch_assignments(unexpected_body, "unexpected", "0")

    termination_call_branches = _powershell_if_chain_branches(
        timeout_body,
        "if (-not $terminateSucceeded) {",
    )
    assert len(termination_call_branches) == 1
    _assert_wait_branch_assignments(
        termination_call_branches[0][1],
        "termination_wait_failed",
        "[Runtime.InteropServices.Marshal]::GetLastWin32Error()",
    )
    termination_wait_branches = _powershell_if_chain_branches(
        timeout_body,
        "if ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0) {",
    )
    assert tuple(header for header, _ in termination_wait_branches) == (
        "if ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0)",
        "elseif ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT)",
        "elseif ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED)",
        "else",
    )
    assert not re.search(
        r"(?m)^\s*\$(?:waitOutcome|nativeError)\s*=", termination_wait_branches[0][1]
    )
    termination_timeout_body, = (
        body for header, body in termination_wait_branches if "WAIT_TIMEOUT" in header
    )
    _assert_wait_branch_assignments(
        termination_timeout_body, "termination_timeout", "0"
    )
    termination_wait_failed_body, = (
        body for header, body in termination_wait_branches if "WAIT_FAILED" in header
    )
    _assert_wait_branch_assignments(
        termination_wait_failed_body,
        "termination_wait_failed",
        "[Runtime.InteropServices.Marshal]::GetLastWin32Error()",
    )
    termination_unexpected_body = termination_wait_branches[-1][1]
    _assert_wait_branch_assignments(
        termination_unexpected_body, "termination_unexpected", "0"
    )

    assert probe.index("$waitResult =") < probe.index("WAIT_TIMEOUT")
    assert probe.index("WAIT_TIMEOUT") < probe.index("TerminateProcess")
    assert probe.index("TerminateProcess") < probe.index("$terminationWaitResult =")
    assert probe.index("$terminationWaitResult =") < probe.index("$lengthBucket =")
    assert "$waitOutcome = 'none'" in probe


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
            "hProcess, 1000)",
            "hProcess, 0)",
            1,
        ),
        module.replace(
            "                        $waitOutcome = 'wait_failed'\n"
            "                        $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                        throw 'credential probe child wait failed'",
            "                        $waitOutcome = 'unexpected'\n"
            "                        $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                        throw 'credential probe child wait failed'",
            1,
        ).replace(
            "                        $waitOutcome = 'unexpected'\n"
            "                        $nativeError = 0\n"
            "                        throw 'credential probe child returned an unexpected wait status'",
            "                        $waitOutcome = 'wait_failed'\n"
            "                        $nativeError = 0\n"
            "                        throw 'credential probe child returned an unexpected wait status'",
            1,
        ),
        module.replace(
            "                        $waitOutcome = 'unexpected'\n"
            "                        $nativeError = 0\n",
            "                        $nativeError = 0\n",
            1,
        ),
        module.replace(
            "                            $waitOutcome = 'termination_wait_failed'\n"
            "                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                            throw 'credential probe child termination failed'",
            "                            $waitOutcome = 'timeout'\n"
            "                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                            throw 'credential probe child termination failed'",
            1,
        ),
        module.replace(
            "                            $waitOutcome = 'termination_wait_failed'\n"
            "                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                            throw 'credential probe child termination wait failed'",
            "                            $waitOutcome = 'timeout'\n"
            "                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()\n"
            "                            throw 'credential probe child termination wait failed'",
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
        "native_error": "[int]$nativeError",
        "wait_outcome": "$waitOutcome",
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
    test_snipeit_loopback_fixture_is_private_and_evidence_only()
    test_direct_scm_exercises_installed_cli_to_service_sync_flow()
    test_direct_scm_result_shape_diagnostic_precedes_first_exit_code_consumer()
    test_direct_scm_result_shape_diagnostic_covers_every_exit_code_consumer()
    test_direct_scm_result_shape_diagnostic_has_exact_bounded_schema()
    test_direct_scm_result_shape_diagnostic_does_not_mask_original_failure()
    test_direct_scm_result_shape_diagnostic_rejects_privacy_mutations()
    test_ac4_real_capture_handlers_are_runspace_independent()
    test_ac4_stream_capture_is_incremental_bounded_and_fail_closed()
    test_ac4_stream_capture_mutations_are_rejected()
    test_ac4_stream_capture_mutation_fixtures_are_registered_and_executable()
    test_ac4_artifact_scanner_handles_bytes_encodings_boundaries_and_fail_closed()
    test_ac4_artifact_scanner_mutations_are_rejected()
    test_ac4_loopback_fixture_behaviorally_validates_routes_queries_and_readiness()
    test_ac4_loopback_mutations_remove_required_safety_contracts()
    test_ac4_ciphertext_validation_is_structural_canonical_and_private()
    test_ac4_ciphertext_mutations_are_rejected()
    test_ac4_caller_successfully_closes_stdin_without_strict_mode_cleanup_failure()
    test_ac4_caller_lifecycle_fixtures_cover_failures_and_descendants()
    test_ac4_caller_stdin_failure_fixtures_are_bounded_and_cleanup_processes()
    test_ac4_stdin_operation_and_cleanup_failures_are_combined_without_leaks()
    test_ac4_caller_lifecycle_mutations_are_rejected()
    test_ac4_timeout_cleanup_kills_child_and_requires_exit()
    test_ac4_timeout_contract_is_deadline_bounded_and_mutation_aware()
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
    test_standard_user_acl_probe_uses_bounded_secure_script_transport()
    test_standard_user_acl_probe_uses_acl_aware_creation_and_acl_apis()
    test_standard_user_acl_probe_regresses_the_oversized_encoded_transport()
    test_standard_user_acl_probe_transport_contract_rejects_unsafe_mutations()
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
    test_credentialed_native_start_capture_preserves_rejection_discriminator()
    test_credential_launch_probe_evidence_parser_is_exact_and_bounded()
    test_credential_launch_probe_rejection_contract_is_exact_and_mutation_aware()
    test_credential_launch_probe_rejection_fixtures_are_exact()
    test_credential_launch_probe_evidence_parser_handles_unclassified_exception()
    test_credential_launch_probe_evidence_parser_rejects_fallback_rejection_mutation()
    test_credential_launch_probe_rejects_malformed_complete_records_before_publishing_stage()
    test_credential_launch_probe_evidence_parser_stage_publication_is_mutation_aware()
    test_credential_launch_probe_stage_fixtures_are_exact()
    test_credential_launch_probe_stage_contract_is_exact_and_mutation_aware()
    test_credential_launch_probe_stage_capture_preserves_probe_failure_boundary()
    test_credential_launch_diagnostic_stage_schema_fixtures()
    test_credential_launch_probe_stage_fixtures_cover_pre_native_exception()
    test_credential_launch_probe_evidence_parser_enforces_int32_native_error_range()
    test_credential_launch_probe_record_semantics_are_exact()
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
