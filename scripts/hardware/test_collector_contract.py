"""Behavioral regression tests for the PowerShell hardware collector contract."""

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

_COLLECTOR = Path(__file__).resolve().parent / "collect_hardware.ps1"
_PROBE = """
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorPath
)

Set-StrictMode -Version Latest
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $CollectorPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw "collector parse failed: $($parseErrors[0].Message)"
}

foreach ($name in @('Get-RsmbSummary', 'Get-WmiSummary', 'Get-ChassisSummary')) {
    $definition = $ast.Find(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name
        },
        $true
    ) | Select-Object -First 1
    if ($null -eq $definition) {
        throw "collector function not found: $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:ForceFailure = $false
function Invoke-Bounded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    if ($script:ForceFailure) {
        return [ordered]@{
            api = $Name
            result = 'unavailable'
            duration_ms = 23
        }
    }

    $summary = switch ($Name) {
        'GetSystemFirmwareTable' {
            [ordered]@{
                status = 'ok'
                length = 8
                structure_count = 0
                type_histogram = [ordered]@{}
                capped = $false
            }
        }
        'WmiMonitorID' {
            [ordered]@{
                status = 'ok'
                count = 0
                array_lengths = [ordered]@{
                    manufacturer_name = @()
                    product_code_id = @()
                    serial_number_id = @()
                    week_of_manufacture = @()
                    year_of_manufacture = @()
                }
                placeholder_classes = @('empty')
                capped = $false
            }
        }
        'Win32_SystemEnclosure' {
            [ordered]@{
                status = 'ok'
                count = 0
                class_counts = [ordered]@{
                    portable = 0
                    desktop = 0
                    server = 0
                    enclosure = 0
                    unknown = 0
                }
                capped = $false
            }
        }
        default { throw "unexpected bounded operation: $Name" }
    }
    return [ordered]@{
        api = $Name
        result = 'ok'
        duration_ms = 17
        value = $summary
    }
}

function Assert-Result {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [object]$Result,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedStatus
    )

    if ($null -eq $Result) { throw "$Name returned null" }
    foreach ($key in @('summary', 'status', 'duration_ms')) {
        if (-not ($Result.Keys -contains $key)) {
            throw "$Name result is missing $key"
        }
    }
    if ($Result['status'] -ne $ExpectedStatus) {
        throw "$Name status was $($Result['status']), expected $ExpectedStatus"
    }
    if ($Result['summary']['status'] -ne $ExpectedStatus) {
        throw "$Name summary status was $($Result['summary']['status']), expected $ExpectedStatus"
    }
    if ([int]$Result['duration_ms'] -lt 0 -or [int]$Result['duration_ms'] -gt 120000) {
        throw "$Name duration was outside the bounded range"
    }
}

$successResults = [ordered]@{
    smbios = Get-RsmbSummary
    wmi = Get-WmiSummary
    chassis = Get-ChassisSummary
}
Assert-Result -Name 'smbios success' -Result $successResults['smbios'] -ExpectedStatus 'ok'
Assert-Result -Name 'wmi success' -Result $successResults['wmi'] -ExpectedStatus 'ok'
Assert-Result -Name 'chassis success' -Result $successResults['chassis'] -ExpectedStatus 'ok'

$script:ForceFailure = $true
$failureResults = [ordered]@{
    smbios = Get-RsmbSummary
    wmi = Get-WmiSummary
    chassis = Get-ChassisSummary
}
Assert-Result -Name 'smbios failure' -Result $failureResults['smbios'] -ExpectedStatus 'unavailable'
Assert-Result -Name 'wmi failure' -Result $failureResults['wmi'] -ExpectedStatus 'unavailable'
Assert-Result -Name 'chassis failure' -Result $failureResults['chassis'] -ExpectedStatus 'unavailable'
"""


class CollectorContractTests(unittest.TestCase):
    """Exercise all collector producer result shapes under strict mode."""

    def test_producers_return_wrapped_results_on_success_and_failure(self) -> None:
        """Run the real producer functions with bounded synthetic inputs."""
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("pwsh is required for the PowerShell contract probe")

        with tempfile.TemporaryDirectory() as temporary_directory:
            probe_path = Path(temporary_directory) / "collector-contract-probe.ps1"
            probe_path.write_text(textwrap.dedent(_PROBE), encoding="utf-8")
            completed = subprocess.run(
                [
                    pwsh,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(probe_path),
                    str(_COLLECTOR),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(
            completed.returncode,
            0,
            msg=f"PowerShell probe failed\nstdout: {completed.stdout}\nstderr: {completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
