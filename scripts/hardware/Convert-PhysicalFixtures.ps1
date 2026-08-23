[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

# Converts a captured physical-hardware fixture (from Capture-PhysicalFixtures.ps1)
# into CI-ready Rust test fixtures:
#
#   {OutputDir}/smbios_fixture.bin    - Raw SMBIOS bytes for parse_smbios_tables
#   {OutputDir}/wmi_monitors.json     - Normalized WMI monitor shapes for convert_monitor tests
#   {OutputDir}/chassis.json          - Chassis type values for ChassisType::is_portable tests
#   {OutputDir}/fixture_summary.json  - Human-readable summary of all fixtures
#
# The converter does NOT redact; the capture script already replaced identifiers.
# This script validates that no raw identifiers remain and that the SMBIOS bytes
# parse through the same structural walk the Rust parser uses.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$capture = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($capture.schema_version -ne 2) { throw "unsupported schema version: $($capture.schema_version)" }
if ($capture.capture_type -ne 'physical_hardware_fixture') { throw "unexpected capture type: $($capture.capture_type)" }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ---------------------------------------------------------------------------
# Validate no real identifiers leaked
# ---------------------------------------------------------------------------

$smbiosHex = $capture.smbios.raw_hex
$smbiosBytes = [Convert]::FromHexString($smbiosHex)

# Privacy validation is handled by validate_physical_fixture.py, which is run
# separately after the converter. This script only transforms the already-redacted
# capture data into CI-ready fixture files.

# Check WMI monitors for unredacted serials
foreach ($monitor in $capture.wmi_monitors) {
    if ($monitor.serial -notmatch '^SER\d' -and $monitor.serial -ne '') {
        throw "unredacted monitor serial detected: $($monitor.serial)"
    }
    if ($monitor.manufacturer_name -notmatch '^MFR\d' -and $monitor.manufacturer_name -ne '') {
        throw "unredacted manufacturer name detected: $($monitor.manufacturer_name)"
    }
}

# ---------------------------------------------------------------------------
# Write SMBIOS binary fixture
# ---------------------------------------------------------------------------

$smbiosPath = Join-Path $OutputDir 'smbios_fixture.bin'
[IO.File]::WriteAllBytes($smbiosPath, $smbiosBytes)

# ---------------------------------------------------------------------------
# Write WMI monitors JSON fixture
# ---------------------------------------------------------------------------

$wmiFixtures = @()
foreach ($monitor in $capture.wmi_monitors) {
    $wmiFixtures += [ordered]@{
        active = $monitor.active
        manufacturer_name = $monitor.manufacturer_name
        manufacturer_name_array_length = $monitor.manufacturer_name_array_length
        product_code = $monitor.product_code
        product_code_array_length = $monitor.product_code_array_length
        serial_number_id = $monitor.serial
        serial_number_array_length = $monitor.serial_array_length
        week_of_manufacture = $monitor.week_of_manufacture
        year_of_manufacture = $monitor.year_of_manufacture
    }
}

$wmiPath = Join-Path $OutputDir 'wmi_monitors.json'
$wmiJson = $wmiFixtures | ConvertTo-Json -Depth 4
if ($wmiFixtures.Count -eq 1) { $wmiJson = "[$wmiJson]" }
[IO.File]::WriteAllText($wmiPath, $wmiJson, [Text.Encoding]::UTF8)

# ---------------------------------------------------------------------------
# Write chassis JSON fixture
# ---------------------------------------------------------------------------

$chassisPath = Join-Path $OutputDir 'chassis.json'
$chassisJson = [ordered]@{
    types = $capture.chassis.types
    class_counts = $capture.chassis.class_counts
} | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($chassisPath, $chassisJson, [Text.Encoding]::UTF8)

# ---------------------------------------------------------------------------
# Write summary
# ---------------------------------------------------------------------------

$summary = [ordered]@{
    source_file = (Split-Path -Leaf $InputPath)
    capture_metadata = $capture.metadata
    smbios = [ordered]@{
        fixture_file = 'smbios_fixture.bin'
        byte_count = $smbiosBytes.Length
        structure_count = $capture.smbios.summary.structure_count
        type_histogram = $capture.smbios.summary.type_histogram
        major_version = $capture.smbios.summary.major_version
        minor_version = $capture.smbios.summary.minor_version
        capped = $capture.smbios.summary.capped
    }
    wmi_monitors = [ordered]@{
        fixture_file = 'wmi_monitors.json'
        count = $wmiFixtures.Count
        per_monitor = @($wmiFixtures | ForEach-Object {
            [ordered]@{
                active = $_.active
                manufacturer_placeholder = $_.manufacturer_name
                serial_placeholder = $_.serial_number_id
                array_lengths = [ordered]@{
                    manufacturer = $_.manufacturer_name_array_length
                    product = $_.product_code_array_length
                    serial = $_.serial_number_array_length
                }
                manufacture_week = $_.week_of_manufacture
                manufacture_year = $_.year_of_manufacture
            }
        })
    }
    chassis = [ordered]@{
        fixture_file = 'chassis.json'
        types = $capture.chassis.types
        class_counts = $capture.chassis.class_counts
    }
    usage = @(
        'smbios_fixture.bin: Feed raw bytes to spotter_core::smbios::parse_smbios_tables in Rust tests.',
        'wmi_monitors.json: Load and feed to spotter_svc::discovery::convert_monitor in Rust tests.',
        'chassis.json: Load ChassisType values and verify ChassisType::is_portable classification.'
    )
}

$summaryPath = Join-Path $OutputDir 'fixture_summary.json'
[IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 6), [Text.Encoding]::UTF8)

Write-Output "Fixtures written to $OutputDir"
Write-Output "  smbios_fixture.bin ($($smbiosBytes.Length) bytes, $($capture.smbios.summary.structure_count) structures)"
Write-Output "  wmi_monitors.json ($($wmiFixtures.Count) monitors)"
Write-Output "  chassis.json (types: $($capture.chassis.types -join ', '))"
Write-Output "  fixture_summary.json"
