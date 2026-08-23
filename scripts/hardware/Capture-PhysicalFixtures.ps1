[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $false)]
    [string]$Label = 'physical-capture'
)

# Captures real SMBIOS and WMI monitor data shapes from a Windows machine.
# All identifiers (serials, asset tags, UUIDs, machine names) are replaced
# with deterministic placeholders so the output is safe to commit as a CI fixture.
#
# Usage:
#   pwsh -File scripts/hardware/Capture-PhysicalFixtures.ps1 -OutputPath .\capture.json
#
# The output JSON contains:
#   - smbios_raw_hex: hex-encoded RawSMBIOSData buffer (identifiers redacted in-place)
#   - smbios_structure_summary: type histogram, counts, header metadata
#   - wmi_monitors: per-monitor array shapes with redacted string values
#   - chassis: ChassisTypes array from Win32_SystemEnclosure
#   - capture_metadata: OS build, PowerShell version, capture timestamp

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MaxSmbiosBytes = 16384
$MaxMonitors = 32

# ---------------------------------------------------------------------------
# SMBIOS capture
# ---------------------------------------------------------------------------

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SpotterFirmware {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint GetSystemFirmwareTable(uint provider, uint id, IntPtr buffer, uint size);
}
'@

# GetSystemFirmwareTable expects the 'RSMB' FourCC as a big-endian DWORD
# (matching the C multi-character constant 'RSMB' == 0x52534D42).
# BitConverter.ToUInt32 on x86/x64 produces little-endian (0x424D5352), which
# returns ERROR_INVALID_PARAMETER or zero. Use manual big-endian packing instead.
$rsmb = [Text.Encoding]::ASCII.GetBytes('RSMB')
$provider = [uint32]($rsmb[0] * 0x1000000 + $rsmb[1] * 0x10000 + $rsmb[2] * 0x100 + $rsmb[3])
$length = [SpotterFirmware]::GetSystemFirmwareTable($provider, 0, [IntPtr]::Zero, 0)
if ($length -le 0) { throw 'firmware size unavailable or zero' }
$boundedLength = [Math]::Min([int]$length, $MaxSmbiosBytes)
$buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($boundedLength)
try {
    $written = [SpotterFirmware]::GetSystemFirmwareTable($provider, 0, $buffer, [uint32]$boundedLength)
    $actualLength = [Math]::Min([int]$written, $boundedLength)
    if ($actualLength -lt 8) { throw 'firmware table header unavailable' }

    $data = New-Object byte[] $actualLength
    [Runtime.InteropServices.Marshal]::Copy($buffer, $data, 0, $actualLength)
} finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
}

# Parse the RawSMBIOSData header: [UsedSize(1)] [SmbiosMajorVersion(1)] [SmbiosMinorVersion(1)] [Reserved(1)] [SmbiosDataSize(4)]
$usedSize = $data[0]
$majorVersion = $data[1]
$minorVersion = $data[2]
$reportedTableLength = [BitConverter]::ToUInt32($data, 4)
$tableStart = 8
$tableLength = [Math]::Min([int]$reportedTableLength, $actualLength - $tableStart)
$tableEnd = $tableStart + $tableLength

# Walk structures and redact string values in-place.
# String tables follow each formatted section and are NUL-terminated sequences
# of NUL-separated strings, ending with a double NUL.
# We replace each non-empty string with a deterministic placeholder that
# preserves length and encoding (ASCII or UTF-8), so parser behavior is
# identical but no real identifiers leak.
function Convert-PlaceholderString {
    param([string]$Value, [int]$Index, [int]$StructureType, [int]$StringIndex)
    # Produce a deterministic placeholder preserving approximate length.
    # Format: "PLACEHOLDER_T{type}_S{stringIndex}_I{index}" padded/truncated to original length.
    $placeholder = "PLACEHOLDER_T${StructureType}_S${StringIndex}_I${Index}"
    if ($Value.Length -eq 0) { return $Value }
    if ($placeholder.Length -gt $Value.Length) {
        $placeholder = $placeholder.Substring(0, $Value.Length)
    } else {
        $placeholder = $placeholder.PadRight($Value.Length, 'X')
    }
    return $placeholder
}

# We need to walk and redact the string tables.
# Make a working copy so we can replace string bytes.
$redacted = [byte[]]::new($actualLength)
[Array]::Copy($data, $redacted, $actualLength)

$structureCount = 0
$typeHistogram = [ordered]@{}
$offset = $tableStart

while ($offset + 4 -le $tableEnd) {
    $structureType = [int]$redacted[$offset]
    $structureLength = [int]$redacted[$offset + 1]
    if ($structureLength -lt 4 -or $offset + $structureLength -gt $tableEnd) { break }

    $formattedEnd = $offset + $structureLength

    # Find string table end (double NUL)
    $stringCursor = $formattedEnd
    $stringEnd = -1
    while ($stringCursor + 1 -lt $tableEnd) {
        if ($redacted[$stringCursor] -eq 0 -and $redacted[$stringCursor + 1] -eq 0) {
            $stringEnd = $stringCursor + 2
            break
        }
        $stringCursor++
    }
    if ($stringEnd -lt 0) { break }

    # Walk the string table and redact each non-empty string.
    # Strings are NUL-separated; a leading NUL means "no strings" (index 0 = not set).
    $stringAreaStart = $formattedEnd
    $stringAreaEnd = $stringEnd - 2  # exclude the terminating double NUL
    if ($stringAreaEnd -gt $stringAreaStart) {
        $stringIndex = 1  # SMBIOS string indices are 1-based
        $strStart = $stringAreaStart
        $pos = $stringAreaStart
        while ($pos -le $stringAreaEnd) {
            if ($pos -lt $stringAreaEnd -and $redacted[$pos] -ne 0) {
                $pos++
                continue
            }
            # We hit a NUL or the end of the string area.
            $strBytes = $redacted[$strStart..($pos - 1)]
            $strValue = [Text.Encoding]::UTF8.GetString($strBytes)
            if ($strValue.Length -gt 0) {
                $placeholder = Convert-PlaceholderString -Value $strValue -Index $structureCount -StructureType $structureType -StringIndex $stringIndex
                $phBytes = [Text.Encoding]::UTF8.GetBytes($placeholder)
                # Replace in-place, preserving the exact same byte length.
                # If placeholder bytes differ in length (multibyte), pad/truncate.
                $len = [Math]::Min($phBytes.Length, $strBytes.Length)
                for ($i = 0; $i -lt $len; $i++) {
                    $redacted[$strStart + $i] = $phBytes[$i]
                }
                # Fill any remaining bytes with 'X' (0x58) to preserve length.
                for ($i = $len; $i -lt $strBytes.Length; $i++) {
                    $redacted[$strStart + $i] = 0x58
                }
            }
            $stringIndex++
            $strStart = $pos + 1
            $pos++
        }
    }

    $key = [string]$structureType
    if (-not $typeHistogram.Contains($key)) { $typeHistogram[$key] = 0 }
    $typeHistogram[$key] = [int]$typeHistogram[$key] + 1
    $structureCount++
    $offset = $stringEnd
    if ($structureType -eq 127) { break }
}

$smbiosRawHex = -join ($redacted | ForEach-Object { $_.ToString('x2') })

$smbiosSummary = [ordered]@{
    used_size = $usedSize
    major_version = $majorVersion
    minor_version = $minorVersion
    reported_table_length = $reportedTableLength
    actual_length = $actualLength
    table_length = $tableLength
    structure_count = $structureCount
    type_histogram = $typeHistogram
    capped = ($length -gt $MaxSmbiosBytes)
}

# ---------------------------------------------------------------------------
# WMI monitor capture
# ---------------------------------------------------------------------------

$monitors = @()
try {
    $wmiRows = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction Stop)
    $wmiRows = @($wmiRows | Select-Object -First $MaxMonitors)
    $monitorIndex = 0
    foreach ($row in $wmiRows) {
        $manufacturerName = [Text.Encoding]::UTF8.GetString(($row.ManufacturerName | Where-Object { $_ -ne 0 })).Trim()
        $productCode = [Text.Encoding]::UTF8.GetString(($row.ProductCodeID | Where-Object { $_ -ne 0 })).Trim()
        $serialNumber = [Text.Encoding]::UTF8.GetString(($row.SerialNumberID | Where-Object { $_ -ne 0 })).Trim()

        # Redact identifiers with deterministic placeholders preserving shape.
        $redactedManufacturer = "MFR$monitorIndex".PadRight($manufacturerName.Length, 'X')
        $redactedProduct = "PROD$monitorIndex".PadRight($productCode.Length, 'X')
        $redactedSerial = "SER$monitorIndex".PadRight($serialNumber.Length, 'X')

        $monitors += [ordered]@{
            index = $monitorIndex
            active = $row.Active
            manufacturer_name = $redactedManufacturer
            manufacturer_name_array_length = @($row.ManufacturerName).Count
            product_code = $redactedProduct
            product_code_array_length = @($row.ProductCodeID).Count
            serial = $redactedSerial
            serial_array_length = @($row.SerialNumberID).Count
            week_of_manufacture = $row.WeekOfManufacture
            year_of_manufacture = $row.YearOfManufacture
            instance_name = "MONITOR_$monitorIndex"
        }
        $monitorIndex++
    }
} catch {
    $monitors = @()
}

# ---------------------------------------------------------------------------
# Chassis capture
# ---------------------------------------------------------------------------

$chassisTypes = @()
$chassisClassCounts = [ordered]@{ portable = 0; desktop = 0; server = 0; enclosure = 0; unknown = 0 }
try {
    $enclosures = @(Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop)
    foreach ($enc in $enclosures) {
        foreach ($ct in @($enc.ChassisTypes)) {
            $chassisTypes += $ct
            if ($ct -in 8, 9, 10, 11, 12, 14, 30, 31, 32) { $chassisClassCounts.portable++ }
            elseif ($ct -in 3, 4, 5, 6, 7, 15, 16) { $chassisClassCounts.desktop++ }
            elseif ($ct -in 23, 24, 25, 26, 27, 28, 29) { $chassisClassCounts.server++ }
            elseif ($ct -gt 0) { $chassisClassCounts.enclosure++ }
            else { $chassisClassCounts.unknown++ }
        }
    }
} catch {
    # Chassis query unavailable; leave types and class counts at defaults.
    $chassisTypes = @()
}

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

$metadata = [ordered]@{
    label = $Label
    capture_timestamp = (Get-Date -Format 'o')
    os_build = [Environment]::OSVersion.Version.Build
    powershell_version = $PSVersionTable.PSVersion.ToString()
    process_bitness = [IntPtr]::Size * 8
    smbios_capped = ($length -gt $MaxSmbiosBytes)
    monitor_count = $monitors.Count
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$report = [ordered]@{
    schema_version = 2
    capture_type = 'physical_hardware_fixture'
    metadata = $metadata
    smbios = [ordered]@{
        raw_hex = $smbiosRawHex
        summary = $smbiosSummary
    }
    wmi_monitors = $monitors
    chassis = [ordered]@{
        types = $chassisTypes
        class_counts = $chassisClassCounts
    }
}

$json = $report | ConvertTo-Json -Depth 8
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
[IO.File]::WriteAllText($OutputPath, $json, [Text.Encoding]::UTF8)
Write-Output $OutputPath
