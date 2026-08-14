[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\chassis-fixture.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Captures Win32_SystemEnclosure.ChassisTypes for portability detection
# test data. Writes a JSON fixture file with the raw chassis type array
# and the interpreted chassis type code.
#
# Requires Windows.

$enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop

# ChassisTypes is an array of uint16. Take the first value as the
# authoritative chassis type (matching SMBIOS Type 3 semantics).
$chassisTypes = @($enclosure.ChassisTypes)
$primaryType = if ($chassisTypes.Count -gt 0) { $chassisTypes[0] } else { 0 }

# SMBIOS chassis type names for reference
$typeNames = @{
    1  = 'Other'
    2  = 'Unknown'
    3  = 'Desktop'
    4  = 'Low Profile Desktop'
    5  = 'Pizza Box'
    6  = 'Mini Tower'
    7  = 'Tower'
    8  = 'Portable'
    9  = 'Laptop'
    10 = 'Notebook'
    11 = 'Hand Held'
    12 = 'Docking Station'
    13 = 'All in One'
    14 = 'Sub Notebook'
    15 = 'Space-Saving'
    16 = 'Lunch Box'
    17 = 'Main Server Chassis'
    18 = 'Expansion Chassis'
    19 = 'SubChassis'
    20 = 'Bus Expansion Chassis'
    21 = 'Peripheral Chassis'
    22 = 'RAID Chassis'
    23 = 'Rack Mount Chassis'
    24 = 'Sealed-case PC'
    25 = 'Multi-system Chassis'
    26 = 'Compact PCI'
    27 = 'Advanced TCA'
    28 = 'Blade'
    29 = 'Blade Enclosure'
    30 = 'Tablet'
    31 = 'Convertible'
    32 = 'Detachable'
    33 = 'IoT Gateway'
    34 = 'Embedded PC'
    35 = 'Mini PC'
    36 = 'Stick PC'
}

# Portable types per spotter-core::smbios::ChassisType::is_portable
$portableTypes = @(8, 9, 10, 11, 12, 14, 30, 31, 32)

$result = [pscustomobject]@{
    product         = 'SnipeSpotter'
    capability      = 'chassis-recon'
    captured_at     = (Get-Date -Format 'o')
    chassis_types   = $chassisTypes
    primary_type    = $primaryType
    type_name       = if ($typeNames.ContainsKey($primaryType)) { $typeNames[$primaryType] } else { 'Unknown' }
    is_portable     = ($portableTypes -contains $primaryType)
    manufacturer    = $enclosure.Manufacturer
    model           = $enclosure.Model
    serial_number   = $enclosure.SerialNumber
    asset_tag       = $enclosure.SMBIOSAssetTag
}

$result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "Chassis fixture written to $OutputPath (type $primaryType, $($result.type_name), portable=$($result.is_portable))"
