[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\smbios-fixture.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Captures raw SMBIOS firmware table data via GetSystemFirmwareTable
# and writes a JSON fixture file for use as test data by spotter-core's
# SMBIOS parser. Run on target hardware to produce realistic fixtures.
#
# Requires Windows and an elevated PowerShell session.

$signature = @'
using System;
using System.Runtime.InteropServices;

public static class Firmware
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetSystemFirmwareTable(
        uint FirmwareTableProviderSignature,
        uint FirmwareTableID,
        [Out] byte[] pFirmwareTableBuffer,
        uint BufferSize);

    public const uint RSMB = 0x52534D42; // 'RSMB'
}
'@

$type = Add-Type -TypeDefinition $signature -PassThru

# 'FIRM' table ID = 0x4649524D
$firmId = [BitConverter]::ToUInt32([System.Text.Encoding]::ASCII.GetBytes('FIRM'), 0)

# First call to get required buffer size
$size = $type::GetSystemFirmwareTable($type::RSMB, $firmId, $null, 0)
if ($size -eq 0) {
    throw "GetSystemFirmwareTable returned zero size — SMBIOS data may be unavailable"
}

$buffer = New-Object byte[] $size
$written = $type::GetSystemFirmwareTable($type::RSMB, $firmId, $buffer, $size)
if ($written -eq 0) {
    $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "GetSystemFirmwareTable failed with Win32 error $code"
}

# Trim to actual bytes written
if ($written -lt $size) {
    $buffer = $buffer[0..($written - 1)]
}

$hex = [BitConverter]::ToString($buffer) -replace '-', ''
$base64 = [Convert]::ToBase64String($buffer)

$result = [pscustomobject]@{
    product       = 'SnipeSpotter'
    capability    = 'smbios-recon'
    captured_at   = (Get-Date -Format 'o')
    raw_hex       = $hex
    raw_base64    = $base64
    byte_count    = $buffer.Length
}

$result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "SMBIOS fixture written to $OutputPath ($($buffer.Length) bytes)"
