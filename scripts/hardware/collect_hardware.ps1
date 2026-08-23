[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('windows-2022', 'windows-latest', 'windows-2025')]
    [string]$Image,
    [Parameter(Mandatory = $true)]
    [ValidateSet('windows-2022', 'windows-latest', 'windows-2025')]
    [string]$ImageAlias,
    [Parameter(Mandatory = $true)]
    [ValidateSet('interactive-admin', 'LocalSystem')]
    [string]$Context,
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 3)]
    [int]$Repetition,
    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 10000)]
    [int]$SessionId,
    [Parameter(Mandatory = $false)]
    [string]$HmacKeyHex,
    [Parameter(Mandatory = $false)]
    [string]$HmacKeyPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ImageAlias -ne $Image) { throw 'image alias must match image' }
$MaxReportBytes = 32768
$MaxRows = 32
$MaxTypes = 128

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$runtimePrincipal = $identity.Name
if ($Context -eq 'LocalSystem' -and $runtimePrincipal -ne 'NT AUTHORITY\SYSTEM') {
    throw 'LocalSystem context did not run as NT AUTHORITY\\SYSTEM'
}
if ($Context -eq 'interactive-admin' -and $runtimePrincipal -eq 'NT AUTHORITY\SYSTEM') {
    throw 'interactive-admin context unexpectedly ran as LocalSystem'
}

if ([string]::IsNullOrWhiteSpace($HmacKeyHex) -and -not [string]::IsNullOrWhiteSpace($HmacKeyPath)) {
    $HmacKeyHex = [IO.File]::ReadAllText($HmacKeyPath).Trim()
}
if ($HmacKeyHex -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'HMAC key must be supplied as 32 bytes of hexadecimal text'
}
$hmacKey = [Convert]::FromHexString($HmacKeyHex)
$hmac = [Security.Cryptography.HMACSHA256]::new($hmacKey)

function Get-HmacFragment {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $digest = $hmac.ComputeHash($bytes)
        return (-join ($digest[0..7] | ForEach-Object { $_.ToString('x2') }))
    } finally {
        $bytes = $null
    }
}

function Get-ClassifiedError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $message = $ErrorRecord.Exception.Message.ToLowerInvariant()
    if ($message -match 'access is denied|unauthorized|permission') { return 'access_denied' }
    if ($message -match 'timeout|timed out') { return 'timeout' }
    return 'error'
}

function Invoke-Bounded {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $value = & $Action
        return [ordered]@{
            api = $Name
            result = 'ok'
            duration_ms = [Math]::Min(120000, [int]$timer.ElapsedMilliseconds)
            value = $value
        }
    } catch {
        return [ordered]@{
            api = $Name
            result = Get-ClassifiedError $_
            duration_ms = [Math]::Min(120000, [int]$timer.ElapsedMilliseconds)
        }
    }
}

function Get-RsmbSummary {
    $result = Invoke-Bounded -Name 'GetSystemFirmwareTable' -Action {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SpotterFirmware {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint GetSystemFirmwareTable(uint provider, uint id, IntPtr buffer, uint size);
}
'@
        $rsmb = [Text.Encoding]::ASCII.GetBytes('RSMB')
        $provider = [uint32]($rsmb[0] * 0x1000000 + $rsmb[1] * 0x10000 + $rsmb[2] * 0x100 + $rsmb[3])
        $length = [SpotterFirmware]::GetSystemFirmwareTable($provider, 0, [IntPtr]::Zero, 0)
        if ($length -le 0) { throw 'firmware size unavailable' }
        $boundedLength = [Math]::Min([int]$length, 16384)
        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($boundedLength)
        try {
            $written = [SpotterFirmware]::GetSystemFirmwareTable($provider, 0, $buffer, [uint32]$boundedLength)
            $actualLength = [Math]::Min([int]$written, $boundedLength)
            if ($actualLength -lt 8) { throw 'firmware table header unavailable' }

            $data = New-Object byte[] $actualLength
            [Runtime.InteropServices.Marshal]::Copy($buffer, $data, 0, $actualLength)
            $reportedTableLength = [BitConverter]::ToUInt32($data, 4)
            $tableStart = 8
            $tableLength = [Math]::Min([int]$reportedTableLength, $actualLength - $tableStart)
            $tableEnd = $tableStart + $tableLength
            $structureCount = 0
            $typeHistogram = [ordered]@{}
            $offset = $tableStart
            $parseCapped = $length -gt 16384 -or $reportedTableLength -gt ($actualLength - $tableStart)

            while ($offset + 4 -le $tableEnd -and $structureCount -lt $MaxTypes) {
                $structureType = [int]$data[$offset]
                $structureLength = [int]$data[$offset + 1]
                if ($structureLength -lt 4 -or $offset + $structureLength -gt $tableEnd) { break }

                $end = $offset + $structureLength
                $terminated = $false
                while ($end + 1 -lt $tableEnd) {
                    if ($data[$end] -eq 0 -and $data[$end + 1] -eq 0) {
                        $end += 2
                        $terminated = $true
                        break
                    }
                    $end++
                }
                if (-not $terminated) { break }

                $key = [string]$structureType
                if (-not $typeHistogram.Contains($key)) { $typeHistogram[$key] = 0 }
                $typeHistogram[$key] = [int]$typeHistogram[$key] + 1
                $structureCount++
                $offset = $end
                if ($structureType -eq 127) { break }
            }

            [ordered]@{
                status = 'ok'
                length = $actualLength
                structure_count = $structureCount
                type_histogram = $typeHistogram
                capped = $parseCapped -or ($structureCount -ge $MaxTypes)
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }
    if ($result.result -eq 'ok') {
        return [ordered]@{ summary = $result.value; status = $result.result; duration_ms = $result.duration_ms }
    }
    return [ordered]@{ summary = [ordered]@{ status = $result.result; length = 0; structure_count = 0; type_histogram = [ordered]@{}; capped = $false }; status = $result.result; duration_ms = $result.duration_ms }
}

function Get-WmiSummary {
    $result = Invoke-Bounded -Name 'WmiMonitorID' -Action {
        $rows = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction Stop)
        $rows = @($rows | Select-Object -First $MaxRows)
        $lengths = [ordered]@{
            manufacturer_name = @($rows | ForEach-Object { @($_.ManufacturerName).Count })
            product_code_id = @($rows | ForEach-Object { @($_.ProductCodeID).Count })
            serial_number_id = @($rows | ForEach-Object { @($_.SerialNumberID).Count })
            week_of_manufacture = @($rows | ForEach-Object { 1 })
            year_of_manufacture = @($rows | ForEach-Object { 1 })
        }
        [ordered]@{
            status = 'ok'
            count = $rows.Count
            array_lengths = $lengths
            placeholder_classes = @('empty', 'zero_terminated')
            capped = ($rows.Count -ge $MaxRows)
        }
    }
    if ($result.result -eq 'ok') {
        return [ordered]@{ summary = $result.value; status = $result.result; duration_ms = $result.duration_ms }
    }
    return [ordered]@{
        summary = [ordered]@{ status = $result.result; count = 0; array_lengths = [ordered]@{ manufacturer_name = @(); product_code_id = @(); serial_number_id = @(); week_of_manufacture = @(); year_of_manufacture = @() }; placeholder_classes = @(); capped = $false }
        status = $result.result
        duration_ms = $result.duration_ms
    }
}

function Get-ChassisSummary {
    $result = Invoke-Bounded -Name 'Win32_SystemEnclosure' -Action {
        $rows = @(Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop | Select-Object -First 16)
        $counts = [ordered]@{ portable = 0; desktop = 0; server = 0; enclosure = 0; unknown = 0 }
        foreach ($row in $rows) {
            foreach ($type in @($row.ChassisTypes)) {
                if ($type -in 8, 9, 10, 11, 12, 14, 30, 31, 32) { $counts.portable++ }
                elseif ($type -in 3, 4, 5, 6, 7, 15, 16) { $counts.desktop++ }
                elseif ($type -in 23, 24, 25, 26, 27, 28, 29) { $counts.server++ }
                elseif ($type -gt 0) { $counts.enclosure++ }
                else { $counts.unknown++ }
            }
        }
        [ordered]@{ status = 'ok'; count = $rows.Count; class_counts = $counts; capped = ($rows.Count -ge 16) }
    }
    if ($result.result -eq 'ok') {
        return [ordered]@{ summary = $result.value; status = $result.result; duration_ms = $result.duration_ms }
    }
    return [ordered]@{
        summary = [ordered]@{ status = $result.result; count = 0; class_counts = [ordered]@{ portable = 0; desktop = 0; server = 0; enclosure = 0; unknown = 0 }; capped = $false }
        status = $result.result
        duration_ms = $result.duration_ms
    }
}

$build = [ordered]@{
    image = $Image
    image_alias = $ImageAlias
    image_os = ([Environment]::GetEnvironmentVariable('ImageOS') ?? 'unknown')
    image_version = ([Environment]::GetEnvironmentVariable('ImageVersion') ?? 'unknown')
    os_build = [Environment]::OSVersion.Version.Build
    powershell_version = $PSVersionTable.PSVersion.ToString()
    runner_architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { 'X64' } else { $env:PROCESSOR_ARCHITECTURE }
}
$apiResults = @(
    [ordered]@{ api = 'process_identity'; result = 'ok'; duration_ms = 0 }
    [ordered]@{ api = 'smbios'; result = 'ok'; duration_ms = 0 }
    [ordered]@{ api = 'wmi_monitors'; result = 'ok'; duration_ms = 0 }
    [ordered]@{ api = 'chassis'; result = 'ok'; duration_ms = 0 }
)
$smbiosResult = Get-RsmbSummary
$wmiResult = Get-WmiSummary
$chassisResult = Get-ChassisSummary
$smbios = $smbiosResult['summary']
$wmi = $wmiResult['summary']
$chassis = $chassisResult['summary']
$apiResults[1].result = $smbiosResult.status
$apiResults[2].result = $wmiResult.status
$apiResults[3].result = $chassisResult.status
$apiResults[1].duration_ms = $smbiosResult.duration_ms
$apiResults[2].duration_ms = $wmiResult.duration_ms
$apiResults[3].duration_ms = $chassisResult.duration_ms

$machineFragment = Get-HmacFragment -Value ($env:COMPUTERNAME ?? 'unknown-machine')
$hmacFragments = @(
    [ordered]@{ kind = 'machine'; fragment = $machineFragment }
)
$report = [ordered]@{
    schema_version = 1
    experiment = [ordered]@{ image = $Image; context = $Context; repetition = $Repetition; caller_class = $Context; session_id = $SessionId }
    build = $build
    process = [ordered]@{ bitness = [IntPtr]::Size * 8 }
    privacy = [ordered]@{ hmac_algorithm = 'HMAC-SHA256'; hmac_key_uploaded = $false; raw_identifiers_emitted = $false; raw_payloads_emitted = $false; max_report_bytes = $MaxReportBytes }
    api_results = $apiResults
    smbios = $smbios
    wmi = $wmi
    chassis = $chassis
    hmac_fragments = $hmacFragments
}
$json = $report | ConvertTo-Json -Depth 8 -Compress
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
if ($bytes.Length -gt $MaxReportBytes) { throw 'redacted hardware report exceeded bounded size' }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
[IO.File]::WriteAllBytes($OutputPath, $bytes)
Write-Output $OutputPath
