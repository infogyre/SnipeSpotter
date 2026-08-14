[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\wmi-monitors-fixture.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Queries WMI WmiMonitorID in root\wmi and writes structured monitor
# data (manufacturer code, product code, serial, week/year) as a JSON
# fixture file. Run on target hardware with connected monitors to
# produce test data for spotter-svc's monitor discovery code.
#
# Requires Windows.

$monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop

$entries = foreach ($mon in $monitors) {
    # WmiMonitorID returns fixed-length char arrays that are null-padded.
    # Extract the active portion and join into a string.
    function Convert-CharArray {
        param([uint16[]]$Chars)
        if ($null -eq $Chars) { return '' }
        $sb = New-Object System.Text.StringBuilder
        foreach ($c in $Chars) {
            if ($c -eq 0) { break }
            [void]$sb.Append([char]$c)
        }
        return $sb.ToString()
    }

    [pscustomobject]@{
        instance_name       = $mon.InstanceName
        manufacturer_code   = (Convert-CharArray $mon.ManufacturerName)
        product_code        = (Convert-CharArray $mon.ProductCodeID)
        serial              = (Convert-CharArray $mon.SerialNumberID)
        manufacture_week    = $mon.WeekOfManufacture
        manufacture_year    = $mon.YearOfManufacture
    }
}

$result = [pscustomobject]@{
    product     = 'SnipeSpotter'
    capability  = 'wmi-monitors-recon'
    captured_at = (Get-Date -Format 'o')
    monitor_count = ($entries | Measure-Object).Count
    monitors    = @($entries)
}

$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "WMI monitors fixture written to $OutputPath ($(($entries | Measure-Object).Count) monitors)"
