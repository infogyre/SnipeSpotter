[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[pscustomobject]@{
    product = 'SnipeSpotter'
    phase = 0
    capability = 'wmi-monitors-recon'
    status = 'not_implemented'
} | ConvertTo-Json -Compress
