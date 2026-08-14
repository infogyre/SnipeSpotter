[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[pscustomobject]@{
    product = 'SnipeSpotter'
    phase = 0
    capability = 'smbios-recon'
    status = 'not_implemented'
} | ConvertTo-Json -Compress
