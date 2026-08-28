Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-FailureSafeCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock[]]$Actions,
        [Parameter(Mandatory = $false)][string]$FailurePrefix = 'cleanup failed',
        [Parameter(Mandatory = $false)][string]$DiagnosticPath,
        [Parameter(Mandatory = $false)][ValidateRange(1024, 65536)][int]$MaxDiagnosticBytes = 32768
    )

    $failures = @()
    foreach ($action in $Actions) {
        try {
            & $action
        } catch {
            $failures += $_.Exception.Message
        }
    }
    if ($failures.Count -gt 0) {
        if (-not [string]::IsNullOrWhiteSpace($DiagnosticPath)) {
            $parent = Split-Path -Parent $DiagnosticPath
            if (-not [string]::IsNullOrWhiteSpace($parent)) {
                New-Item -ItemType Directory -Force -Path $parent | Out-Null
            }
            $payload = [ordered]@{
                failure_prefix = $FailurePrefix
                failures = @($failures | ForEach-Object {
                    if ($_.Length -gt 4096) { $_.Substring(0, 4096) } else { $_ }
                })
            } | ConvertTo-Json -Depth 3 -Compress
            if ($payload.Length -gt $MaxDiagnosticBytes) {
                $payload = $payload.Substring(0, $MaxDiagnosticBytes)
            }
            [IO.File]::WriteAllText($DiagnosticPath, $payload)
        }
        throw "${FailurePrefix}: $($failures -join '; ')"
    }
}

Export-ModuleMember -Function Invoke-FailureSafeCleanup
