Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-FailureSafeCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock[]]$Actions,
        [Parameter(Mandatory = $false)][string]$FailurePrefix = 'cleanup failed'
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
        throw "${FailurePrefix}: $($failures -join '; ')"
    }
}

Export-ModuleMember -Function Invoke-FailureSafeCleanup
