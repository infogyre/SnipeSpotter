Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Wait-Condition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $false)][ValidateRange(1, 60)][int]$PollIntervalSeconds = 1
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = $null
    while ($true) {
        try {
            $value = & $Condition
            if ($value) { return $value }
        } catch {
            $lastError = $_.Exception.Message
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            $detail = if ($lastError) { " Last error: $lastError" } else { '' }
            throw "timed out waiting for $Description after $TimeoutSeconds seconds.$detail"
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }
}

function Wait-ConditionStable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$StabilitySeconds,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $false)][ValidateRange(1, 60)][int]$PollIntervalSeconds = 1
    )

    if ($StabilitySeconds -gt $TimeoutSeconds) {
        throw "stability window for $Description cannot exceed timeout"
    }

    $frequency = [Diagnostics.Stopwatch]::Frequency
    $timeoutTicks = [int64]$TimeoutSeconds * $frequency
    $stabilityTicks = [int64]$StabilitySeconds * $frequency
    $startedAt = [Diagnostics.Stopwatch]::GetTimestamp()
    $timeoutDeadline = $startedAt + $timeoutTicks
    $stableDeadline = $null
    $lastError = $null

    while ($true) {
        $now = [Diagnostics.Stopwatch]::GetTimestamp()
        if ($now -ge $timeoutDeadline) {
            $detail = if ($lastError) { " Last error: $lastError" } else { '' }
            throw "timed out waiting for $Description to remain true for $StabilitySeconds seconds after $TimeoutSeconds seconds.$detail"
        }

        try {
            $value = & $Condition
            if ($value) {
                if ($null -eq $stableDeadline) {
                    $stableDeadline = $now + $stabilityTicks
                } elseif ($now -ge $stableDeadline) {
                    return $true
                }
                $lastError = $null
            } else {
                $stableDeadline = $null
            }
        } catch {
            $lastError = $_.Exception.Message
            $stableDeadline = $null
        }

        $remainingTicks = $timeoutDeadline - [Diagnostics.Stopwatch]::GetTimestamp()
        if ($remainingTicks -le 0) { continue }
        $remainingMilliseconds = [Math]::Max(1, [int][Math]::Floor(($remainingTicks * 1000.0) / $frequency))
        $sleepMilliseconds = [Math]::Min($remainingMilliseconds, $PollIntervalSeconds * 1000)
        Start-Sleep -Milliseconds $sleepMilliseconds
    }
}

Export-ModuleMember -Function Wait-Condition, Wait-ConditionStable
