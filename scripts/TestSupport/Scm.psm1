Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $moduleRoot 'Wait.psm1') -Force

function Get-ServiceProcessOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name)

    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if ($null -eq $service) { throw "service $Name was not found" }
    if ($service.State -ne 'Running') { throw "service $Name is not Running" }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
    if ($null -eq $process) { throw "service $Name process $($service.ProcessId) was not found" }
    $owner = $process | Invoke-CimMethod -MethodName GetOwner
    if ($owner.ReturnValue -ne 0) { throw "could not query runtime owner for service $Name" }
    if ([string]::IsNullOrWhiteSpace($owner.User)) { throw "runtime owner for service $Name is empty" }
    if ($owner.Domain) { return "$($owner.Domain)\$($owner.User)" }
    return $owner.User
}

function Assert-ServiceRunsAsSystem {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name)

    $owner = Get-ServiceProcessOwner -Name $Name
    if ($owner -ne 'NT AUTHORITY\SYSTEM') {
        throw "service $Name runtime owner was $owner, expected NT AUTHORITY\SYSTEM"
    }
    return $owner
}

function Wait-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Running', 'Stopped')][string]$State,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $false)][ValidateRange(1, 60)][int]$PollIntervalSeconds = 1
    )

    Wait-Condition -Description "service $Name to reach $State" -TimeoutSeconds $TimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        $null -ne $service -and $service.Status.ToString() -eq $State
    }
}

function Wait-ServiceRemoved {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $false)][ValidateRange(1, 60)][int]$PollIntervalSeconds = 1
    )

    Wait-Condition -Description "service $Name removal" -TimeoutSeconds $TimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $null -eq (Get-Service -Name $Name -ErrorAction SilentlyContinue)
    }
}

Export-ModuleMember -Function Get-ServiceProcessOwner, Assert-ServiceRunsAsSystem, Wait-ServiceState, Wait-ServiceRemoved
