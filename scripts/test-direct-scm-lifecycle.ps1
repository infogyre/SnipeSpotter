#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CliPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServicePath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunIdentity,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DataRoot,
    [string]$LogDirectory = "$env:RUNNER_TEMP\snipespotter-direct-scm-logs",
    [ValidateRange(5, 600)]
    [int]$WaitTimeoutSeconds = 90,
    [ValidateRange(1, 30)]
    [int]$PollIntervalSeconds = 1,
    [ValidateRange(185, 1200)]
    [int]$ProcessTimeoutSeconds = 185
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The registrar bounds stop and delete waits independently at 90 seconds each.
$RegistrarWaitTimeoutSeconds = 90
$MinimumProcessTimeoutSeconds = ($RegistrarWaitTimeoutSeconds * 2) + 5

# This harness consumes test-support CLI arguments and never uses the MSI-owned service identity.
$testSupportRoot = Join-Path $PSScriptRoot 'TestSupport'
Import-Module (Join-Path $testSupportRoot 'Scm.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Acl.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Security.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Diagnostics.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Cleanup.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Wait.psm1') -Force

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory = $true)][string]$Message)
    if (-not $Condition) { throw $Message }
}

Assert-True ($ProcessTimeoutSeconds -ge $MinimumProcessTimeoutSeconds) "ProcessTimeoutSeconds must be at least $MinimumProcessTimeoutSeconds seconds"

function Invoke-DirectCli {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CliPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "$Description could not start" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($ProcessTimeoutSeconds * 1000)) {
        try { $process.Kill($true) } catch { Write-Warning "could not terminate ${Description}: $($_.Exception.Message)" }
        throw "$Description did not exit within $ProcessTimeoutSeconds seconds"
    }
    $exitCode = $process.ExitCode
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $process.Dispose()
    [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        Description = $Description
    }
}

function Get-CommonCliArgument {
    @(
        '--test-service-name', $serviceName,
        '--test-data-root', $DataRoot,
        '--test-pipe-endpoint', $pipeEndpoint,
        '--test-mutex-name', $mutexName,
        '--test-service-executable', $ServicePath
    )
}

function Invoke-DirectUninstall {
    $result = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'uninstall')) -Description 'ServiceUninstall'
    if ($result.ExitCode -ne 0) {
        throw "direct service uninstall failed with exit code $($result.ExitCode): $($result.Stderr.Trim())"
    }
}

function Get-DirectStatus {
    $result = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('--json', 'status')) -Description 'StatusHealthCheck'
    if ($result.ExitCode -ne 0) { return $null }
    try {
        $status = $result.Stdout | ConvertFrom-Json
        if ($status.type -ne 'status') { return $null }
        return $status
    } catch {
        return $null
    }
}

function Assert-DirectRuntimeAcl {
    param([Parameter(Mandatory = $true)][object[]]$Artifacts)

    $normalizedRules = @(Get-NormalizedAcl -Path $DataRoot)
    Assert-True ($normalizedRules.Count -gt 0) 'direct service data root has no ACL rules'
    [void](Assert-AclContract -Path $DataRoot)
    foreach ($artifact in $Artifacts) {
        if ($artifact.Path -ne $DataRoot) {
            [void](Assert-AclContract -Path $artifact.Path)
        }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-True $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'direct SCM lifecycle requires an elevated administrator token'
Assert-True ($RunIdentity -match '^[A-Za-z0-9-]+$') 'RunIdentity must contain only letters, digits, and hyphens'

$CliPath = (Resolve-Path -LiteralPath $CliPath).Path
$ServicePath = (Resolve-Path -LiteralPath $ServicePath).Path
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Force -Path $LogDirectory, $DataRoot | Out-Null
Assert-True ([IO.Path]::GetExtension($CliPath) -ieq '.exe') 'CliPath must point to an executable'
Assert-True ([IO.Path]::GetExtension($ServicePath) -ieq '.exe') 'ServicePath must point to an executable'

$serviceName = "SnipeSpotterDirect-$RunIdentity"
$pipeEndpoint = "\\.\pipe\SnipeSpotterDirect-$RunIdentity"
$mutexName = "Global\SnipeSpotterDirect-$RunIdentity"
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
Assert-True ($null -eq $service) "refusing to mutate pre-existing unique service $serviceName"

$primaryError = $null
$cleanupError = $null
try {
    $install = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'install')) -Description 'ServiceInstall'
    Assert-True ($install.ExitCode -eq 0) "direct service install failed: $($install.Stderr.Trim())"

    $duplicate = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'install')) -Description 'DuplicateServiceInstall'
    Assert-True ($duplicate.ExitCode -eq 1) "already-installed contract returned exit code $($duplicate.ExitCode)"
    Assert-True ($duplicate.Stderr.Contains('already installed')) 'already-installed contract did not report an actionable error'

    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-True ($null -ne $service) 'ServiceQueryConfig could not find the direct service registration'
    Assert-True ($service.StartMode -eq 'Auto') "direct service start mode was $($service.StartMode), expected Auto"
    Assert-True ($service.StartName -in @('LocalSystem', 'LocalSystem account')) "direct service account was $($service.StartName), expected LocalSystem"
    Assert-True ($service.PathName.Contains($ServicePath)) 'direct service registration omitted the service executable path'
    foreach ($runtimeValue in @($serviceName, $DataRoot, $pipeEndpoint, $mutexName)) {
        Assert-True ($service.PathName.Contains($runtimeValue)) "direct service registration omitted runtime value $runtimeValue"
    }
    Assert-True ($service.PathName -match '(?i)spotter-svc\.exe') 'direct service registration is not an own-process service executable'

    Start-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Running' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Wait-ConditionStable -Description "direct service $serviceName to remain Running" -StabilitySeconds 5 -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $null -ne $candidate -and $candidate.Status -eq 'Running'
    }
    Assert-ServiceRunsAsSystem -Name $serviceName
    Wait-Condition -Description "direct service $serviceName status response" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $status = Get-DirectStatus
        $null -ne $status -and $status.data.state -eq 'Unconfigured'
    } | Out-Null

    $runtimeArtifacts = @(
        [pscustomobject]@{ Path = $DataRoot; Type = 'Container' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'settings.toml'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'state-hmac-key.bin'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'logs'); Type = 'Container' }
    )
    foreach ($artifact in $runtimeArtifacts) {
        Wait-Condition -Description "direct runtime artifact $($artifact.Path)" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            Test-Path -LiteralPath $artifact.Path -PathType $artifact.Type
        } | Out-Null
    }
    foreach ($optionalArtifact in @('state.toml', 'operations.jsonl')) {
        $optionalPath = Join-Path $DataRoot $optionalArtifact
        if (Test-Path -LiteralPath $optionalPath -PathType Leaf) {
            $runtimeArtifacts += [pscustomobject]@{ Path = $optionalPath; Type = 'Leaf' }
        }
    }
    $logFiles = @(
        Wait-Condition -Description 'direct service rolling log file' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            @(Get-ChildItem -LiteralPath (Join-Path $DataRoot 'logs') -Filter 'spotter-svc.log*' -File -ErrorAction SilentlyContinue)
        }
    )
    $runtimeArtifacts += @(
        $logFiles | ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Type = 'Leaf' }
        }
    )
    Assert-DirectRuntimeAcl -Artifacts $runtimeArtifacts

    $standardUser = New-TemporaryStandardUser -Name ("SpotterAcl" + (Get-Random -Minimum 10000 -Maximum 99999))
    try {
        foreach ($artifact in $runtimeArtifacts) {
            $probeResult = Assert-StandardUserCannotReadWrite -User $standardUser -Path $artifact.Path -PathType $artifact.Type -TimeoutSeconds $WaitTimeoutSeconds
            [void](Assert-ChildIsStandardUser -Result $probeResult)
        }
    } finally {
        Remove-TemporaryStandardUser -User $standardUser
    }

    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Stopped' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Invoke-DirectUninstall
    Wait-ServiceRemoved -Name $serviceName -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds

    $missing = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'uninstall')) -Description 'MissingServiceUninstall'
    Assert-True ($missing.ExitCode -eq 1) "missing-service contract returned exit code $($missing.ExitCode)"
    Assert-True ($missing.Stderr.Contains('not installed')) 'missing-service contract did not report an actionable error'
} catch {
    $primaryError = $_
    Write-BoundedDiagnostic -Path (Join-Path $LogDirectory 'failure-state.json') -Values @{
        phase = 'direct-scm-failure'
        service_name = $serviceName
        service_status = if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { 'absent' } else { (Get-Service -Name $serviceName).Status.ToString() }
        data_root_exists = [bool](Test-Path -LiteralPath $DataRoot)
    }
} finally {
    try {
        Invoke-FailureSafeCleanup -Actions @(
            {
                $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Invoke-DirectUninstall
                }
            },
            {
                Wait-ServiceRemoved -Name $serviceName -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
            },
            {
                if (Test-Path -LiteralPath $DataRoot) {
                    Remove-Item -LiteralPath $DataRoot -Recurse -Force
                }
            }
        ) -FailurePrefix 'direct SCM cleanup failed'
    } catch {
        $cleanupError = $_
    }
}

if ($primaryError -or $cleanupError) {
    $messages = @()
    if ($primaryError) { $messages += "direct SCM lifecycle failed: $($primaryError.Exception.Message)" }
    if ($cleanupError) { $messages += "direct SCM cleanup failed: $($cleanupError.Exception.Message)" }
    throw ($messages -join '; ')
}

Write-Output 'direct SCM lifecycle validation passed'
