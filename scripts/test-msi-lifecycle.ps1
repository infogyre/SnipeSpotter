#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MsiPath,
    [string]$PreviousMsiPath,
    [string]$LogDirectory = "$env:RUNNER_TEMP\snipespotter-msi-logs",
    [ValidateRange(5, 600)]
    [int]$WaitTimeoutSeconds = 90,
    [ValidateRange(1, 30)]
    [int]$PollIntervalSeconds = 2,
    [ValidateRange(1, 60)]
    [int]$StableRunningSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testSupportRoot = Join-Path $PSScriptRoot 'TestSupport'
Import-Module (Join-Path $testSupportRoot 'Scm.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Wait.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Diagnostics.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Security.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Cleanup.psm1') -Force

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$MaxServiceLogBytes = 32768
$MaxServiceLogFiles = 4
$MaxServiceLogTotalBytes = 65536
$ServiceLogTruncationMarker = '...[truncated]'

function Get-ServiceStatusForDiagnostic {
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { return 'absent' }
    return $service.Status.ToString()
}

function Save-ServiceLogDiagnostic {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DataRoot,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Destination
    )

    try {
        $logDirectory = Join-Path $DataRoot 'logs'
        if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) { return }
        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        $totalBytes = 0
        Get-ChildItem -LiteralPath $logDirectory -Filter 'spotter-svc.log*' -File -ErrorAction Stop |
            Sort-Object Name |
            Select-Object -First $MaxServiceLogFiles |
            ForEach-Object {
                $log = $_
                $logName = $log.Name
                try {
                    if ($totalBytes -ge $MaxServiceLogTotalBytes) { return }
                    $remainingBytes = $MaxServiceLogTotalBytes - $totalBytes
                    $bytesToRead = [Math]::Min($MaxServiceLogBytes, $remainingBytes)
                    $source = [IO.File]::OpenRead($log.FullName)
                    try {
                        $logSize = [int64](Get-Item -LiteralPath $log.FullName -Force -ErrorAction Stop).Length
                        $wasTruncated = $logSize -gt $bytesToRead
                        if ($wasTruncated) {
                            $markerBytes = [Text.Encoding]::UTF8.GetBytes($ServiceLogTruncationMarker)
                            $bytesToRead = [Math]::Max(0, $bytesToRead - $markerBytes.Length)
                        } else {
                            $markerBytes = [byte[]]@()
                        }
                        if ($bytesToRead -le 0) { return }
                        $buffer = New-Object byte[] $bytesToRead
                        $bytesRead = $source.Read($buffer, 0, $buffer.Length)
                        $contentBytes = if ($wasTruncated) {
                            $output = New-Object byte[] ($bytesRead + $markerBytes.Length)
                            [Array]::Copy($buffer, 0, $output, 0, $bytesRead)
                            [Array]::Copy($markerBytes, 0, $output, $bytesRead, $markerBytes.Length)
                            $output
                        } else {
                            if ($bytesRead -eq $buffer.Length) {
                                $buffer
                            } else {
                                $trimmed = New-Object byte[] $bytesRead
                                [Array]::Copy($buffer, 0, $trimmed, 0, $bytesRead)
                                $trimmed
                            }
                        }
                        [IO.File]::WriteAllBytes((Join-Path $Destination $logName), $contentBytes)
                        $totalBytes += $contentBytes.Length
                    } finally {
                        $source.Dispose()
                    }
                } catch {
                    Write-Warning "could not capture service log ${logName}: $($_.Exception.Message)"
                }
            }
    } catch {
        Write-Warning "service log capture failed: $($_.Exception.Message)"
    }
}

function Get-MachinePathEntry {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ([string]::IsNullOrWhiteSpace($machinePath)) { return @() }
    return @(
        $machinePath.Split(';') |
            ForEach-Object { $_.Trim().TrimEnd('\') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Invoke-MsiExec {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "msiexec failed with exit code $($process.ExitCode)"
    }
}

function Invoke-InstalledCli {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $cliPath = Join-Path $binRoot 'spotter-cli.exe'
    Assert-True (Test-Path -LiteralPath $cliPath -PathType Leaf) "installed CLI is missing: $cliPath"
    $stdoutPath = Join-Path $LogDirectory 'cli-stdout.txt'
    $stderrPath = Join-Path $LogDirectory 'cli-stderr.txt'
    $process = Start-Process -FilePath $cliPath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = Get-BoundedText -Path $stdoutPath -MaxCharacters 65536
        Stderr = Get-BoundedText -Path $stderrPath -MaxCharacters 512
        Description = $Description
    }
}

function Assert-InstalledCliContract {
    param(
        [Parameter(Mandatory = $true)][psobject]$Result,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [Parameter(Mandatory = $true)][string]$ExpectedStdout,
        [Parameter(Mandatory = $true)][string]$ExpectedStderr
    )

    Assert-True ($Result.ExitCode -eq $ExpectedExitCode) "installed CLI $($Result.Description) returned an unexpected exit code"
    Assert-True ($Result.Stdout -ceq $ExpectedStdout) "installed CLI $($Result.Description) returned an unexpected stdout contract"
    Assert-True ($Result.Stderr -ceq $ExpectedStderr) "installed CLI $($Result.Description) returned an unexpected stderr contract"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-True $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'MSI lifecycle test requires an elevated administrator token'

New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
Assert-True ([IO.Path]::GetExtension($MsiPath) -ieq '.msi') 'MsiPath must point to an MSI file'
if ($PreviousMsiPath) {
    $PreviousMsiPath = (Resolve-Path -LiteralPath $PreviousMsiPath).Path
    Assert-True ([IO.Path]::GetExtension($PreviousMsiPath) -ieq '.msi') 'PreviousMsiPath must point to an MSI file'
}

$installRoot = Join-Path $env:ProgramFiles 'infogyre\SnipeSpotter'
$binRoot = Join-Path $installRoot 'bin'
$dataRoot = Join-Path $env:ProgramData 'infogyre\SnipeSpotter'
$settingsPath = Join-Path $dataRoot 'settings.toml'
$serviceName = 'SnipeSpotter'

$installAttempted = $false
$primaryError = $null
$cleanupError = $null
try {
    if ($PreviousMsiPath) {
        Invoke-MsiExec @('/i', $PreviousMsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'previous-install.log'))
        Wait-Condition -Description 'previous settings.toml' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            Test-Path -LiteralPath $settingsPath -PathType Leaf
        }
        Add-Content -LiteralPath $settingsPath -Value "`n# lifecycle-preservation-marker"
    }

    $installAttempted = $true
    Invoke-MsiExec @('/i', $MsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'install.log'))

    Wait-Condition -Description 'SnipeSpotter service registration' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $null -ne (Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue)
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-True ($service.StartMode -eq 'Auto') "service start mode is $($service.StartMode), expected Auto"
    Assert-True ($service.StartName -in @('LocalSystem', 'LocalSystem account')) "service account is $($service.StartName), expected LocalSystem"
    $expectedExe = Join-Path $binRoot 'spotter-svc.exe'
    Assert-True ($service.PathName.Trim('"') -eq $expectedExe) "service path is $($service.PathName), expected $expectedExe"

    Start-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Running' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Wait-ConditionStable -Description "service $serviceName to remain Running" -StabilitySeconds $StableRunningSeconds -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $null -ne $candidate -and $candidate.Status -eq 'Running'
    }
    Assert-ServiceRunsAsSystem -Name $serviceName
    $pipePath = '\\.\pipe\SnipeSpotter'
    Wait-Condition -Description 'SnipeSpotter named pipe' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        Test-Path -LiteralPath $pipePath
    } | Out-Null
    Wait-Condition -Description 'SnipeSpotter status response' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        try {
            $candidate = (Invoke-InstalledCli -Arguments @('--json', 'status') -Description 'installed CLI status request').Stdout | ConvertFrom-Json
            $candidate.type -eq 'status' -and $candidate.data.state -eq 'Unconfigured'
        } catch {
            $false
        }
    } | Out-Null

    foreach ($relative in @(
        'bin\spotter-svc.exe',
        'bin\spotter-cli.exe',
        'bin\spotter_svc.pdb',
        'bin\spotter_cli.pdb',
        'sbom\spotter-svc.cdx.json',
        'sbom\spotter-cli.cdx.json'
    )) {
        Assert-True (Test-Path -LiteralPath (Join-Path $installRoot $relative) -PathType Leaf) "missing installed artifact: $relative"
    }
    Assert-True (Test-Path -LiteralPath $settingsPath -PathType Leaf) 'settings.toml was not installed'
    if ($PreviousMsiPath) {
        Assert-True ((Get-Content -Raw -LiteralPath $settingsPath).Contains('# lifecycle-preservation-marker')) 'major upgrade did not preserve settings.toml'
    }
    Assert-True ((Get-MachinePathEntry) -contains $binRoot) 'MSI did not append the binary directory to machine PATH'

    $logFiles = @(
        Wait-Condition -Description 'service rolling log file' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            @(Get-ChildItem -LiteralPath (Join-Path $dataRoot 'logs') -Filter 'spotter-svc.log*' -File -ErrorAction SilentlyContinue)
        }
    )
    $runtimeArtifacts = @(
        [pscustomobject]@{ Path = $dataRoot; Type = 'Container' },
        [pscustomobject]@{ Path = $settingsPath; Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $dataRoot 'state.toml'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $dataRoot 'state-hmac-key.bin'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $dataRoot 'operations.jsonl'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $dataRoot 'logs'); Type = 'Container' }
    )
    $runtimeArtifacts += @(
        $logFiles | ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Type = 'Leaf' }
        }
    )
    foreach ($artifact in $runtimeArtifacts) {
        Wait-Condition -Description "runtime artifact $($artifact.Path)" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            Test-Path -LiteralPath $artifact.Path -PathType $artifact.Type
        } | Out-Null
    }
    [void](Assert-AclContract -Path $dataRoot)
    $artifactAclBefore = @{}
    foreach ($artifact in $runtimeArtifacts) {
        $artifactAclBefore[$artifact.Path] = @(Get-NormalizedAcl -Path $artifact.Path)
    }

    $replacementInterval = '12'
    $settingsUpdate = Invoke-InstalledCli -Arguments @('config', 'set', 'polling.interval_hours', $replacementInterval) -Description 'installed settings update'
    Assert-InstalledCliContract -Result $settingsUpdate -ExpectedExitCode 0 -ExpectedStdout 'updated polling.interval_hours' -ExpectedStderr ''
    Wait-Condition -Description 'settings committed by CLI' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        try {
            $settingsText = Get-Content -Raw -LiteralPath $settingsPath -ErrorAction Stop
            $settingsText.Contains("interval_hours = $replacementInterval")
        } catch {
            $false
        }
    } | Out-Null
    Wait-ConditionStable -Description 'settings ACL after atomic replacement' -StabilitySeconds 2 -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = @(Get-NormalizedAcl -Path $settingsPath)
        (Compare-Object $artifactAclBefore[$settingsPath] $candidate | Measure-Object).Count -eq 0
    } | Out-Null

    $standardUser = New-TemporaryStandardUser -Name ("SnipeSpotterAcl" + (Get-Random -Minimum 10000 -Maximum 99999))
    try {
        foreach ($artifact in $runtimeArtifacts) {
            $probeResult = Assert-StandardUserCannotReadWrite -User $standardUser -Path $artifact.Path -PathType $artifact.Type -TimeoutSeconds $WaitTimeoutSeconds
            [void](Assert-ChildIsStandardUser -Result $probeResult)
        }
    } finally {
        Remove-TemporaryStandardUser -User $standardUser
    }

    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-Condition -Description 'SnipeSpotter service to stop' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $null -ne $candidate -and $candidate.Status -eq 'Stopped'
    } | Out-Null
    Start-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Running' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Assert-ServiceRunsAsSystem -Name $serviceName
    foreach ($artifact in $runtimeArtifacts) {
        $afterRestart = @(Get-NormalizedAcl -Path $artifact.Path)
        if ((Compare-Object $artifactAclBefore[$artifact.Path] $afterRestart | Measure-Object).Count -ne 0) {
            throw "runtime artifact ACL changed across service restart: $($artifact.Path)"
        }
    }

    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-Condition -Description 'SnipeSpotter service to stop after ACL verification' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $null -ne $candidate -and $candidate.Status -eq 'Stopped'
    } | Out-Null
} catch {
    $primaryError = $_
    try {
        if (Test-Path -LiteralPath $dataRoot) {
            try {
                [void](Assert-AclContract -Path $dataRoot)
            } catch {
                Write-Warning "observed invalid ACL before diagnostics: $($_.Exception.Message)"
                try {
                    Ensure-AclContract -Path $dataRoot
                } catch {
                    Write-Warning "could not repair ACL for diagnostics: $($_.Exception.Message)"
                }
            }
        }
        Save-ServiceLogDiagnostic -DataRoot $dataRoot -Destination $LogDirectory
    } catch {
        Write-Warning "service log capture failed: $($_.Exception.Message)"
    }
    Write-BoundedDiagnostic -Path (Join-Path $LogDirectory 'failure-state.json') -Values @{
        phase = 'failure'
        service_status = Get-ServiceStatusForDiagnostic -Name $serviceName
        install_root_exists = [bool](Test-Path -LiteralPath $installRoot)
        data_root_exists = [bool](Test-Path -LiteralPath $dataRoot)
        machine_path_contains_bin = [bool]((Get-MachinePathEntry) -contains $binRoot)
    }
} finally {
    $cleanupActions = @(
        {
            if ($installAttempted) {
                Invoke-MsiExec @('/x', $MsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'uninstall.log'))
            }
        }
    )
    try {
        Invoke-FailureSafeCleanup -Actions $cleanupActions
    } catch {
        $cleanupError = $_
        Write-BoundedDiagnostic -Path (Join-Path $LogDirectory 'cleanup-failure-state.json') -Values @{
            phase = 'cleanup-failure'
            service_status = Get-ServiceStatusForDiagnostic -Name $serviceName
            install_root_exists = [bool](Test-Path -LiteralPath $installRoot)
            data_root_exists = [bool](Test-Path -LiteralPath $dataRoot)
            machine_path_contains_bin = [bool]((Get-MachinePathEntry) -contains $binRoot)
        }
    }
}

try {
    Wait-Condition -Description 'SnipeSpotter service removal' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    }
    Wait-Condition -Description 'Program Files installation removal' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        -not (Test-Path -LiteralPath $installRoot)
    }
    Wait-Condition -Description 'machine PATH cleanup' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        (Get-MachinePathEntry) -notcontains $binRoot
    }
} catch {
    if ($null -eq $primaryError) { $primaryError = $_ }
    Write-BoundedDiagnostic -Path (Join-Path $LogDirectory 'post-uninstall-failure-state.json') -Values @{
        phase = 'post-uninstall-failure'
        service_status = Get-ServiceStatusForDiagnostic -Name $serviceName
        install_root_exists = [bool](Test-Path -LiteralPath $installRoot)
        data_root_exists = [bool](Test-Path -LiteralPath $dataRoot)
        machine_path_contains_bin = [bool]((Get-MachinePathEntry) -contains $binRoot)
    }
}

if ($primaryError -or $cleanupError) {
    $messages = @()
    if ($primaryError) { $messages += "MSI lifecycle validation failed: $($primaryError.Exception.Message)" }
    if ($cleanupError) { $messages += "MSI cleanup failed: $($cleanupError.Exception.Message)" }
    throw ($messages -join '; ')
}

Write-Output 'MSI lifecycle validation passed'
