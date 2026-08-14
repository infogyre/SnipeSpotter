[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,
    [string]$PreviousMsiPath,
    [string]$LogDirectory = "$env:RUNNER_TEMP\snipespotter-msi-logs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-MsiExec {
    param([string[]]$Arguments)
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "msiexec failed with exit code $($process.ExitCode): $($Arguments -join ' ')"
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-True $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'MSI lifecycle test requires an elevated administrator token'

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
if ($PreviousMsiPath) { $PreviousMsiPath = (Resolve-Path -LiteralPath $PreviousMsiPath).Path }
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null

$installRoot = Join-Path $env:ProgramFiles 'infogyre\SnipeSpotter'
$binRoot = Join-Path $installRoot 'bin'
$dataRoot = Join-Path $env:ProgramData 'infogyre\SnipeSpotter'
$settingsPath = Join-Path $dataRoot 'settings.toml'
$serviceName = 'SnipeSpotter'

$installAttempted = $false
try {
    if ($PreviousMsiPath) {
        Invoke-MsiExec @('/i', $PreviousMsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'previous-install.log'))
        Assert-True (Test-Path -LiteralPath $settingsPath -PathType Leaf) 'previous MSI did not install settings.toml'
        Add-Content -LiteralPath $settingsPath -Value "`n# lifecycle-preservation-marker"
    }

    $installAttempted = $true
    Invoke-MsiExec @('/i', $MsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'install.log'))

    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-True ($null -ne $service) 'MSI did not register the SnipeSpotter service'
    Assert-True ($service.StartMode -eq 'Auto') "service start mode is $($service.StartMode), expected Auto"
    Assert-True ($service.StartName -in @('LocalSystem', 'LocalSystem account')) "service account is $($service.StartName), expected LocalSystem"
    $expectedExe = Join-Path $binRoot 'spotter-svc.exe'
    Assert-True ($service.PathName.Trim('"') -eq $expectedExe) "service path is $($service.PathName), expected $expectedExe"

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

    $acl = Get-Acl -LiteralPath $dataRoot
    $systemRule = $acl.Access | Where-Object { $_.IdentityReference.Value -eq 'NT AUTHORITY\SYSTEM' -and $_.FileSystemRights.ToString().Contains('FullControl') }
    $adminRule = $acl.Access | Where-Object { $_.IdentityReference.Value -match '\\Administrators$' -and $_.FileSystemRights.ToString().Contains('FullControl') }
    Assert-True ($null -ne $systemRule) 'ProgramData ACL does not grant SYSTEM full control'
    Assert-True ($null -ne $adminRule) 'ProgramData ACL does not grant Administrators full control'

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine').Split(';')
    Assert-True ($machinePath -contains $binRoot) 'MSI did not append the binary directory to machine PATH'

    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svcState = (Get-Service -Name $serviceName).Status
    Assert-True ($svcState -in @('Running', 'Stopped')) "service is in unexpected state $svcState after start attempt"
    if ($svcState -eq 'Running') {
        Stop-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}
finally {
    if ($installAttempted) {
        Invoke-MsiExec @('/x', $MsiPath, '/qn', '/norestart', '/l*v', (Join-Path $LogDirectory 'uninstall.log'))
    }
}

Assert-True (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) 'service remains registered after uninstall'
Assert-True (-not (Test-Path -LiteralPath $installRoot)) 'Program Files installation remains after uninstall'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine').Split(';')
Assert-True ($machinePath -notcontains $binRoot) 'machine PATH entry remains after uninstall'
Write-Host 'MSI lifecycle validation passed'
