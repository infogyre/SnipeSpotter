#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TestSupport/WorkflowPaths.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'TestSupport/WorkflowInputs.psm1') -Force

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory = $true)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Rejected {
    param([Parameter(Mandatory = $true)][scriptblock]$Action, [Parameter(Mandatory = $true)][string]$Description)
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Assert-True $rejected "accepted invalid $Description"
}

$labelParameter = (Get-Command Assert-ArtifactName).Parameters['Label']
Assert-True (-not [bool]($labelParameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory })) 'artifact Label must be optional'
Assert-True ((Assert-ArtifactName -Name 'packaged-release') -ceq 'packaged-release') 'artifact default label failed'

$valid = Get-WorkflowInputContract -ArtifactName 'packaged-release' -LogArtifactName 'msi-lifecycle-logs' -RunIdentity 'release-123-1' -MsiName 'SnipeSpotter-0.1.0-x64.msi'
Assert-True ($valid.PSObject.Properties.Name -join ',' -ceq 'artifact_name,log_artifact_name,run_identity,msi_name') 'validator output shape/order changed'

# An empty MSI name is the explicit discovery sentinel; supplied names still obey the full 1..128 rule.
Assert-True ((Assert-MsiName -Name '') -ceq '') 'empty MSI name must request discovery'
Assert-True ((Assert-MsiName -Name (('a' * 124) + '.msi')) -ceq (('a' * 124) + '.msi')) '128-character MSI name was rejected'
foreach ($name in @('../escape', '..\escape', 'C:\absolute', '\\server\share', 'good.msi:stream', 'CON.msi', 'aux.MSI', 'NUL.', 'CON.foo.msi', 'AUX.backup.msi', 'good name.msi', "bad`n.msi", ('a' * 125) + '.msi', 'bad.msi.')) {
    Assert-Rejected -Description $name -Action { Assert-MsiName -Name $name }
}
foreach ($name in @('_leading', 'bad_name', 'bad name', 'CON.', 'release.')) {
    Assert-Rejected -Description $name -Action { Assert-RunIdentity -Name $name }
}
foreach ($name in @('../artifact', 'bad artifact', 'CON', 'bad.', ('a' * 129))) {
    Assert-Rejected -Description $name -Action { Assert-ArtifactName -Name $name -Label 'artifact_name' }
}

$script:ExecutorInvocations = 0
$injectedMsiExecutor = {
    param([Parameter(Mandatory = $true)][string]$MsiPath)
    $script:ExecutorInvocations++
    $script:ExecutorLastPath = $MsiPath
}
function Invoke-ValidatedMsiProbe {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)][string]$LogArtifactName,
        [Parameter(Mandatory = $true)][string]$RunIdentity,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$MsiName,
        [Parameter(Mandatory = $true)][string]$StagePath,
        [Parameter(Mandatory = $true)][scriptblock]$MsiExecutor
    )
    $validated = Get-WorkflowInputContract -ArtifactName $ArtifactName -LogArtifactName $LogArtifactName -RunIdentity $RunIdentity -MsiName $MsiName
    New-Item -ItemType Directory -Force -Path $StagePath | Out-Null
    & $MsiExecutor (Join-Path $StagePath $validated.msi_name)
}
function Assert-RejectedWithoutSideEffect {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$StagePath
    )
    $script:ExecutorInvocations = 0
    Remove-Item -LiteralPath $StagePath -Recurse -Force -ErrorAction SilentlyContinue
    Assert-Rejected -Description $Description -Action $Action
    Assert-True (-not (Test-Path -LiteralPath $StagePath)) "rejected $Description created a staging path"
    Assert-True ($script:ExecutorInvocations -eq 0) "rejected $Description invoked the MSI executor"
}

$rejectionStage = Join-Path ([IO.Path]::GetTempPath()) ('workflow-inputs-rejection-' + [Guid]::NewGuid().ToString('N'))
try {
    foreach ($name in @('../escape', '..\escape', 'C:\absolute', 'good name.msi', 'bad.msi.')) {
        $caseName = $name
        Assert-RejectedWithoutSideEffect -Description $caseName -StagePath $rejectionStage -Action {
            Invoke-ValidatedMsiProbe -ArtifactName 'packaged-release' -LogArtifactName 'msi-lifecycle-logs' -RunIdentity 'release-123-1' -MsiName $caseName -StagePath $rejectionStage -MsiExecutor $injectedMsiExecutor
        }
    }
    Assert-RejectedWithoutSideEffect -Description 'invalid artifact staging' -StagePath $rejectionStage -Action {
        Invoke-ValidatedMsiProbe -ArtifactName '../artifact' -LogArtifactName 'msi-lifecycle-logs' -RunIdentity 'release-123-1' -MsiName 'safe.msi' -StagePath $rejectionStage -MsiExecutor $injectedMsiExecutor
    }
    Assert-RejectedWithoutSideEffect -Description 'invalid run identity staging' -StagePath $rejectionStage -Action {
        Invoke-ValidatedMsiProbe -ArtifactName 'packaged-release' -LogArtifactName 'msi-lifecycle-logs' -RunIdentity '_invalid' -MsiName 'safe.msi' -StagePath $rejectionStage -MsiExecutor $injectedMsiExecutor
    }
} finally {
    Remove-Item -LiteralPath $rejectionStage -Recurse -Force -ErrorAction SilentlyContinue
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('workflow-inputs-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $root | Out-Null
try {
    $safe = Join-Path $root 'safe.msi'
    [IO.File]::WriteAllText($safe, 'fixture')
    $resolved = Resolve-ValidatedMsiPath -Root $root -RequestedName ''
    Assert-True ($resolved -ceq ([IO.Path]::GetFullPath($safe))) 'safe MSI was not resolved'
    $outside = Join-Path ([IO.Path]::GetTempPath()) ('outside-' + [Guid]::NewGuid().ToString('N') + '.msi')
    [IO.File]::WriteAllText($outside, 'outside')
    try {
        $link = Join-Path $root 'link.msi'
        New-Item -ItemType SymbolicLink -Path $link -Target $outside | Out-Null
        Assert-Rejected -Description 'reparse MSI' -Action { Resolve-ValidatedMsiPath -Root $root -RequestedName 'link.msi' }
    } catch [System.Exception] {
        if ($_.Exception.Message -notmatch 'administrator|privilege|symbolic') { throw }
    } finally {
        Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $safe -Force
    New-Item -ItemType File -Path (Join-Path $root 'one.msi') | Out-Null
    New-Item -ItemType File -Path (Join-Path $root 'two.msi') | Out-Null
    Assert-Rejected -Description 'ambiguous MSI discovery' -Action { Resolve-ValidatedMsiPath -Root $root -RequestedName '' }
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'workflow input contract: OK'
