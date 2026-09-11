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

$valid = Get-ValidatedWorkflowInputs -ArtifactName 'packaged-release' -LogArtifactName 'msi-lifecycle-logs' -RunIdentity 'release-123-1' -MsiName 'SnipeSpotter-0.1.0-x64.msi'
Assert-True ($valid.PSObject.Properties.Name -join ',' -ceq 'artifact_name,log_artifact_name,run_identity,msi_name') 'validator output shape/order changed'

foreach ($name in @('../escape', '..\escape', 'C:\absolute', '\\server\share', 'good.msi:stream', 'CON.msi', 'aux.MSI', 'NUL.', 'good name.msi', "bad`n.msi", ('a' * 129) + '.msi', 'bad.msi.')) {
    Assert-Rejected -Description $name -Action { Assert-MsiName -Name $name }
}
foreach ($name in @('_leading', 'bad_name', 'bad name', 'CON.', 'release.')) {
    Assert-Rejected -Description $name -Action { Assert-RunIdentity -Name $name }
}
foreach ($name in @('../artifact', 'bad artifact', 'CON', 'bad.', ('a' * 129))) {
    Assert-Rejected -Description $name -Action { Assert-ArtifactName -Name $name }
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
