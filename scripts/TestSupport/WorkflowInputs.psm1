# pattern: Functional Core

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ReservedDeviceNames = @(
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
)

function Assert-AsciiSafeName {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][int]$MaximumLength,
        [Parameter(Mandatory = $true)][bool]$AllowEmpty,
        [Parameter(Mandatory = $true)][bool]$AllowUnderscore,
        [Parameter(Mandatory = $true)][bool]$RequireMsiSuffix
    )

    if ([string]::IsNullOrEmpty($Name)) {
        if ($AllowEmpty) { return $Name }
        throw "$Label must not be empty"
    }
    if ($Name.Length -gt $MaximumLength) { throw "$Label exceeds its maximum length" }
    if ($Name.EndsWith('.', [StringComparison]::Ordinal) -or $Name.EndsWith(' ', [StringComparison]::Ordinal)) {
        throw "$Label must not end with a dot or space"
    }
    if ($Name -match '[\x00-\x20\x7f]' -or $Name -match '[^\x00-\x7f]') {
        throw "$Label must contain only safe ASCII characters"
    }
    $pattern = if ($AllowUnderscore) { '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' } else { '^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$' }
    if ($Name -notmatch $pattern) { throw "$Label contains unsupported characters" }
    if ($RequireMsiSuffix -and $Name -notmatch '(?i)\.msi$') { throw "$Label must use the .msi suffix" }
    $base = [IO.Path]::GetFileNameWithoutExtension($Name)
    if ($script:ReservedDeviceNames -contains $base.TrimEnd('.').ToUpperInvariant()) {
        throw "$Label uses a reserved device name"
    }
    return $Name
}

function Assert-RunIdentity {
    param([Parameter(Mandatory = $true)][string]$Name)
    return Assert-AsciiSafeName -Name $Name -Label 'run_identity' -MaximumLength 64 -AllowEmpty:$false -AllowUnderscore:$false -RequireMsiSuffix:$false
}

function Assert-ArtifactName {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Label = 'artifact_name')
    return Assert-AsciiSafeName -Name $Name -Label $Label -MaximumLength 128 -AllowEmpty:$false -AllowUnderscore:$true -RequireMsiSuffix:$false
}

function Assert-MsiName {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $Name }
    if ([IO.Path]::IsPathRooted($Name) -or $Name.Contains('/') -or $Name.Contains('\') -or $Name.Contains(':')) {
        throw 'msi_name must be a filename, not a path'
    }
    return Assert-AsciiSafeName -Name $Name -Label 'msi_name' -MaximumLength 128 -AllowEmpty:$true -AllowUnderscore:$true -RequireMsiSuffix:$true
}

function Assert-DiscoveredMsiFile {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { throw 'discovered MSI name must not be empty' }
    return Assert-MsiName -Name $Name
}

function Get-ValidatedWorkflowInputs {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)][string]$LogArtifactName,
        [Parameter(Mandatory = $true)][string]$RunIdentity,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$MsiName
    )

    $validatedArtifact = Assert-ArtifactName -Name $ArtifactName -Label 'artifact_name'
    $validatedLog = Assert-ArtifactName -Name $LogArtifactName -Label 'log_artifact_name'
    $validatedIdentity = Assert-RunIdentity -Name $RunIdentity
    $validatedMsi = Assert-MsiName -Name $MsiName
    [pscustomobject][ordered]@{
        artifact_name = $validatedArtifact
        log_artifact_name = $validatedLog
        run_identity = $validatedIdentity
        msi_name = $validatedMsi
    }
}

Export-ModuleMember -Function Assert-RunIdentity, Assert-ArtifactName, Assert-MsiName, Assert-DiscoveredMsiFile, Get-ValidatedWorkflowInputs
