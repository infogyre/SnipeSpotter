# pattern: Imperative Shell

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'WorkflowInputs.psm1') -Force

function Resolve-ValidatedMsiPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RequestedName
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path
    $rootItem = Get-Item -LiteralPath $resolvedRoot -Force
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'MSI root must not be a reparse point'
    }
    if ([string]::IsNullOrEmpty($RequestedName)) {
        $candidateNames = @(
            Get-ChildItem -LiteralPath $resolvedRoot -File -Filter '*.msi' -Force |
                Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
                ForEach-Object { $_.Name }
        )
    } else {
        $candidateNames = @(Assert-MsiName -Name $RequestedName)
    }
    if ($candidateNames.Count -ne 1) { throw 'exactly one MSI must be selected' }
    $leaf = Assert-DiscoveredMsiFile -Name $candidateNames[0]
    $path = Join-Path $resolvedRoot $leaf
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'MSI file must not be a reparse point'
    }
    $resolvedPath = [IO.Path]::GetFullPath($item.FullName)
    $rootFullPath = [IO.Path]::GetFullPath($resolvedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $rootWithSeparator = $rootFullPath + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MSI path escaped its containment root'
    }
    return $resolvedPath
}

Export-ModuleMember -Function Resolve-ValidatedMsiPath
