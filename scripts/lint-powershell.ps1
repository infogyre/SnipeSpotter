[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Files
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Pre-commit / prek hook: lints all staged .ps1 files with PSScriptAnalyzer.
# Invoked as: pwsh -NoProfile -File scripts/lint-powershell.ps1 <file1> <file2> ...
# Also usable standalone: pwsh scripts/lint-powershell.ps1 scripts/*.ps1

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Output 'PSScriptAnalyzer not installed -- skipping PowerShell lint'
    exit 0
}

if (-not $Files -or $Files.Count -eq 0) {
    Write-Output 'No PowerShell files to lint'
    exit 0
}

$violations = @()
foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file)) {
        continue
    }
    $results = Invoke-ScriptAnalyzer -Path $file -Severity Warning, Error
    if ($results) {
        $violations += $results
    }
}

if ($violations.Count -gt 0) {
    $violations | Format-Table -AutoSize
    Write-Error "$($violations.Count) PSScriptAnalyzer violation(s) found"
    exit 1
}

Write-Output "PSScriptAnalyzer: $($Files.Count) file(s) clean"
