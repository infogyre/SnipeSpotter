Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-BoundedText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $false)][ValidateRange(1, 65536)][int]$MaxCharacters = 512
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ($text.Length -le $MaxCharacters) { return $text.Trim() }
    return ($text.Substring(0, $MaxCharacters).Trim() + '...')
}

function Write-BoundedDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Values,
        [Parameter(Mandatory = $false)][ValidateRange(1024, 1048576)][int]$MaxBytes = 32768
    )

    $allowed = [ordered]@{}
    foreach ($entry in $Values.GetEnumerator()) {
        if ($entry.Key -notmatch '^[A-Za-z][A-Za-z0-9_.-]{0,63}$') {
            throw "diagnostic key is not allowlisted: $($entry.Key)"
        }
        if ($null -eq $entry.Value -or $entry.Value -is [string] -or $entry.Value -is [ValueType]) {
            $allowed[$entry.Key] = $entry.Value
        } else {
            throw "diagnostic value for $($entry.Key) is not scalar"
        }
    }
    $json = $allowed | ConvertTo-Json -Compress -Depth 3
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt $MaxBytes) {
        throw "diagnostics exceed $MaxBytes bytes"
    }
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function Get-BoundedText, Write-BoundedDiagnostic
