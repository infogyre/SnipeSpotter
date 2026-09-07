# pattern: Imperative Shell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SmbiosFixture.psm1') -Force
try {
    $bytes = [IO.File]::ReadAllBytes($InputPath)
    $result = Protect-SmbiosFixture -Data $bytes
    [IO.File]::WriteAllBytes($OutputPath, $result.Bytes)
    [pscustomobject]@{ status = 'ok'; structures = $result.StructureCount; uuid_fields_redacted = $result.UuidFieldsRedacted } | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine('{"status":"error","category":"smbios_invalid"}')
    exit 1
}
