Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalizedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    @($acl.Access | ForEach-Object {
        [ordered]@{
            identity = $_.IdentityReference.Value
            type = $_.AccessControlType.ToString()
            rights = $_.FileSystemRights.ToString()
            inheritance = $_.InheritanceFlags.ToString()
            propagation = $_.PropagationFlags.ToString()
            inherited = [bool]$_.IsInherited
        }
    } | Sort-Object identity, type, rights, inheritance, propagation, inherited)
}

function Assert-AclPrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Rules,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Identity,
        [Parameter(Mandatory = $true)][ValidateSet('Allow', 'Deny')][string]$AccessType = 'Allow',
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RightsFragment,
        [Parameter(Mandatory = $false)][bool]$MustBeInherited = $false
    )

    $match = @($Rules | Where-Object {
        $_.identity -eq $Identity -and
        $_.type -eq $AccessType -and
        $_.rights.Contains($RightsFragment) -and
        (-not $MustBeInherited -or $_.inherited)
    })
    if ($match.Count -ne 1) {
        throw "expected exactly one $AccessType ACL rule for $Identity with $RightsFragment"
    }
    return $match[0]
}

Export-ModuleMember -Function Get-NormalizedAcl, Assert-AclPrincipal
