Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$canonicalAllowSids = @($SystemSid, $AdministratorsSid)
$canonicalRightsMask = [int][Security.AccessControl.FileSystemRights]::FullControl
# Windows emits GenericAll as this access-mask value for inherit-only child ACEs.
$canonicalChildRightsMask = 268435456
$canonicalSelfInheritanceMask = [int][Security.AccessControl.InheritanceFlags]::None
$canonicalInheritanceMask = [int]([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit)
$canonicalPropagationMask = [int][Security.AccessControl.PropagationFlags]::None
$canonicalChildPropagationMask = [int][Security.AccessControl.PropagationFlags]::InheritOnly

function ConvertTo-SecurityIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$IdentityReference)

    if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) {
        return $IdentityReference.Value
    }
    $identity = $IdentityReference.ToString()
    try {
        return ([Security.Principal.NTAccount]$identity).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "failed to translate ACL principal $identity to a SID"
    }
}

function Get-NormalizedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    @($acl.Access | ForEach-Object {
        [ordered]@{
            sid = ConvertTo-SecurityIdentifier -IdentityReference $_.IdentityReference
            identity = $_.IdentityReference.ToString()
            type = $_.AccessControlType.ToString()
            rights = $_.FileSystemRights.ToString()
            rights_mask = [int]$_.FileSystemRights
            inheritance = $_.InheritanceFlags.ToString()
            inheritance_mask = [int]$_.InheritanceFlags
            propagation = $_.PropagationFlags.ToString()
            propagation_mask = [int]$_.PropagationFlags
            inherited = [bool]$_.IsInherited
        }
    } | Sort-Object sid, type, rights, inheritance, propagation, inherited)
}

function Get-AclDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('root', 'settings')][string]$PathClass,
        [Parameter(Mandatory = $false)][ValidateRange(1, 64)][int]$MaxRules = 64
    )

    $acl = Get-Acl -LiteralPath $Path
    @($acl.Access | Select-Object -First $MaxRules | ForEach-Object {
        [ordered]@{
            path_class = $PathClass
            sid = ConvertTo-SecurityIdentifier -IdentityReference $_.IdentityReference
            access_type = $_.AccessControlType.ToString()
            rights_mask = [int]$_.FileSystemRights
            inheritance_flags = $_.InheritanceFlags.ToString()
            propagation_flags = $_.PropagationFlags.ToString()
            inherited = [bool]$_.IsInherited
        }
    })
}

function Write-AclDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('root', 'settings')][string]$PathClass,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter(Mandatory = $false)][ValidateRange(1024, 65536)][int]$MaxBytes = 32768,
        [Parameter(Mandatory = $false)][ValidateRange(1, 64)][int]$MaxRules = 64
    )

    $records = @(Get-AclDiagnostic -Path $Path -PathClass $PathClass -MaxRules $MaxRules)
    $json = if ($records.Count -eq 0) {
        '[]'
    } else {
        $records | ConvertTo-Json -Compress -Depth 3
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt $MaxBytes) {
        throw "ACL diagnostics exceed $MaxBytes bytes"
    }
    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false))
}

function Get-RequiredAclRule {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$PathType)

    $required = @()
    foreach ($sid in $canonicalAllowSids) {
        $required += [pscustomobject]@{
            sid = $sid
            type = 'Allow'
            rights_mask = $canonicalRightsMask
            inheritance_mask = $canonicalSelfInheritanceMask
            propagation_mask = $canonicalPropagationMask
            inherited = $false
            scope = 'self'
        }
        if ($PathType -eq 'Container') {
            $required += [pscustomobject]@{
                sid = $sid
                type = 'Allow'
                rights_mask = $canonicalChildRightsMask
                inheritance_mask = $canonicalInheritanceMask
                propagation_mask = $canonicalChildPropagationMask
                inherited = $false
                scope = 'children'
            }
        }
    }
    return $required
}

function Assert-AclRulesContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$PathType,
        [Parameter(Mandatory = $true)][object[]]$Rules
    )

    $required = @(Get-RequiredAclRule -PathType $PathType)
    $allowRules = @($Rules | Where-Object { $_.type -eq 'Allow' })
    if ($allowRules.Count -ne $required.Count) {
        throw "ACL contract for $Path contains $($allowRules.Count) explicit Allow rule(s); expected exactly $($required.Count) for a $PathType"
    }
    $unexpectedAllowSids = @($allowRules |
        Where-Object { -not $canonicalAllowSids.Contains($_.sid) } |
        Select-Object -ExpandProperty sid -Unique |
        Select-Object -First 8)
    if ($unexpectedAllowSids.Count -gt 0) {
        throw "ACL contract for $Path contains non-canonical Allow SID(s): $($unexpectedAllowSids -join ', ')"
    }
    foreach ($requiredRule in $required) {
        $matchingRules = @($allowRules | Where-Object {
            $_.sid -eq $requiredRule.sid -and $_.type -eq $requiredRule.type -and
            $_.rights_mask -eq $requiredRule.rights_mask -and
            $_.inheritance_mask -eq $requiredRule.inheritance_mask -and
            $_.propagation_mask -eq $requiredRule.propagation_mask -and
            $_.inherited -eq $requiredRule.inherited
        })
        if ($matchingRules.Count -ne 1) {
            throw "ACL contract for $Path lacks exactly one canonical $($requiredRule.scope) Allow rule for $($requiredRule.sid)"
        }
    }
}

function Get-AclContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$PathType
    )

    $acl = Get-Acl -LiteralPath $Path
    $rules = @(Get-NormalizedAcl -Path $Path)
    [pscustomobject]@{
        path = $Path
        path_type = $PathType
        protected = [bool]$acl.AreAccessRulesProtected
        owner_sid = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner
        allowed_allow_sids = $canonicalAllowSids
        required = @(Get-RequiredAclRule -PathType $PathType)
        rules = $rules
    }
}

function Assert-AclContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$PathType
    )

    $contract = Get-AclContract -Path $Path -PathType $PathType
    if (-not $contract.protected) {
        throw "ACL contract for $Path is not protected from inherited broad access"
    }
    Assert-AclRulesContract -Path $Path -PathType $PathType -Rules $contract.rules
    return $contract
}

function Set-AclContract {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$PathType
    )

    $acl = Get-Acl -LiteralPath $Path
    $owner = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner
    $acl.SetAccessRuleProtection($true, $true)
    $removedAllowCount = 0
    $removedAllowSids = @()
    foreach ($rule in @($acl.Access)) {
        $sid = ConvertTo-SecurityIdentifier -IdentityReference $rule.IdentityReference
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) {
            $acl.RemoveAccessRule($rule) | Out-Null
            $removedAllowCount++
            if ($removedAllowSids.Count -lt 8 -and -not $removedAllowSids.Contains($sid)) {
                $removedAllowSids += $sid
            }
        }
    }
    foreach ($requiredRule in @(Get-RequiredAclRule -PathType $PathType)) {
        $identity = [Security.Principal.SecurityIdentifier]::new($requiredRule.sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]$requiredRule.rights_mask,
            [Security.AccessControl.InheritanceFlags]$requiredRule.inheritance_mask,
            [Security.AccessControl.PropagationFlags]$requiredRule.propagation_mask,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    if ($removedAllowCount -gt 0) {
        Write-Verbose "removed $removedAllowCount existing Allow ACL rule(s) for SID(s): $($removedAllowSids -join ', ')"
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Set canonical ACL contract')) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    $updatedOwner = ConvertTo-SecurityIdentifier -IdentityReference (Get-Acl -LiteralPath $Path).Owner
    if ($updatedOwner -ne $owner) {
        throw "ACL repair changed owner SID for $Path"
    }
}

function Assert-AclPrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Rules,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Identity,
        [Parameter(Mandatory = $true)][ValidateSet('Allow', 'Deny')][string]$AccessType,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RightsFragment,
        [Parameter(Mandatory = $false)][bool]$MustBeInherited = $false
    )

    $match = @($Rules | Where-Object {
        (($_.sid -and $_.sid -eq $Identity) -or ($_.identity -and $_.identity -eq $Identity)) -and
        $_.type -eq $AccessType -and
        $_.rights.Contains($RightsFragment) -and
        (-not $MustBeInherited -or $_.inherited)
    })
    if ($match.Count -ne 1) {
        throw "expected exactly one $AccessType ACL rule for $Identity with $RightsFragment"
    }
    return $match[0]
}

Export-ModuleMember -Function Get-NormalizedAcl, Get-AclDiagnostic, Write-AclDiagnostic, Assert-AclPrincipal, Get-AclContract, Set-AclContract, Assert-AclRulesContract, Assert-AclContract
