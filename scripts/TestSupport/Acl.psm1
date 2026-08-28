Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$canonicalAllowSids = @($SystemSid, $AdministratorsSid)
$canonicalRightsMask = [int][Security.AccessControl.FileSystemRights]::FullControl
$canonicalInheritanceMask = [int]([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit)
$canonicalPropagationMask = [int][Security.AccessControl.PropagationFlags]::None

function ConvertTo-SecurityIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$IdentityReference)

    if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) {
        return $IdentityReference.Value
    }
    try {
        return ([Security.Principal.NTAccount]$IdentityReference.Value).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "failed to translate ACL principal $($IdentityReference.Value) to a SID"
    }
}

function Get-NormalizedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    @($acl.Access | ForEach-Object {
        [ordered]@{
            sid = ConvertTo-SecurityIdentifier -IdentityReference $_.IdentityReference
            identity = $_.IdentityReference.Value
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

function Get-AclContract {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $rules = @(Get-NormalizedAcl -Path $Path)
    [pscustomobject]@{
        path = $Path
        protected = [bool]$acl.AreAccessRulesProtected
        owner_sid = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner
        allowed_allow_sids = $canonicalAllowSids
        required = @(
            [pscustomobject]@{
                sid = $SystemSid
                type = 'Allow'
                rights_mask = $canonicalRightsMask
                inheritance_mask = $canonicalInheritanceMask
                propagation_mask = $canonicalPropagationMask
                inherited = $false
            }
            [pscustomobject]@{
                sid = $AdministratorsSid
                type = 'Allow'
                rights_mask = $canonicalRightsMask
                inheritance_mask = $canonicalInheritanceMask
                propagation_mask = $canonicalPropagationMask
                inherited = $false
            }
        )
        rules = $rules
    }
}

function Assert-AclContract {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $contract = Get-AclContract -Path $Path
    if (-not $contract.protected) {
        throw "ACL contract for $Path is not protected from inherited broad access"
    }
    $allowRules = @($contract.rules | Where-Object { $_.type -eq 'Allow' })
    if ($allowRules.Count -ne $contract.allowed_allow_sids.Count) {
        throw "ACL contract for $Path contains $($allowRules.Count) Allow rule(s); expected exactly $($contract.allowed_allow_sids.Count) canonical principals"
    }
    $unexpectedAllowSids = @($allowRules |
        Where-Object { -not $contract.allowed_allow_sids.Contains($_.sid) } |
        Select-Object -ExpandProperty sid -Unique |
        Select-Object -First 8)
    if ($unexpectedAllowSids.Count -gt 0) {
        throw "ACL contract for $Path contains non-canonical Allow SID(s): $($unexpectedAllowSids -join ', ')"
    }
    foreach ($required in $contract.required) {
        $matches = @($allowRules | Where-Object {
            $_.sid -eq $required.sid -and $_.type -eq $required.type -and
            $_.rights_mask -eq $required.rights_mask -and
            $_.inheritance_mask -eq $required.inheritance_mask -and
            $_.propagation_mask -eq $required.propagation_mask -and
            $_.inherited -eq $required.inherited
        })
        if ($matches.Count -ne 1) {
            throw "ACL contract for $Path lacks exactly one canonical Allow rule for $($required.sid)"
        }
    }
    return $contract
}

function Ensure-AclContract {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $owner = ConvertTo-SecurityIdentifier -IdentityReference $acl.Owner
    $acl.SetAccessRuleProtection($true, $true)
    $removedAllowCount = 0
    $removedAllowSids = @()
    foreach ($rule in @($acl.Access)) {
        $sid = ConvertTo-SecurityIdentifier -IdentityReference $rule.IdentityReference
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            -not $canonicalAllowSids.Contains($sid)) {
            $acl.RemoveAccessRule($rule) | Out-Null
            $removedAllowCount++
            if ($removedAllowSids.Count -lt 8) {
                $removedAllowSids += $sid
            }
        }
    }
    foreach ($sid in $canonicalAllowSids) {
        foreach ($rule in @($acl.Access)) {
            $ruleSid = ConvertTo-SecurityIdentifier -IdentityReference $rule.IdentityReference
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $ruleSid -eq $sid) {
                $acl.RemoveAccessRule($rule) | Out-Null
            }
        }
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.SetAccessRule($rule)
    }
    if ($removedAllowCount -gt 0) {
        Write-Verbose "removed $removedAllowCount non-canonical Allow ACL rule(s) for SID(s): $($removedAllowSids -join ', ')"
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
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

Export-ModuleMember -Function Get-NormalizedAcl, Assert-AclPrincipal, Get-AclContract, Ensure-AclContract, Assert-AclContract
