#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AccessDeniedHResult = -2147024891

function New-TemporaryStandardUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$Domain = $env:COMPUTERNAME
    )

    if ($Name -notmatch '^[A-Za-z][A-Za-z0-9_-]{2,19}$') {
        throw 'temporary standard-user name must contain 3-20 letters, digits, underscores, or hyphens'
    }
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
        throw "refusing to reuse an existing local user: $Name"
    }

    $passwordText = [Guid]::NewGuid().ToString('N') + 'aA!7'
    $password = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
    $user = New-LocalUser -Name $Name -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'temporary SnipeSpotter ACL test account'
    try {
        $member = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ieq "$Domain\$Name" -or $_.Name -ieq $Name }
        if ($null -ne $member) {
            throw "temporary user $Name unexpectedly belongs to Administrators"
        }
        [pscustomobject]@{
            Name = $user.Name
            Domain = $Domain
            Password = $password
        }
    } catch {
        Remove-TemporaryStandardUser -User ([pscustomobject]@{ Name = $Name })
        throw
    }
}

function Remove-TemporaryStandardUser {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$User)

    if ([string]::IsNullOrWhiteSpace($User.Name)) {
        throw 'temporary standard-user cleanup requires a user name'
    }
    $localUser = Get-LocalUser -Name $User.Name -ErrorAction SilentlyContinue
    if ($null -ne $localUser) {
        $profiles = @(Get-CimInstance Win32_UserProfile -Filter "LocalPath LIKE '%\$($User.Name)'" -ErrorAction SilentlyContinue)
        Remove-LocalUser -Name $User.Name -ErrorAction Stop
        foreach ($profile in $profiles) {
            Remove-CimInstance -InputObject $profile -ErrorAction Stop
        }
    }
}

function Get-TokenProof {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isSystem = $identity.User.Value -eq 'S-1-5-18'
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [pscustomobject]@{
        sid = $identity.User.Value
        name = $identity.Name
        is_system = $isSystem
        is_administrator = $isAdministrator
        is_standard_user = -not $isSystem -and -not $isAdministrator
    }
}

function Assert-StandardUserToken {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Proof)

    if (-not $Proof.is_standard_user) {
        throw "child token is privileged: sid=$($Proof.sid), name=$($Proof.name)"
    }
    return $Proof
}

function Assert-ChildIsStandardUser {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][psobject]$Result)

    $stdout = [string]$Result.Stdout
    $tokenFields = @(
        'child_is_administrator=False',
        'child_is_system=False',
        'child_is_standard_user=True',
        'read_denied=True',
        'write_denied=True'
    )
    $missingTokenFields = @($tokenFields | Where-Object { -not $stdout.Contains($_) })
    if ($Result.ExitCode -ne 0 -or $missingTokenFields.Count -gt 0) {
        throw "standard-user token or access assertion failed: exit code $($Result.ExitCode), missing=$($missingTokenFields -join ', '), stdout=$stdout, stderr=$($Result.Stderr.Trim())"
    }
    return $Result
}

function Invoke-AsStandardUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$User,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $false)][ValidateRange(1, 600)][int]$TimeoutSeconds = 30
    )

    if ($null -eq $User.Password) { throw 'standard-user process requires an in-memory password' }
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "standard-user executable was not found: $FilePath"
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UserName = [string]$User.Name
    $startInfo.Domain = [string]$User.Domain
    $startInfo.Password = $User.Password
    foreach ($argument in $ArgumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'failed to start standard-user process' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { Write-Warning "could not terminate standard-user process: $($_.Exception.Message)" }
            throw "standard-user process did not exit within $TimeoutSeconds seconds"
        }
        $exitCode = $process.ExitCode
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [pscustomobject]@{
            ExitCode = $exitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-StandardUserCannotReadWrite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$User,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory = $false)][ValidateSet('Leaf', 'Container')][string]$PathType = 'Leaf',
        [Parameter(Mandatory = $false)][ValidateRange(1, 600)][int]$TimeoutSeconds = 30
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "ACL target does not exist: $Path" }
    $probe = @'
$AccessDeniedHResult = -2147024891
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isSystem = $identity.User.Value -eq 'S-1-5-18'
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isSystem -or $isAdministrator) {
    [Console]::Error.WriteLine("privileged child token: sid=$($identity.User.Value)")
    exit 20
}
$path = $args[0]
$pathType = $args[1]
$readDenied = $false
$writeDenied = $false
if ($pathType -eq 'Container') {
    try {
        [void][IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator().MoveNext()
    } catch [UnauthorizedAccessException] {
        $readDenied = $true
    } catch {
        if ($_.Exception.HResult -eq $AccessDeniedHResult -or $_.Exception.Message -match '(?i)access is denied|access denied') {
            $readDenied = $true
        } else {
            throw
        }
    }
    $probeDirectory = Join-Path $path ('.acl-probe-' + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.Directory]::CreateDirectory($probeDirectory) | Out-Null
    } catch [UnauthorizedAccessException] {
        $writeDenied = $true
    } catch {
        if ($_.Exception.HResult -eq $AccessDeniedHResult -or $_.Exception.Message -match '(?i)access is denied|access denied') {
            $writeDenied = $true
        } else {
            throw
        }
    } finally {
        if (Test-Path -LiteralPath $probeDirectory) {
            [IO.Directory]::Delete($probeDirectory, $false)
        }
    }
} else {
    try {
        $handle = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $handle.Dispose()
    } catch [UnauthorizedAccessException] {
        $readDenied = $true
    } catch {
        if ($_.Exception.HResult -eq $AccessDeniedHResult -or $_.Exception.Message -match '(?i)access is denied|access denied') {
            $readDenied = $true
        } else {
            throw
        }
    }
    try {
        $handle = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $handle.Dispose()
    } catch [UnauthorizedAccessException] {
        $writeDenied = $true
    } catch {
        if ($_.Exception.HResult -eq $AccessDeniedHResult -or $_.Exception.Message -match '(?i)access is denied|access denied') {
            $writeDenied = $true
        } else {
            throw
        }
    }
}
Write-Output "child_is_administrator=$isAdministrator"
Write-Output "child_is_system=$isSystem"
Write-Output "child_is_standard_user=$(-not $isSystem -and -not $isAdministrator)"
Write-Output "read_denied=$readDenied"
Write-Output "write_denied=$writeDenied"
if (-not $readDenied -or -not $writeDenied) {
    [Console]::Error.WriteLine("read-denied=$readDenied write-denied=$writeDenied")
    exit 21
}
Write-Output 'identity-class=standard-user'
Write-Output 'access=read-write-denied'
exit 0
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $result = Invoke-AsStandardUser -User $User -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded, $Path, $PathType
    ) -TimeoutSeconds $TimeoutSeconds
    [void](Assert-ChildIsStandardUser -Result $result)
    if (-not $result.Stdout.Contains('access=read-write-denied')) {
        throw "standard-user ACL probe did not report denial: $($result.Stderr.Trim())"
    }
    return $result
}

Export-ModuleMember -Function New-TemporaryStandardUser, Remove-TemporaryStandardUser, Get-TokenProof, Assert-StandardUserToken, Invoke-AsStandardUser, Assert-ChildIsStandardUser, Assert-StandardUserCannotReadWrite
