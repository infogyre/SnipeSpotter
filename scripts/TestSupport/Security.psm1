#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-TemporaryStandardUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
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

    $password = [Security.SecureString]::new()
    foreach ($character in ([Guid]::NewGuid().ToString('N') + 'aA!7').ToCharArray()) {
        $password.AppendChar($character)
    }
    $password.MakeReadOnly()
    if (-not $PSCmdlet.ShouldProcess($Name, 'Create temporary standard user')) {
        return
    }
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][psobject]$User)

    if ([string]::IsNullOrWhiteSpace($User.Name)) {
        throw 'temporary standard-user cleanup requires a user name'
    }
    $localUser = Get-LocalUser -Name $User.Name -ErrorAction SilentlyContinue
    if ($null -ne $localUser) {
        $profiles = @(Get-CimInstance Win32_UserProfile -Filter "LocalPath LIKE '%\$($User.Name)'" -ErrorAction SilentlyContinue)
        if ($PSCmdlet.ShouldProcess($User.Name, 'Remove temporary standard user')) {
            Remove-LocalUser -Name $User.Name -ErrorAction Stop
        }
        foreach ($userProfile in $profiles) {
            if ($PSCmdlet.ShouldProcess($userProfile.LocalPath, 'Remove temporary user profile')) {
                Remove-CimInstance -InputObject $userProfile -ErrorAction Stop
            }
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

function Get-CredentialLaunchDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('configuration', 'native_start')][string]$LaunchStage,
        [Parameter(Mandatory = $true)][ValidateSet('configuration', 'native')][string]$FailureKind,
        [Parameter(Mandatory = $true)][ValidateSet('file_name', 'use_shell_execute', 'redirect_standard_output', 'redirect_standard_error', 'username', 'domain', 'password', 'argument_list', 'process_start_info', 'process_start', 'unknown')][string]$FailedField,
        [Parameter(Mandatory = $true)][Diagnostics.ProcessStartInfo]$StartInfo,
        [Parameter(Mandatory = $true)][ValidateRange(0, 4096)][int]$ArgumentCount,
        [Parameter(Mandatory = $true)][object]$ErrorRecord
    )

    $nativeErrorCode = 0
    $hresult = 0
    $exception = if ($ErrorRecord -is [Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    } else {
        $ErrorRecord
    }
    if ($null -ne $exception) {
        $hresult = [int]$exception.HResult
        while ($null -ne $exception) {
            if ($exception -is [ComponentModel.Win32Exception]) {
                $nativeErrorCode = [int]$exception.NativeErrorCode
                break
            }
            $exception = $exception.InnerException
        }
    }

    $redirects = if ($StartInfo.RedirectStandardOutput -and $StartInfo.RedirectStandardError) {
        'stdout_stderr'
    } elseif ($StartInfo.RedirectStandardOutput) {
        'stdout'
    } elseif ($StartInfo.RedirectStandardError) {
        'stderr'
    } else {
        'none'
    }
    $executableClass = if ([IO.Path]::GetExtension($StartInfo.FileName) -ieq '.exe') {
        'windows_executable'
    } elseif ([IO.Path]::GetExtension($StartInfo.FileName) -ieq '.ps1') {
        'powershell_script'
    } else {
        'other'
    }
    $diagnostic = [ordered]@{
        launch_stage = $LaunchStage
        failure_kind = $FailureKind
        failed_field = $FailedField
        has_username = -not [string]::IsNullOrEmpty($StartInfo.UserName)
        has_domain = -not [string]::IsNullOrEmpty($StartInfo.Domain)
        has_secure_password = $null -ne $StartInfo.Password
        use_shell_execute = [bool]$StartInfo.UseShellExecute
        redirects = $redirects
        has_working_directory = -not [string]::IsNullOrEmpty($StartInfo.WorkingDirectory)
        load_user_profile = [bool]$StartInfo.LoadUserProfile
        argument_count = $ArgumentCount
        executable_class = $executableClass
        native_error_code = $nativeErrorCode
        hresult = $hresult
    }
    $json = $diagnostic | ConvertTo-Json -Compress -Depth 3
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt 8192) { throw 'credential launch diagnostics exceeded the bounded size' }
    return $json
}

if (-not ('SnipeSpotter.CredentialLaunchNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace SnipeSpotter
{
    public static class CredentialLaunchNative
    {
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const uint HANDLE_FLAG_INHERIT = 0x00000001;
        public const uint WAIT_OBJECT_0 = 0x00000000;
        public const uint WAIT_TIMEOUT = 0x00000102;
        public const uint WAIT_FAILED = 0xffffffff;

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreatePipe(
            out IntPtr hReadPipe,
            out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes,
            int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetHandleInformation(
            IntPtr hObject,
            uint dwMask,
            uint dwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            IntPtr lpPassword,
            uint dwLogonFlags,
            string lpApplicationName,
            IntPtr lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    }
}
'@
}

function Invoke-CredentialLaunchProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][psobject]$User
    )

    $commandExecutable = Join-Path $PSHOME 'pwsh.exe'
    $shortCommand = "`"$commandExecutable`" -NoLogo -NoProfile -NonInteractive -Command `"exit 0`""
    $longCommand = $shortCommand + ('x' * 1100)
    $explicitCommand = $shortCommand
    $cases = @(
        [pscustomobject]@{ Case = 'short_null_application'; Command = $shortCommand; ApplicationName = $null }
        [pscustomobject]@{ Case = 'long_null_application'; Command = $longCommand; ApplicationName = $null }
        [pscustomobject]@{ Case = 'short_explicit_application'; Command = $explicitCommand; ApplicationName = $commandExecutable }
    )

    $logonFlags = 0
    $dwCreationFlags = 0
    $lpEnvironment = [IntPtr]::Zero
    $lpCurrentDirectory = $null
    $bInheritHandles = $true
    $passwordPointer = [IntPtr]::Zero
    $records = @()
    try {
        $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($User.Password)
        foreach ($case in $cases) {
            $command = $case.Command
            $commandPointer = [IntPtr]::Zero
            $hInputRead = [IntPtr]::Zero
            $hInputWrite = [IntPtr]::Zero
            $hOutputRead = [IntPtr]::Zero
            $hOutputWrite = [IntPtr]::Zero
            $hErrorRead = [IntPtr]::Zero
            $hErrorWrite = [IntPtr]::Zero
            $processInfo = [SnipeSpotter.CredentialLaunchNative+PROCESS_INFORMATION]::new()
            $success = $false
            $nativeError = 0
            try {
                $securityAttributes = [SnipeSpotter.CredentialLaunchNative+SECURITY_ATTRIBUTES]::new()
                $securityAttributes.nLength = [Runtime.InteropServices.Marshal]::SizeOf($securityAttributes)
                $securityAttributes.bInheritHandle = $bInheritHandles
                if (-not [SnipeSpotter.CredentialLaunchNative]::CreatePipe(
                        [ref]$hInputRead,
                        [ref]$hInputWrite,
                        [ref]$securityAttributes,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe input pipe creation failed'
                }
                if (-not [SnipeSpotter.CredentialLaunchNative]::CreatePipe(
                        [ref]$hOutputRead,
                        [ref]$hOutputWrite,
                        [ref]$securityAttributes,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe output pipe creation failed'
                }
                if (-not [SnipeSpotter.CredentialLaunchNative]::CreatePipe(
                        [ref]$hErrorRead,
                        [ref]$hErrorWrite,
                        [ref]$securityAttributes,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe error pipe creation failed'
                }
                if (-not [SnipeSpotter.CredentialLaunchNative]::SetHandleInformation(
                        $hInputWrite,
                        [SnipeSpotter.CredentialLaunchNative]::HANDLE_FLAG_INHERIT,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe input handle setup failed'
                }
                if (-not [SnipeSpotter.CredentialLaunchNative]::SetHandleInformation(
                        $hOutputRead,
                        [SnipeSpotter.CredentialLaunchNative]::HANDLE_FLAG_INHERIT,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe output handle setup failed'
                }
                if (-not [SnipeSpotter.CredentialLaunchNative]::SetHandleInformation(
                        $hErrorRead,
                        [SnipeSpotter.CredentialLaunchNative]::HANDLE_FLAG_INHERIT,
                        0
                    )) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw 'credential probe error handle setup failed'
                }

                $startupInfo = [SnipeSpotter.CredentialLaunchNative+STARTUPINFO]::new()
                $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf($startupInfo)
                $startupInfo.dwFlags = [SnipeSpotter.CredentialLaunchNative]::STARTF_USESTDHANDLES
                $startupInfo.hStdInput = $hInputRead
                $startupInfo.hStdOutput = $hOutputWrite
                $startupInfo.hStdError = $hErrorWrite
                $commandPointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($command)
                $success = [SnipeSpotter.CredentialLaunchNative]::CreateProcessWithLogonW(
                    $User.Name,
                    $User.Domain,
                    $passwordPointer,
                    $logonFlags,
                    $case.ApplicationName,
                    $commandPointer,
                    $dwCreationFlags,
                    $lpEnvironment,
                    $lpCurrentDirectory,
                    [ref]$startupInfo,
                    [ref]$processInfo
                )
                if (-not $success) {
                    $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                } else {
                    $waitResult = [SnipeSpotter.CredentialLaunchNative]::WaitForSingleObject($processInfo.hProcess, 5000)
                    if ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0) {
                        # The credentialed probe child exited within the bounded wait.
                    } elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT) {
                        $nativeError = [int]$waitResult
                        $terminateSucceeded = [SnipeSpotter.CredentialLaunchNative]::TerminateProcess($processInfo.hProcess, 1)
                        if (-not $terminateSucceeded) {
                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            throw 'credential probe child termination failed'
                        }
                        $terminationWaitResult = [SnipeSpotter.CredentialLaunchNative]::WaitForSingleObject($processInfo.hProcess, 1000)
                        if ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_OBJECT_0) {
                            # The timed-out credentialed probe child was terminated within the bounded wait.
                        } elseif ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_TIMEOUT) {
                            $nativeError = [int]$terminationWaitResult
                            throw 'credential probe child termination did not complete within the bounded wait'
                        } elseif ($terminationWaitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {
                            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            throw 'credential probe child termination wait failed'
                        } else {
                            $nativeError = [int]$terminationWaitResult
                            throw 'credential probe child termination returned an unexpected wait status'
                        }
                    } elseif ($waitResult -eq [SnipeSpotter.CredentialLaunchNative]::WAIT_FAILED) {
                        $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw 'credential probe child wait failed'
                    } else {
                        $nativeError = [int]$waitResult
                        throw 'credential probe child returned an unexpected wait status'
                    }
                }
            } catch {
                if ($nativeError -eq 0) { $nativeError = 1 }
            } finally {
                if ($commandPointer -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($commandPointer)
                }
                foreach ($handle in @(
                    $hInputRead,
                    $hInputWrite,
                    $hOutputRead,
                    $hOutputWrite,
                    $hErrorRead,
                    $hErrorWrite,
                    $processInfo.hProcess,
                    $processInfo.hThread
                )) {
                    if ($handle -ne [IntPtr]::Zero) {
                        [void][SnipeSpotter.CredentialLaunchNative]::CloseHandle($handle)
                    }
                }
            }
            $lengthBucket = if ($command.Length -gt 1024) { 'over_1024' } else { 'short' }
            $records += [ordered]@{
                case = $case.Case
                success = $success
                native_error = $nativeError
                length_bucket = $lengthBucket
            }
        }
    } finally {
        if ($passwordPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
        }
    }
    $json = $records | ConvertTo-Json -Compress -Depth 3
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt 4096) { throw 'credential launch probe exceeded the bounded size' }
    return $json
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
    $failedField = 'unknown'
    $argumentCount = 0
    try {
        $failedField = 'file_name'
        $startInfo.FileName = $FilePath
        $failedField = 'use_shell_execute'
        $startInfo.UseShellExecute = $false
        $failedField = 'redirect_standard_output'
        $startInfo.RedirectStandardOutput = $true
        $failedField = 'redirect_standard_error'
        $startInfo.RedirectStandardError = $true
        $failedField = 'username'
        $startInfo.UserName = [string]$User.Name
        $failedField = 'domain'
        $startInfo.Domain = [string]$User.Domain
        $failedField = 'password'
        $startInfo.Password = $User.Password
        foreach ($argument in $ArgumentList) {
            $failedField = 'argument_list'
            [void]$startInfo.ArgumentList.Add($argument)
            $argumentCount++
        }
    } catch {
        $diagnostic = Get-CredentialLaunchDiagnostic -LaunchStage 'configuration' -FailureKind 'configuration' -FailedField $failedField -StartInfo $startInfo -ArgumentCount $argumentCount -ErrorRecord $_
        throw "credentialed launch failed: $diagnostic"
    }

    $process = [Diagnostics.Process]::new()
    try {
        try {
            $failedField = 'process_start_info'
            $process.StartInfo = $startInfo
        } catch {
            $diagnostic = Get-CredentialLaunchDiagnostic -LaunchStage 'configuration' -FailureKind 'configuration' -FailedField $failedField -StartInfo $startInfo -ArgumentCount $argumentCount -ErrorRecord $_
            throw "credentialed launch failed: $diagnostic"
        }
        try {
            $failedField = 'process_start'
            if (-not $process.Start()) { throw 'process start returned false' }
        } catch {
            $nativeStartErrorRecord = $_
            try {
                Invoke-CredentialLaunchProbe -User $User
            } catch {
                $null = $_
            }
            $diagnostic = Get-CredentialLaunchDiagnostic -LaunchStage 'native_start' -FailureKind 'native' -FailedField $failedField -StartInfo $startInfo -ArgumentCount $argumentCount -ErrorRecord $nativeStartErrorRecord
            throw "credentialed launch failed: $diagnostic"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { Write-Warning 'could not terminate standard-user process after timeout' }
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
