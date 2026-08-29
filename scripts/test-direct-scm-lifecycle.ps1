#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CliPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServicePath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunIdentity,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DataRoot,
    [string]$LogDirectory = "$env:RUNNER_TEMP\snipespotter-direct-scm-logs",
    [ValidateRange(5, 600)]
    [int]$WaitTimeoutSeconds = 90,
    [ValidateRange(1, 30)]
    [int]$PollIntervalSeconds = 1,
    [ValidateRange(185, 1200)]
    [int]$ProcessTimeoutSeconds = 185
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The registrar bounds stop and delete waits independently at 90 seconds each.
$RegistrarWaitTimeoutSeconds = 90
$MinimumProcessTimeoutSeconds = ($RegistrarWaitTimeoutSeconds * 2) + 5

# This harness consumes test-support CLI arguments and never uses the MSI-owned service identity.
$testSupportRoot = Join-Path $PSScriptRoot 'TestSupport'
Import-Module (Join-Path $testSupportRoot 'Scm.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Acl.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Security.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Diagnostics.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'SnipeItLoopback.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Cleanup.psm1') -Force
Import-Module (Join-Path $testSupportRoot 'Wait.psm1') -Force

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory = $true)][string]$Message)
    if (-not $Condition) { throw $Message }
}

Assert-True ($ProcessTimeoutSeconds -ge $MinimumProcessTimeoutSeconds) "ProcessTimeoutSeconds must be at least $MinimumProcessTimeoutSeconds seconds"

function Initialize-BoundedProcessCaptureType {
    if ($null -eq ('SnipeSpotter.Ac4BoundedProcessCapture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Text;

namespace SnipeSpotter
{
    public sealed class Ac4BoundedProcessCapture : IDisposable
    {
        private readonly object gate = new object();
        private readonly string sentinel;
        private readonly int maxCharacters;
        private readonly StringBuilder stdout = new StringBuilder();
        private readonly StringBuilder stderr = new StringBuilder();
        private string stdoutTail = string.Empty;
        private string stderrTail = string.Empty;
        private bool stdoutSentinelFound;
        private bool stderrSentinelFound;
        private bool stdoutRetainedTruncated;
        private bool stderrRetainedTruncated;
        private bool stdoutScanComplete;
        private bool stderrScanComplete;
        private bool scanError;
        private bool disposed;

        public Ac4BoundedProcessCapture(string sentinel, int maxCharacters)
        {
            if (string.IsNullOrEmpty(sentinel))
            {
                throw new ArgumentException("sentinel must not be empty", nameof(sentinel));
            }
            if (maxCharacters < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxCharacters));
            }
            this.sentinel = sentinel;
            this.maxCharacters = maxCharacters;
            StdoutHandler = new DataReceivedEventHandler(OnStdout);
            StderrHandler = new DataReceivedEventHandler(OnStderr);
        }

        public DataReceivedEventHandler StdoutHandler { get; }
        public DataReceivedEventHandler StderrHandler { get; }

        public string Stdout
        {
            get { lock (gate) { return stdout.ToString(); } }
        }

        public string Stderr
        {
            get { lock (gate) { return stderr.ToString(); } }
        }

        public bool StdoutSentinelFound { get { lock (gate) { return stdoutSentinelFound; } } }
        public bool StderrSentinelFound { get { lock (gate) { return stderrSentinelFound; } } }
        public bool StdoutRetainedTruncated { get { lock (gate) { return stdoutRetainedTruncated; } } }
        public bool StderrRetainedTruncated { get { lock (gate) { return stderrRetainedTruncated; } } }
        public bool StdoutScanComplete { get { lock (gate) { return stdoutScanComplete; } } }
        public bool StderrScanComplete { get { lock (gate) { return stderrScanComplete; } } }
        public bool ScanError { get { lock (gate) { return scanError; } } }

        public void Append(string streamName, string chunk)
        {
            if (streamName != "Stdout" && streamName != "Stderr")
            {
                throw new ArgumentException("unknown stream", nameof(streamName));
            }
            if (chunk == null)
            {
                return;
            }
            lock (gate)
            {
                if (disposed)
                {
                    throw new ObjectDisposedException(nameof(Ac4BoundedProcessCapture));
                }
                if (streamName == "Stdout")
                {
                    AppendStream(chunk, stdout, ref stdoutTail, ref stdoutSentinelFound, ref stdoutRetainedTruncated);
                }
                else
                {
                    AppendStream(chunk, stderr, ref stderrTail, ref stderrSentinelFound, ref stderrRetainedTruncated);
                }
            }
        }

        public void CompleteStdout()
        {
            lock (gate) { stdoutScanComplete = true; }
        }

        public void CompleteStderr()
        {
            lock (gate) { stderrScanComplete = true; }
        }

        private void OnStdout(object sender, DataReceivedEventArgs args)
        {
            try
            {
                if (args == null || args.Data == null)
                {
                    lock (gate) { stdoutScanComplete = true; }
                    return;
                }
                Append("Stdout", args.Data);
            }
            catch { lock (gate) { scanError = true; } }
        }

        private void OnStderr(object sender, DataReceivedEventArgs args)
        {
            try
            {
                if (args == null || args.Data == null)
                {
                    lock (gate) { stderrScanComplete = true; }
                    return;
                }
                Append("Stderr", args.Data);
            }
            catch { lock (gate) { scanError = true; } }
        }

        private void AppendStream(
            string chunk,
            StringBuilder retained,
            ref string scanTail,
            ref bool sentinelFound,
            ref bool retainedTruncated)
        {
            string combined = scanTail + chunk;
            if (combined.IndexOf(sentinel, StringComparison.Ordinal) >= 0)
            {
                sentinelFound = true;
            }

            int remaining = maxCharacters - retained.Length;
            if (chunk.Length > Math.Max(0, remaining))
            {
                retainedTruncated = true;
            }
            if (remaining > 0)
            {
                retained.Append(chunk, 0, Math.Min(remaining, chunk.Length));
            }

            int tailLength = Math.Min(Math.Max(0, sentinel.Length - 1), combined.Length);
            scanTail = tailLength == 0
                ? string.Empty
                : combined.Substring(combined.Length - tailLength, tailLength);
        }

        public void Dispose()
        {
            lock (gate) { disposed = true; }
        }
    }
}
'@
    }
}

function Sync-BoundedProcessCaptureState {
    param([Parameter(Mandatory = $true)][hashtable]$Capture)
    if (-not $Capture.ContainsKey('NativeCapture') -or $null -eq $Capture['NativeCapture']) { return }
    $native = $Capture['NativeCapture']
    $Capture.Stdout = [Text.StringBuilder]::new($native.Stdout)
    $Capture.Stderr = [Text.StringBuilder]::new($native.Stderr)
    $Capture.StdoutSentinelFound = $native.StdoutSentinelFound
    $Capture.StderrSentinelFound = $native.StderrSentinelFound
    $Capture.StdoutRetainedTruncated = $native.StdoutRetainedTruncated
    $Capture.StderrRetainedTruncated = $native.StderrRetainedTruncated
    $Capture.StdoutScanComplete = $native.StdoutScanComplete
    $Capture.StderrScanComplete = $native.StderrScanComplete
    $Capture.ScanError = $native.ScanError
}

function Write-BoundedProcessCaptureStream {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Capture,
        [Parameter(Mandatory = $true)][ValidateSet('Stdout', 'Stderr')][string]$StreamName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Chunk
    )

    if ($Capture.ContainsKey('NativeCapture') -and $null -ne $Capture['NativeCapture']) {
        try {
            $Capture['NativeCapture'].Append($StreamName, $Chunk)
        } catch {
            $Capture.ScanError = $true
        }
        return
    }

    $builder = $Capture[$StreamName]
    $tailName = "${StreamName}ScanTail"
    $foundName = "${StreamName}SentinelFound"
    $truncatedName = "${StreamName}RetainedTruncated"
    $previousTail = [string]$Capture[$tailName]
    $combined = $previousTail + $Chunk
    if ($combined.Contains([string]$Capture.Sentinel, [StringComparison]::Ordinal)) {
        $Capture[$foundName] = $true
    }

    # Retained output is diagnostic-only. Sentinel scanning always consumes the full chunk.
    $remaining = [int]$Capture.MaxCharacters - $builder.Length
    if ($Chunk.Length -gt [Math]::Max(0, $remaining)) {
        $Capture[$truncatedName] = $true
    }
    if ($remaining -gt 0) {
        $appendLength = [Math]::Min($remaining, $Chunk.Length)
        if ($appendLength -gt 0) {
            [void]$builder.Append($Chunk, 0, $appendLength)
        }
    }
    $tailLength = [Math]::Min([Math]::Max(0, ([string]$Capture.Sentinel).Length - 1), $combined.Length)
    $Capture[$tailName] = if ($tailLength -gt 0) {
        $combined.Substring($combined.Length - $tailLength)
    } else {
        ''
    }
}

function Complete-BoundedProcessCaptureStream {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Capture,
        [Parameter(Mandatory = $true)][ValidateSet('Stdout', 'Stderr')][string]$StreamName
    )
    if ($Capture.ContainsKey('NativeCapture') -and $null -ne $Capture['NativeCapture']) {
        if ($StreamName -eq 'Stdout') {
            $Capture['NativeCapture'].CompleteStdout()
        } else {
            $Capture['NativeCapture'].CompleteStderr()
        }
        Sync-BoundedProcessCaptureState -Capture $Capture
        return
    }
    $Capture["${StreamName}ScanComplete"] = $true
}

function Assert-BoundedProcessCaptureSafe {
    param([Parameter(Mandatory = $true)][hashtable]$Capture)
    if ($null -ne (Get-Command Sync-BoundedProcessCaptureState -ErrorAction SilentlyContinue)) {
        Sync-BoundedProcessCaptureState -Capture $Capture
    }
    foreach ($streamName in @('Stdout', 'Stderr')) {
        if ([bool]$Capture["${StreamName}SentinelFound"]) {
            throw 'bounded process output contains the token sentinel'
        }
        if (-not [bool]$Capture["${StreamName}ScanComplete"]) {
            throw 'bounded process output leak scan was incomplete'
        }
    }
    if ([bool]$Capture.ScanError) {
        throw 'bounded process output leak scan failed'
    }
}

function Get-BoundedProcessCapture {
    param([Parameter(Mandatory = $true)][hashtable]$Capture)
    Assert-True ($null -ne $Capture) 'bounded process capture state must not be null'
    Initialize-BoundedProcessCaptureType
    if (-not $Capture.ContainsKey('NativeCapture') -or $null -eq $Capture['NativeCapture']) {
        $Capture.NativeCapture = [SnipeSpotter.Ac4BoundedProcessCapture]::new(
            [string]$Capture.Sentinel,
            [int]$Capture.MaxCharacters
        )
    }
    [pscustomobject]@{
        StdoutHandler = $Capture.NativeCapture.StdoutHandler
        StderrHandler = $Capture.NativeCapture.StderrHandler
        NativeCapture = $Capture.NativeCapture
    }
}

function Get-BoundedRemainingMillisecond {
    param([Parameter(Mandatory = $true)][DateTime]$Deadline)
    $remaining = ($Deadline - [DateTime]::UtcNow).TotalMilliseconds
    if ($remaining -le 0) { return 0 }
    return [Math]::Max(1, [int][Math]::Floor($remaining))
}

function Invoke-BoundedProcessStop {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][ValidateRange(1, 30000)][int]$WaitMilliseconds
    )
    if ($Process.HasExited) { return }
    try {
        $Process.Kill($true)
    } catch {
        throw 'child process termination failed'
    }
    try {
        if (-not $Process.WaitForExit($WaitMilliseconds)) {
            throw 'child process did not exit after termination'
        }
    } catch {
        throw 'child process termination wait failed'
    }
    if (-not $Process.HasExited) {
        throw 'child process remained alive after termination'
    }
}

function Wait-BoundedTask {
    param(
        [Parameter(Mandatory = $true)][Threading.Tasks.Task]$Task,
        [Parameter(Mandatory = $true)][DateTime]$Deadline,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    try {
        $remainingMilliseconds = Get-BoundedRemainingMillisecond -Deadline $Deadline
        if ($remainingMilliseconds -le 0 -or -not $Task.Wait($remainingMilliseconds)) {
            throw $FailureMessage
        }
        $Task.GetAwaiter().GetResult()
    } catch {
        throw $FailureMessage
    }
}

function Invoke-BoundedStandardInput {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][DateTime]$Deadline
    )
    $stdinError = $null
    $stdinCleanupError = $null
    try {
        $writeTask = $Process.StandardInput.WriteAsync($Text)
        Wait-BoundedTask -Task $writeTask -Deadline $Deadline -FailureMessage 'child stdin write failed or exceeded the process deadline'

        $flushTask = $Process.StandardInput.FlushAsync()
        Wait-BoundedTask -Task $flushTask -Deadline $Deadline -FailureMessage 'child stdin flush failed or exceeded the process deadline'

        $closeValueTask = $Process.StandardInput.DisposeAsync()
        $closeTask = $closeValueTask.AsTask()
        Wait-BoundedTask -Task $closeTask -Deadline $Deadline -FailureMessage 'child stdin close failed or exceeded the process deadline'
    } catch {
        $stdinError = $_
        try {
            if (-not $Process.HasExited) {
                Invoke-BoundedProcessStop -Process $Process -WaitMilliseconds 5000
            }
            if (-not $Process.HasExited) {
                throw 'child process remained alive after termination'
            }
        } catch {
            $stdinCleanupError = $_
        }
        if ($stdinError -and $stdinCleanupError) { throw 'child stdin operation failed and cleanup failed' }
        if ($stdinError) { throw $stdinError }
        throw 'child process cleanup failed'
    }
}

function Invoke-BoundedProcessCaptureCleanup {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][object]$Handlers
    )
    $cleanupFailed = $false
    try { $Process.remove_OutputDataReceived($Handlers.StdoutHandler) } catch { $cleanupFailed = $true }
    try { $Process.remove_ErrorDataReceived($Handlers.StderrHandler) } catch { $cleanupFailed = $true }
    try {
        $nativeProperty = $Handlers.PSObject.Properties['NativeCapture']
        if ($null -ne $nativeProperty -and $null -ne $nativeProperty.Value) {
            $nativeProperty.Value.Dispose()
        }
    } catch { $cleanupFailed = $true }
    if ($cleanupFailed) {
        throw 'child process capture cleanup failed'
    }
}

function Invoke-BoundedProcessCleanup {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][bool]$Started
    )
    $cleanupFailed = $false
    try {
        if ($Started) {
            if (-not $Process.HasExited) {
                Invoke-BoundedProcessStop -Process $Process -WaitMilliseconds 5000
            }
            if (-not $Process.HasExited) {
                throw 'child process remained alive after termination'
            }
        }
    } catch {
        $cleanupFailed = $true
    } finally {
        try {
            $Process.Dispose()
        } catch {
            $cleanupFailed = $true
        }
    }
    if ($cleanupFailed) {
        throw 'child process cleanup failed'
    }
}

function Wait-BoundedProcessOutput {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][DateTime]$Deadline
    )
    $remainingMilliseconds = Get-BoundedRemainingMillisecond -Deadline $Deadline
    if ($remainingMilliseconds -le 0 -or -not $Process.WaitForExit($remainingMilliseconds)) {
        throw 'child process did not exit within the process deadline'
    }
    if (-not $Process.HasExited) {
        throw 'child process exit state was unavailable'
    }
    # A second bounded wait drains asynchronous output handlers without exceeding the deadline.
    $remainingMilliseconds = Get-BoundedRemainingMillisecond -Deadline $Deadline
    if ($remainingMilliseconds -le 0 -or -not $Process.WaitForExit($remainingMilliseconds)) {
        throw 'child process output did not drain within the process deadline'
    }
    if (-not $Process.HasExited) {
        throw 'child process remained alive after bounded wait'
    }
}

function Invoke-DirectCli {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CliPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $capture = [hashtable]::Synchronized(@{
        Sentinel = $tokenSentinel
        MaxCharacters = 65536
        Stdout = [Text.StringBuilder]::new()
        Stderr = [Text.StringBuilder]::new()
        StdoutScanTail = ''
        StderrScanTail = ''
        StdoutSentinelFound = $false
        StderrSentinelFound = $false
        StdoutRetainedTruncated = $false
        StderrRetainedTruncated = $false
        StdoutScanComplete = $false
        StderrScanComplete = $false
        ScanError = $false
    })
    $handlers = Get-BoundedProcessCapture -Capture $capture
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $process.add_OutputDataReceived($handlers.StdoutHandler)
    $process.add_ErrorDataReceived($handlers.StderrHandler)
    $deadline = [DateTime]::UtcNow.AddSeconds($ProcessTimeoutSeconds)
    $started = $false
    $primaryError = $null
    $cleanupError = $null
    try {
        try {
            if (-not $process.Start()) { throw "$Description could not start" }
            $started = $true
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            try {
                Wait-BoundedProcessOutput -Process $process -Deadline $deadline
            } catch {
                throw "$Description did not exit within $ProcessTimeoutSeconds seconds"
            }
            Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout'
            Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr'
            $exitCode = $process.ExitCode
            Assert-BoundedProcessCaptureSafe -Capture $capture
        } catch {
            $primaryError = $_
        }
    } finally {
        try {
            Invoke-BoundedProcessCaptureCleanup -Process $process -Handlers $handlers
        } catch {
            $cleanupError = $_
        }
        try {
            Invoke-BoundedProcessCleanup -Process $process -Started $started
        } catch {
            if ($null -eq $cleanupError) { $cleanupError = $_ }
        }
    }
    if ($primaryError -and $cleanupError) { throw 'child process operation failed and cleanup failed' }
    if ($primaryError) { throw $primaryError }
    if ($cleanupError) { throw 'child process cleanup failed' }
    $stdout = $capture.Stdout.ToString()
    $stderr = $capture.Stderr.ToString()
    [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        Description = $Description
    }
}

function Get-CommonCliArgument {
    @(
        '--test-service-name', $serviceName,
        '--test-data-root', $DataRoot,
        '--test-pipe-endpoint', $pipeEndpoint,
        '--test-mutex-name', $mutexName,
        '--test-service-executable', $ServicePath
    )
}

function Invoke-TokenCli {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-True (-not [string]::IsNullOrEmpty($Token)) "$Description token must not be empty"
    Assert-True (-not ($Arguments -contains $Token)) "$Description token must not be an argument"
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CliPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $capture = [hashtable]::Synchronized(@{
        Sentinel = $Token
        MaxCharacters = 65536
        Stdout = [Text.StringBuilder]::new()
        Stderr = [Text.StringBuilder]::new()
        StdoutScanTail = ''
        StderrScanTail = ''
        StdoutSentinelFound = $false
        StderrSentinelFound = $false
        StdoutRetainedTruncated = $false
        StderrRetainedTruncated = $false
        StdoutScanComplete = $false
        StderrScanComplete = $false
        ScanError = $false
    })
    $handlers = Get-BoundedProcessCapture -Capture $capture
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $process.add_OutputDataReceived($handlers.StdoutHandler)
    $process.add_ErrorDataReceived($handlers.StderrHandler)
    $exitCode = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($ProcessTimeoutSeconds)
    $started = $false
    $primaryError = $null
    $cleanupError = $null
    try {
        try {
            if (-not $process.Start()) { throw "$Description could not start" }
            $started = $true
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            Invoke-BoundedStandardInput -Process $process -Text $Token -Deadline $deadline
            try {
                Wait-BoundedProcessOutput -Process $process -Deadline $deadline
            } catch {
                throw "$Description did not exit within $ProcessTimeoutSeconds seconds"
            }
            Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stdout'
            Complete-BoundedProcessCaptureStream -Capture $capture -StreamName 'Stderr'
            $exitCode = $process.ExitCode
            Assert-BoundedProcessCaptureSafe -Capture $capture
        } catch {
            $primaryError = $_
        }
    } finally {
        try {
            Invoke-BoundedProcessCaptureCleanup -Process $process -Handlers $handlers
        } catch {
            $cleanupError = $_
        }
        try {
            Invoke-BoundedProcessCleanup -Process $process -Started $started
        } catch {
            if ($null -eq $cleanupError) { $cleanupError = $_ }
        }
    }
    if ($primaryError -and $cleanupError) { throw 'child process operation failed and cleanup failed' }
    if ($primaryError) { throw $primaryError }
    if ($cleanupError) { throw 'child process cleanup failed' }
    $stdout = $capture.Stdout.ToString()
    $stderr = $capture.Stderr.ToString()
    [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        Description = $Description
    }
}

function Assert-NoSentinelInText {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Sentinel,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Assert-True (-not $Text.Contains($Sentinel, [StringComparison]::Ordinal)) "$Description contains the token sentinel"
}

function Test-BytePatternInWindow {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Window,
        [Parameter(Mandatory = $true)][byte[]]$Pattern
    )
    if ($Pattern.Length -eq 0 -or $Window.Length -lt $Pattern.Length) { return $false }
    for ($start = 0; $start -le $Window.Length - $Pattern.Length; $start++) {
        $match = $true
        for ($index = 0; $index -lt $Pattern.Length; $index++) {
            if ($Window[$start + $index] -ne $Pattern[$index]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
    }
    return $false
}

function Write-ByteSentinelScan {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Scan,
        [Parameter(Mandatory = $true)][byte[]]$Chunk
    )
    $window = [byte[]]::new($Scan.Tail.Length + $Chunk.Length)
    if ($Scan.Tail.Length -gt 0) { [Array]::Copy($Scan.Tail, 0, $window, 0, $Scan.Tail.Length) }
    if ($Chunk.Length -gt 0) { [Array]::Copy($Chunk, 0, $window, $Scan.Tail.Length, $Chunk.Length) }
    foreach ($pattern in @($Scan.Patterns)) {
        if (Test-BytePatternInWindow -Window $window -Pattern $pattern) {
            $Scan.Found = $true
        }
    }
    $tailLength = [Math]::Min([int]$Scan.MaxTailLength, $window.Length)
    $Scan.Tail = if ($tailLength -gt 0) {
        $tail = [byte[]]::new($tailLength)
        [Array]::Copy($window, $window.Length - $tailLength, $tail, 0, $tailLength)
        $tail
    } else {
        [byte[]]::new(0)
    }
}

function Invoke-BoundedArtifactStreamScan {
    param(
        [Parameter(Mandatory = $true)][IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int64]$ExpectedLength,
        [Parameter(Mandatory = $true)][hashtable]$Scan
    )
    if ($ExpectedLength -lt 0) { throw 'artifact leak scan failed' }
    $buffer = [byte[]]::new(65536)
    try {
        while ($true) {
            $read = $Stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            if ($read -eq $buffer.Length) {
                Write-ByteSentinelScan -Scan $Scan -Chunk $buffer
            } else {
                $chunk = [byte[]]::new($read)
                [Array]::Copy($buffer, $chunk, $read)
                Write-ByteSentinelScan -Scan $Scan -Chunk $chunk
            }
        }
        if ($Stream.Position -ne $ExpectedLength) {
            throw 'artifact leak scan did not reach the complete file'
        }
        $Scan.Complete = $true
    } catch {
        throw 'artifact leak scan failed'
    }
}

function Assert-NoSentinelInArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Sentinel,
        [Parameter(Mandatory = $false)][ValidateRange(1, 1073741824)][int64]$MaxArtifactBytes = 67108864
    )
    if (-not (Test-Path -LiteralPath $Root -PathType Container -ErrorAction SilentlyContinue)) {
        throw 'artifact leak scan failed'
    }
    $patterns = @(
        [Text.Encoding]::ASCII.GetBytes($Sentinel),
        [Text.Encoding]::UTF8.GetBytes($Sentinel),
        [Text.Encoding]::Unicode.GetBytes($Sentinel),
        [Text.Encoding]::BigEndianUnicode.GetBytes($Sentinel)
    )
    $maxTailLength = [Math]::Max(0, (($patterns | Measure-Object -Property Length -Maximum).Maximum - 1))
    try {
        $artifacts = @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction Stop)
    } catch {
        throw 'artifact leak scan failed'
    }
    foreach ($artifact in $artifacts) {
        if ($artifact.Length -gt $MaxArtifactBytes) {
            throw 'artifact leak scan failed'
        }
        $scan = @{
            Patterns = $patterns
            MaxTailLength = $maxTailLength
            Tail = [byte[]]::new(0)
            Found = $false
            Complete = $false
        }
        $stream = $null
        try {
            $stream = [IO.File]::OpenRead($artifact.FullName)
            Invoke-BoundedArtifactStreamScan -Stream $stream -ExpectedLength ([int64]$artifact.Length) -Scan $scan
        } catch {
            throw 'artifact leak scan failed'
        } finally {
            if ($null -ne $stream) {
                try { $stream.Dispose() } catch { throw 'artifact leak scan failed' }
            }
        }
        if (-not [bool]$scan.Complete) {
            throw 'artifact leak scan failed'
        }
        if ($scan.Found) {
            throw 'artifact leak scan found the token sentinel'
        }
    }
}

function Assert-EncryptedTokenSetting {
    param([Parameter(Mandatory = $true)][string]$SettingsText)
    $section = $null
    $encoded = $null
    foreach ($line in ($SettingsText -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[(?<name>[A-Za-z0-9_-]+)\]$') {
            $section = $Matches['name']
            continue
        }
        if ($section -cne 'snipeit' -or $trimmed.StartsWith('#') -or $trimmed.Length -eq 0) {
            continue
        }
        $match = [Text.RegularExpressions.Regex]::Match(
            $trimmed,
            '^api_token_encrypted\s*=\s*"(?<encoded>[A-Za-z0-9+/]+={0,2})"$'
        )
        if ($match.Success) {
            $encoded = $match.Groups['encoded'].Value
            break
        }
    }
    if ($null -eq $encoded -or $encoded.Length -eq 0) { throw 'encrypted token setting was missing or malformed' }
    try {
        $bytes = [Convert]::FromBase64String($encoded)
    } catch {
        throw 'encrypted token setting was not canonical base64'
    }
    $canonical = [Convert]::ToBase64String($bytes)
    if ($canonical -cne $encoded) { throw 'encrypted token setting was not canonical base64' }
    if ($bytes.Length -lt 32) { throw 'encrypted token ciphertext was too short' }
    $expectedHeader = [byte[]](
        0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15,
        0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb
    )
    for ($index = 0; $index -lt $expectedHeader.Length; $index++) {
        if ($bytes[$index] -ne $expectedHeader[$index]) {
            throw 'encrypted token ciphertext had an invalid DPAPI structure'
        }
    }
}

function Invoke-DirectUninstall {
    $result = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'uninstall')) -Description 'ServiceUninstall'
    if ($result.ExitCode -ne 0) {
        throw "direct service uninstall failed with exit code $($result.ExitCode): $($result.Stderr.Trim())"
    }
}

function Get-DirectStatus {
    $result = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('--json', 'status')) -Description 'StatusHealthCheck'
    if ($result.ExitCode -ne 0) { return $null }
    try {
        $status = $result.Stdout | ConvertFrom-Json
        if ($status.type -ne 'status') { return $null }
        return $status
    } catch {
        return $null
    }
}

function Assert-DirectRuntimeAcl {
    param([Parameter(Mandatory = $true)][object[]]$Artifacts)

    $normalizedRules = @(Get-NormalizedAcl -Path $DataRoot)
    Assert-True ($normalizedRules.Count -gt 0) 'direct service data root has no ACL rules'
    [void](Assert-AclContract -Path $DataRoot -PathType Container)
    foreach ($artifact in $Artifacts) {
        if ($artifact.Path -ne $DataRoot) {
            [void](Assert-AclContract -Path $artifact.Path -PathType $artifact.Type)
        }
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-True $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'direct SCM lifecycle requires an elevated administrator token'
Assert-True ($RunIdentity -match '^[A-Za-z0-9-]+$') 'RunIdentity must contain only letters, digits, and hyphens'

$CliPath = (Resolve-Path -LiteralPath $CliPath).Path
$ServicePath = (Resolve-Path -LiteralPath $ServicePath).Path
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
New-Item -ItemType Directory -Force -Path $LogDirectory, $DataRoot | Out-Null
Assert-True ([IO.Path]::GetExtension($CliPath) -ieq '.exe') 'CliPath must point to an executable'
Assert-True ([IO.Path]::GetExtension($ServicePath) -ieq '.exe') 'ServicePath must point to an executable'

$serviceName = "SnipeSpotterDirect-$RunIdentity"
$pipeEndpoint = "\\.\pipe\SnipeSpotterDirect-$RunIdentity"
$mutexName = "Global\SnipeSpotterDirect-$RunIdentity"
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
Assert-True ($null -eq $service) "refusing to mutate pre-existing unique service $serviceName"

$tokenSentinel = "AC4-" + [Guid]::NewGuid().ToString('N')
$fixture = $null
$primaryError = $null
$cleanupError = $null
try {
    $install = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'install')) -Description 'ServiceInstall'
    Assert-True ($install.ExitCode -eq 0) "direct service install failed: $($install.Stderr.Trim())"

    $duplicate = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'install')) -Description 'DuplicateServiceInstall'
    Assert-True ($duplicate.ExitCode -eq 1) "already-installed contract returned exit code $($duplicate.ExitCode)"
    Assert-True ($duplicate.Stderr.Contains('already installed')) 'already-installed contract did not report an actionable error'

    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    Assert-True ($null -ne $service) 'ServiceQueryConfig could not find the direct service registration'
    Assert-True ($service.StartMode -eq 'Auto') "direct service start mode was $($service.StartMode), expected Auto"
    Assert-True ($service.StartName -in @('LocalSystem', 'LocalSystem account')) "direct service account was $($service.StartName), expected LocalSystem"
    Assert-True ($service.PathName.Contains($ServicePath)) 'direct service registration omitted the service executable path'
    foreach ($runtimeValue in @($serviceName, $DataRoot, $pipeEndpoint, $mutexName)) {
        Assert-True ($service.PathName.Contains($runtimeValue)) "direct service registration omitted runtime value $runtimeValue"
    }
    Assert-True ($service.PathName -match '(?i)spotter-svc\.exe') 'direct service registration is not an own-process service executable'

    Start-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Running' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Wait-ConditionStable -Description "direct service $serviceName to remain Running" -StabilitySeconds 5 -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $candidate = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        $null -ne $candidate -and $candidate.Status -eq 'Running'
    }
    Assert-ServiceRunsAsSystem -Name $serviceName
    Wait-Condition -Description "direct service $serviceName status response" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $status = Get-DirectStatus
        $null -ne $status -and $status.data.state -eq 'Unconfigured'
    } | Out-Null

    $fixture = Start-SnipeItLoopbackFixture -AuthorizationSentinel $tokenSentinel
    Wait-Condition -Description 'Snipe-IT loopback fixture readiness' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $fixture.State.Ready -and $fixture.Listener.IsListening
    } | Out-Null
    Assert-True $fixture.Prefix.StartsWith('http://127.0.0.1:') 'loopback fixture did not bind only to 127.0.0.1'

    foreach ($update in @(
        @('snipeit.url', $fixture.Prefix.TrimEnd('/')),
        @('snipeit.checkout_status_id', '1'),
        @('snipeit.checkin_status_id', '2')
    )) {
        $result = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('config', 'set', $update[0], $update[1])) -Description "SetConfig-$($update[0])"
        Assert-True ($result.ExitCode -eq 0) "configuration update $($update[0]) failed"
        Assert-NoSentinelInText -Text $result.Stdout -Sentinel $tokenSentinel -Description "configuration update $($update[0]) stdout"
        Assert-NoSentinelInText -Text $result.Stderr -Sentinel $tokenSentinel -Description "configuration update $($update[0]) stderr"
    }

    $tokenResult = Invoke-TokenCli -Arguments (@(Get-CommonCliArgument) + @('config', 'set-token')) -Token $tokenSentinel -Description 'SetToken'
    Assert-True ($tokenResult.ExitCode -eq 0) 'token submission failed'
    Assert-NoSentinelInText -Text $tokenResult.Stdout -Sentinel $tokenSentinel -Description 'token submission stdout'
    Assert-NoSentinelInText -Text $tokenResult.Stderr -Sentinel $tokenSentinel -Description 'token submission stderr'

    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Stopped' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Restart-Service -Name $serviceName -Force -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Running' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Assert-ServiceRunsAsSystem -Name $serviceName
    Wait-Condition -Description "configured service $serviceName status response" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $status = Get-DirectStatus
        $null -ne $status -and $status.data.state -eq 'Idle'
    } | Out-Null

    $sync = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('sync')) -Description 'TriggerSync'
    Assert-True ($sync.ExitCode -eq 0) 'explicit sync trigger failed'
    Assert-NoSentinelInText -Text $sync.Stdout -Sentinel $tokenSentinel -Description 'sync stdout'
    Assert-NoSentinelInText -Text $sync.Stderr -Sentinel $tokenSentinel -Description 'sync stderr'
    Wait-Condition -Description 'authenticated Snipe-IT reads' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
        $evidence = Get-SnipeItLoopbackEvidence -Fixture $fixture
        @($evidence.Requests | Where-Object { $_.accepted -and $_.authorized }).Count -ge 3
    } | Out-Null
    $evidence = Get-SnipeItLoopbackEvidence -Fixture $fixture
    Assert-True ($null -eq $evidence.WorkerError) 'loopback fixture worker failed'
    Assert-True ($evidence.DroppedRequests -eq 0) 'loopback fixture dropped request evidence'
    Assert-True (@($evidence.Requests | Where-Object { $_.accepted -and -not $_.authorized }).Count -eq 0) 'unauthorized request was accepted'
    Assert-True (@($evidence.Requests | Where-Object { $_.method_class -eq 'mutation' }).Count -eq 0) 'fixture observed a mutation request'
    Assert-True (@($evidence.Requests | Where-Object { $_.route -eq 'unexpected' }).Count -eq 0) 'fixture observed an unexpected route'
    Assert-True (@($evidence.Requests | Where-Object { $_.route -eq 'hardware_byserial' -and $_.response_class -eq 'not_found' }).Count -gt 0) 'fixture did not serve a hardware not-found read'
    Assert-True (@($evidence.Requests | Where-Object { $_.route -in @('manufacturers', 'models') -and $_.response_class -eq 'rows_empty' }).Count -ge 2) 'fixture did not serve empty taxonomy reads'

    $settingsText = [IO.File]::ReadAllText((Join-Path $DataRoot 'settings.toml'))
    Assert-EncryptedTokenSetting -SettingsText $settingsText
    Assert-NoSentinelInText -Text $settingsText -Sentinel $tokenSentinel -Description 'settings.toml'
    Assert-NoSentinelInArtifact -Root $DataRoot -Sentinel $tokenSentinel
    Assert-NoSentinelInArtifact -Root $LogDirectory -Sentinel $tokenSentinel

    $runtimeArtifacts = @(
        [pscustomobject]@{ Path = $DataRoot; Type = 'Container' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'settings.toml'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'state-hmac-key.bin'); Type = 'Leaf' },
        [pscustomobject]@{ Path = (Join-Path $DataRoot 'logs'); Type = 'Container' }
    )
    foreach ($artifact in $runtimeArtifacts) {
        Wait-Condition -Description "direct runtime artifact $($artifact.Path)" -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            Test-Path -LiteralPath $artifact.Path -PathType $artifact.Type
        } | Out-Null
    }
    foreach ($optionalArtifact in @('state.toml', 'operations.jsonl')) {
        $optionalPath = Join-Path $DataRoot $optionalArtifact
        if (Test-Path -LiteralPath $optionalPath -PathType Leaf) {
            $runtimeArtifacts += [pscustomobject]@{ Path = $optionalPath; Type = 'Leaf' }
        }
    }
    $logFiles = @(
        Wait-Condition -Description 'direct service rolling log file' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Condition {
            @(Get-ChildItem -LiteralPath (Join-Path $DataRoot 'logs') -Filter 'spotter-svc.log*' -File -ErrorAction SilentlyContinue)
        }
    )
    $runtimeArtifacts += @(
        $logFiles | ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Type = 'Leaf' }
        }
    )
    Assert-DirectRuntimeAcl -Artifacts $runtimeArtifacts

    $standardUser = New-TemporaryStandardUser -Name ("SpotterAcl" + (Get-Random -Minimum 10000 -Maximum 99999))
    try {
        foreach ($artifact in $runtimeArtifacts) {
            $probeResult = Assert-StandardUserCannotReadWrite -User $standardUser -Path $artifact.Path -PathType $artifact.Type -TimeoutSeconds $WaitTimeoutSeconds
            [void](Assert-ChildIsStandardUser -Result $probeResult)
        }
    } finally {
        Remove-TemporaryStandardUser -User $standardUser
    }

    Stop-Service -Name $serviceName -ErrorAction Stop
    Wait-ServiceState -Name $serviceName -State 'Stopped' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
    Invoke-DirectUninstall
    Wait-ServiceRemoved -Name $serviceName -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds

    $missing = Invoke-DirectCli -Arguments (@(Get-CommonCliArgument) + @('service', 'uninstall')) -Description 'MissingServiceUninstall'
    Assert-True ($missing.ExitCode -eq 1) "missing-service contract returned exit code $($missing.ExitCode)"
    Assert-True ($missing.Stderr.Contains('not installed')) 'missing-service contract did not report an actionable error'
} catch {
    $primaryError = $_
    Write-BoundedDiagnostic -Path (Join-Path $LogDirectory 'failure-state.json') -Values @{
        phase = 'direct-scm-failure'
        service_name = $serviceName
        service_status = if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { 'absent' } else { (Get-Service -Name $serviceName).Status.ToString() }
        data_root_exists = [bool](Test-Path -LiteralPath $DataRoot)
    }
} finally {
    try {
        Invoke-FailureSafeCleanup -Actions @(
            {
                if ($null -ne $fixture) {
                    Stop-SnipeItLoopbackFixture -Fixture $fixture -TimeoutSeconds $WaitTimeoutSeconds
                }
            },
            {
                $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $existing -and $existing.Status -ne 'Stopped') {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                }
            },
            {
                $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Wait-ServiceState -Name $serviceName -State 'Stopped' -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
                }
            },
            {
                Assert-NoSentinelInArtifact -Root $DataRoot -Sentinel $tokenSentinel
                Assert-NoSentinelInArtifact -Root $LogDirectory -Sentinel $tokenSentinel
            },
            {
                $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Invoke-DirectUninstall
                }
            },
            {
                Wait-ServiceRemoved -Name $serviceName -TimeoutSeconds $WaitTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds
            },
            {
                if (Test-Path -LiteralPath $DataRoot) {
                    Remove-Item -LiteralPath $DataRoot -Recurse -Force
                }
            }
        ) -FailurePrefix 'direct SCM cleanup failed'
    } catch {
        $cleanupError = $_
    }
}

if ($primaryError -or $cleanupError) {
    $messages = @()
    if ($primaryError) { $messages += "direct SCM lifecycle failed: $($primaryError.Exception.Message)" }
    if ($cleanupError) { $messages += "direct SCM cleanup failed: $($cleanupError.Exception.Message)" }
    throw ($messages -join '; ')
}

Write-Output 'direct SCM lifecycle validation passed'
