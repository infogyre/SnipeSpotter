# pattern: Imperative Shell

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MaxRecordedRequests = 128
$MaxBindAttempts = 8

function Start-SnipeItLoopbackFixture {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AuthorizationSentinel
    )

    if ($AuthorizationSentinel.Contains("`r") -or $AuthorizationSentinel.Contains("`n")) {
        throw 'loopback authorization sentinel must not contain line breaks'
    }
    if (-not $PSCmdlet.ShouldProcess('loopback fixture', 'start loopback fixture')) {
        throw 'loopback fixture start was declined'
    }

    $requests = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
    $state = [hashtable]::Synchronized(@{
        Listener = $null
        Prefix = $null
        ExpectedAuthorization = "Bearer $AuthorizationSentinel"
        Requests = $requests
        DroppedRequests = 0
        StopRequested = $false
        Ready = $false
        WorkerError = $null
        BindAttempts = 0
    })

    $worker = [PowerShell]::Create()
    [void]$worker.AddScript({
        param($state, $maxRecordedRequests, $maxBindAttempts)

        function Get-QueryMultiset {
            param([Uri]$Uri)
            $pairs = [Collections.Generic.List[string]]::new()
            $query = $Uri.Query
            if ($query.StartsWith('?')) { $query = $query.Substring(1) }
            if ([string]::IsNullOrEmpty($query)) { return ,$pairs }
            foreach ($part in $query.Split('&')) {
                if ([string]::IsNullOrEmpty($part) -or -not $part.Contains('=')) {
                    return $null
                }
                $keyValue = $part.Split('=', 2)
                if ([string]::IsNullOrEmpty($keyValue[0])) { return $null }
                [void]$pairs.Add($keyValue[0] + '=' + $keyValue[1])
            }
            return ,$pairs
        }

        function Test-ExpectedQuery {
            param([Uri]$Uri, [string]$Route)
            $actual = Get-QueryMultiset -Uri $Uri
            if ($null -eq $actual) { return $false }
            $expectedKeys = if ($Route -in @('manufacturers', 'models')) {
                @('search', 'limit', 'offset')
            } else {
                @()
            }
            if ($actual.Count -ne $expectedKeys.Count) { return $false }
            $actualKeys = @($actual | ForEach-Object { $_.Substring(0, $_.IndexOf('=')) })
            foreach ($key in $expectedKeys) {
                if (@($actualKeys | Where-Object { $_ -eq $key }).Count -ne 1) { return $false }
            }
            foreach ($item in $actual) {
                $key = $item.Substring(0, $item.IndexOf('='))
                $value = $item.Substring($item.IndexOf('=') + 1)
                if ($key -eq 'limit' -and $value -cne '100') { return $false }
                if ($key -in @('search', 'offset') -and [string]::IsNullOrEmpty($value)) { return $false }
                if ($key -eq 'offset' -and $value -notmatch '^(0|[1-9][0-9]*)$') { return $false }
            }
            return $true
        }

        $listener = $null
        $contextTask = $null
        $requestStage = 'not_started'
        $workerRequests = [Collections.Generic.List[object]]::new()
        try {
            for ($attempt = 1; $attempt -le $maxBindAttempts -and -not $state.StopRequested; $attempt++) {
                $candidate = [Net.HttpListener]::new()
                try {
                    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
                    $reservation.Start()
                    try {
                        $port = ([Net.IPEndPoint]$reservation.LocalEndpoint).Port
                    } finally {
                        $reservation.Stop()
                    }
                    if ($port -le 0) { throw 'loopback fixture did not receive an ephemeral port' }
                    $candidate.Prefixes.Add('http://127.0.0.1:' + $port + '/')
                    $candidate.Start()
                    $listener = $candidate
                    $actualPort = ([Uri]('http://127.0.0.1:' + $port + '/')).Port
                    if ($actualPort -le 0) { throw 'loopback fixture received an invalid ephemeral port' }
                    $state.Listener = $listener
                    $state.Prefix = 'http://127.0.0.1:' + $actualPort + '/'
                    $state.BindAttempts = $attempt
                    break
                } catch {
                    $candidate.Close()
                    if ($attempt -eq $maxBindAttempts) { throw 'loopback fixture could not bind a loopback listener' }
                }
            }
            if ($null -eq $listener -or -not $listener.IsListening) {
                throw 'loopback fixture listener was not listening'
            }

            $contextTask = $listener.GetContextAsync()
            if ($contextTask.IsCompleted -and $contextTask.IsFaulted) {
                throw 'loopback fixture receive capability failed'
            }
            $state.Ready = $true

            while (-not $state.StopRequested) {
                try {
                    if ($null -eq $contextTask) { $contextTask = $listener.GetContextAsync() }
                    if (-not $contextTask.Wait(250)) { continue }
                    $context = $contextTask.GetAwaiter().GetResult()
                    $contextTask = $null
                    try {
                        $requestStage = 'request_metadata'
                        $method = $context.Request.HttpMethod
                        $uri = $context.Request.Url
                        $path = $uri.AbsolutePath
                        $route = if ($path -match '^/api/v1/hardware/byserial/[^/]+$') {
                            'hardware_byserial'
                        } elseif ($path -eq '/api/v1/manufacturers') {
                            'manufacturers'
                        } elseif ($path -eq '/api/v1/models') {
                            'models'
                        } else {
                            'unexpected'
                        }
                        $requestStage = 'request_query'
                        $queryValid = if ($route -in @('manufacturers', 'models')) {
                            Test-ExpectedQuery -Uri $uri -Route $route
                        } elseif ($route -eq 'hardware_byserial') {
                            [string]::IsNullOrEmpty($uri.Query)
                        } else {
                            $false
                        }
                        if (-not $queryValid -and $route -ne 'unexpected') {
                            $route = 'unexpected'
                        }
                        $requestStage = 'request_auth'
                        $authorized = [string]::Equals(
                            $context.Request.Headers['Authorization'],
                            $state.ExpectedAuthorization,
                            [StringComparison]::Ordinal
                        )
                        $isMutation = $method -ne 'GET'
                        $accepted = $authorized -and $route -ne 'unexpected' -and $queryValid -and -not $isMutation
                        $statusCode = if (-not $authorized) {
                            401
                        } elseif ($isMutation) {
                            405
                        } elseif ($route -eq 'hardware_byserial' -and $queryValid) {
                            404
                        } elseif ($route -in @('manufacturers', 'models') -and $queryValid) {
                            200
                        } else {
                            404
                        }
                        $requestStage = 'request_evidence'
                        if ($workerRequests.Count -lt $maxRecordedRequests) {
                            $workerRequests.Add([pscustomobject]@{
                                route = $route
                                method_class = if ($isMutation) { 'mutation' } else { 'read' }
                                response_class = if ($statusCode -eq 404 -and $route -eq 'hardware_byserial') { 'not_found' } elseif ($statusCode -eq 200) { 'rows_empty' } else { 'rejected' }
                                query_valid = [bool]$queryValid
                                authorized = [bool]$authorized
                                accepted = [bool]$accepted
                            })
                            $state.Requests = @($workerRequests)
                        } else {
                            $state.DroppedRequests++
                        }
                        $requestStage = 'request_response'
                        $body = if ($statusCode -eq 200) {
                            [ordered]@{ rows = @() } | ConvertTo-Json -Compress
                        } elseif ($route -eq 'hardware_byserial' -and $queryValid) {
                            '{"message":"not found"}'
                        } elseif ($isMutation) {
                            '{"message":"mutation rejected"}'
                        } else {
                            '{"message":"unexpected route"}'
                        }
                        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                        $context.Response.StatusCode = $statusCode
                        $context.Response.ContentType = 'application/json'
                        $context.Response.ContentLength64 = $bytes.Length
                        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                    } finally {
                        $context.Response.Close()
                    }
                } catch {
                    if (-not $state.StopRequested) {
                        $state.WorkerError = 'loopback fixture request worker failed at ' + $requestStage
                        break
                    }
                }
            }
        } catch {
            $state.WorkerError = 'loopback fixture worker failed'
        } finally {
            $state.Ready = $false
            if ($null -ne $listener) { $listener.Close() }
        }
    }).AddArgument($state).AddArgument($MaxRecordedRequests).AddArgument($MaxBindAttempts)
    $async = $worker.BeginInvoke()

    $fixture = [pscustomobject]@{
        State = $state
        Worker = $worker
        Async = $async
    }
    $fixture | Add-Member -MemberType ScriptProperty -Name Prefix -Value { $this.State.Prefix }
    $fixture | Add-Member -MemberType ScriptProperty -Name Port -Value {
        if ($null -eq $this.State.Prefix) { return 0 }
        return ([Uri]$this.State.Prefix).Port
    }
    $fixture | Add-Member -MemberType ScriptProperty -Name Listener -Value { $this.State.Listener }
    return $fixture
}

function Get-SnipeItLoopbackEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Fixture
    )

    [pscustomobject]@{
        Requests = @($Fixture.State.Requests | ForEach-Object {
            [pscustomobject]@{
                route = $_.route
                method_class = $_.method_class
                response_class = $_.response_class
                query_valid = [bool]$_.query_valid
                authorized = [bool]$_.authorized
                accepted = [bool]$_.accepted
            }
        })
        DroppedRequests = [int]$Fixture.State.DroppedRequests
        WorkerError = $Fixture.State.WorkerError
    }
}

function Stop-SnipeItLoopbackFixture {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Fixture,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds = 30
    )

    $failures = @()
    $Fixture.State.StopRequested = $true
    try {
        if ($PSCmdlet.ShouldProcess('loopback fixture', 'stop loopback fixture')) {
            if ($null -ne $Fixture.State.Listener -and $Fixture.State.Listener.IsListening) { $Fixture.State.Listener.Stop() }
        } else {
            $failures += 'listener stop was declined'
        }
    } catch { $failures += 'listener stop failed' }
    try {
        if (-not $Fixture.Async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
            $failures += 'loopback worker did not stop within the bounded timeout'
        } else {
            [void]$Fixture.Worker.EndInvoke($Fixture.Async)
        }
    } catch {
        $failures += 'loopback worker shutdown failed'
    }
    try { $Fixture.Worker.Dispose() } catch { $failures += 'loopback worker disposal failed' }
    try {
        if ($null -ne $Fixture.State.Listener) { $Fixture.State.Listener.Close() }
    } catch { $failures += 'listener disposal failed' }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
}

Export-ModuleMember -Function Start-SnipeItLoopbackFixture, Get-SnipeItLoopbackEvidence, Stop-SnipeItLoopbackFixture
