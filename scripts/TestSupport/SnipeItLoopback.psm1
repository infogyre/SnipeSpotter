# pattern: Imperative Shell

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MaxRecordedRequests = 128
$MaxBindAttempts = 8
$FixtureCertificateLifetimeDays = 2

# Creates the run-scoped TLS material: one CA plus one localhost leaf signed by
# it. Keys exist only as run-scoped temporary files removed on stop; nothing is
# written to disk or the certificate store beyond that lifetime.
function New-FixtureCertificateMaterial {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if (-not $PSCmdlet.ShouldProcess('fixture certificate material', 'generate run-scoped CA and leaf')) {
        throw 'fixture certificate generation was declined'
    }
    $caKeyPath = Join-Path ([IO.Path]::GetTempPath()) ("snipespotter-fixture-ca-" + [Guid]::NewGuid().ToString('N') + ".key")
    $leafKeyPath = Join-Path ([IO.Path]::GetTempPath()) ("snipespotter-fixture-leaf-" + [Guid]::NewGuid().ToString('N') + ".key")
    $caCertPath = Join-Path ([IO.Path]::GetTempPath()) ("snipespotter-fixture-ca-" + [Guid]::NewGuid().ToString('N') + ".cer")
    $leafCertPath = Join-Path ([IO.Path]::GetTempPath()) ("snipespotter-fixture-leaf-" + [Guid]::NewGuid().ToString('N') + ".cer")
    $leafPfxPath = Join-Path ([IO.Path]::GetTempPath()) ("snipespotter-fixture-leaf-" + [Guid]::NewGuid().ToString('N') + ".pfx")

    $paths = @($caKeyPath, $leafKeyPath, $caCertPath, $leafCertPath, $leafPfxPath)
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    $caSerialPath = [IO.Path]::ChangeExtension($caCertPath, '.srl')
    $leafCsrPath = "$leafKeyPath.csr"

    foreach ($path in @("$leafKeyPath.csr", $caSerialPath)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }

    $caDn = '/CN=SnipeSpotter Fixture CA ' + [Guid]::NewGuid().ToString('N')
    $caArgs = @('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', $caKeyPath,
        '-out', $caCertPath, '-days', "$FixtureCertificateLifetimeDays", '-subj', $caDn,
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign')
    $leafDn = '/CN=localhost'
    $leafCsrArgs = @('req', '-newkey', 'rsa:3072', '-nodes', '-keyout', $leafKeyPath,
        '-out', $leafCsrPath, '-subj', $leafDn,
        '-addext', 'subjectAltName=DNS:localhost')
    $leafSignArgs = @('x509', '-req', '-in', $leafCsrPath, '-CA', $caCertPath,
        '-CAkey', $caKeyPath, '-CAcreateserial', '-out', $leafCertPath,
        '-days', "$FixtureCertificateLifetimeDays", '-copy_extensions', 'copy')

    foreach ($arguments in @($caArgs, $leafCsrArgs, $leafSignArgs)) {
        $output = & openssl @arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Partial-generation failure: remove everything this call created
            # (including any outputs from earlier steps) before surfacing.
            foreach ($path in @($paths + @($leafCsrPath, $caSerialPath, "$leafKeyPath.pfxpass"))) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            }
            throw ("fixture certificate generation failed: " + ($output -join ' '))
        }
    }

    $pfxPasswordText = [Guid]::NewGuid().ToString('N')
    $pfxPasswordPath = "$leafKeyPath.pfxpass"
    Set-Content -LiteralPath $pfxPasswordPath -Value $pfxPasswordText -NoNewline -Encoding ASCII
    $pfxOutput = & openssl pkcs12 -export -out $leafPfxPath -inkey $leafKeyPath -in $leafCertPath -certfile $caCertPath -passout "file:$pfxPasswordPath" 2>&1
    Remove-Item -LiteralPath $pfxPasswordPath -Force
    if ($LASTEXITCODE -ne 0) {
        throw ("fixture PFX conversion failed: " + ($pfxOutput -join ' '))
    }
    # The X509Certificate2 constructor requires a plaintext password; run-scoped
    # random GUID guards ephemeral fixture-only material with no durable secret.
    $pfxPassword = $pfxPasswordText

    [pscustomobject]@{
        CaKeyPath = $caKeyPath
        LeafKeyPath = $leafKeyPath
        CaCertPath = $caCertPath
        LeafCertPath = $leafCertPath
        LeafPfxPath = $leafPfxPath
        Password = $pfxPassword
        Paths = @($paths) + @($leafCsrPath, $caSerialPath)
    }
}

function Remove-FixtureCertificateMaterial {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([pscustomobject]$Material)
    $failures = @()
    $candidatePaths = @()
    if ($null -ne $Material) {
        $candidatePaths = @($Material.Paths)
    }
    foreach ($path in $candidatePaths | Select-Object -Unique) {
        try {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        } catch { $failures += "removal failed for fixture material $path" }
    }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
}

# Waits until the fixture signals Ready or the bounded startup window elapses;
# on timeout removes the partial material and listeners before surfacing.
function Assert-FixtureReady {
    param(
        [hashtable]$State,
        [int]$TimeoutSeconds
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $State.Ready) {
        if ([DateTime]::UtcNow -gt $deadline) {
            $State.StopRequested = $true
            if ($null -ne $State.Listener) { try { $State.Listener.Stop() } catch { $State.WorkerError = 'listener stop during startup timeout failed' } }
            if ($null -ne $State.WorkerError) { throw $State.WorkerError }
            throw 'loopback TLS fixture did not become ready within the bounded window'
        }
        Start-Sleep -Milliseconds 100
    }
}

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
    if (-not $PSCmdlet.ShouldProcess('loopback TLS fixture', 'start loopback TLS fixture')) {
        throw 'loopback fixture start was declined'
    }

    $material = New-FixtureCertificateMaterial
    try {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $material.LeafPfxPath, $material.Password
        )
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
            Certificate = $certificate
            ChainExtra = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
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

            function Read-HttpRequestHead {
                param([IO.Stream]$Stream)
                $head = [Text.StringBuilder]::new()
                $buffer = [byte[]]::new(1)
                while (-not $head.ToString().EndsWith("`r`n`r`n")) {
                    $read = $Stream.Read($buffer, 0, 1)
                    if ($read -le 0) { return $null }
                    [void]$head.Append([Text.Encoding]::ASCII.GetString($buffer, 0, $read))
                    if ($head.Length -gt 32768) { return $null }
                }
                return $head.ToString()
            }

            $listener = $null
            $requestStage = 'not_started'
            $workerRequests = [Collections.Generic.List[object]]::new()
            try {
                for ($attempt = 1; $attempt -le $maxBindAttempts -and -not $state.StopRequested; $attempt++) {
                    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
                    $reservation.Start()
                    try {
                        $port = ([Net.IPEndPoint]$reservation.LocalEndpoint).Port
                    } finally {
                        $reservation.Stop()
                    }
                    if ($port -le 0) { throw 'loopback fixture did not receive an ephemeral port' }
                    try {
                        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port)
                        $listener.Start()
                        $state.Listener = $listener
                        $state.Prefix = 'https://localhost:' + $port + '/'
                        $state.BindAttempts = $attempt
                        break
                    } catch {
                        if ($null -ne $listener) { $listener.Stop(); $listener = $null }
                        if ($attempt -eq $maxBindAttempts) { throw 'loopback fixture could not bind a loopback listener' }
                    }
                }
                if ($null -eq $listener) {
                    throw 'loopback fixture listener was not listening'
                }
                $state.Ready = $true

                while (-not $state.StopRequested) {
                    $requestStage = 'accept'
                    if (-not $listener.Pending()) {
                        Start-Sleep -Milliseconds 50
                        continue
                    }
                    $tcpClient = $listener.AcceptTcpClient()
                    try {
                        $tcpClient.ReceiveTimeout = 5000
                        $tcpClient.SendTimeout = 5000
                        $stream = $tcpClient.GetStream()
                        $requestStage = 'tls_handshake'
                        $ssl = [Net.Security.SslStream]::new($stream, $false)
                        try {
                            # AuthenticateAsServer(certificate) presents the
                            # leaf; clients trusting the imported fixture CA
                            # build the chain through the LocalMachine Root.
                            $ssl.AuthenticateAsServer($state.Certificate)
                            $requestStage = 'request_metadata'
                            $head = Read-HttpRequestHead -Stream $ssl
                            if ($null -eq $head) { continue }
                            $requestLine = ($head -split "`r`n")[0]
                            $parts = $requestLine -split ' '
                            if ($parts.Count -lt 2) { continue }
                            $method = $parts[0]
                            $target = $parts[1]
                            $uri = [Uri]('https://localhost' + $target)
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
                            # Header names and the auth scheme are case-insensitive per RFC 9110;
                            # hyper serializes header names in lowercase.
                            $authorized = $false
                            foreach ($line in ($head -split "`r`n")) {
                                $colon = $line.IndexOf(':')
                                if ($colon -lt 1) { continue }
                                $name = $line.Substring(0, $colon).Trim()
                                if (-not $name.Equals('Authorization', [StringComparison]::OrdinalIgnoreCase)) { continue }
                                $value = $line.Substring($colon + 1).Trim()
                                if ($value.Equals($state.ExpectedAuthorization, [StringComparison]::OrdinalIgnoreCase)) {
                                    $authorized = $true
                                }
                            }
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
                            $responseHead = "HTTP/1.1 $statusCode Reason`r`nContent-Type: application/json`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                            $headBytes = [Text.Encoding]::ASCII.GetBytes($responseHead)
                            $ssl.Write($headBytes, 0, $headBytes.Length)
                            $ssl.Write($bytes, 0, $bytes.Length)
                            $ssl.Flush()
                        } finally {
                            try { $ssl.Dispose() } catch { $state.WorkerError = 'ssl stream disposal failed' }
                        }
                    } catch {
                        if (-not $state.StopRequested) {
                            $state.WorkerError = 'loopback TLS fixture request worker failed at ' + $requestStage
                            return
                        }
                    } finally {
                        try { $tcpClient.Dispose() } catch { $state.WorkerError = 'tcp client disposal failed' }
                    }
                }
            } catch {
                $state.WorkerError = 'loopback TLS fixture worker failed'
            } finally {
                $state.Ready = $false
                if ($null -ne $listener) { $listener.Stop() }
            }
        }).AddArgument($state).AddArgument($MaxRecordedRequests).AddArgument($MaxBindAttempts)
        $async = $worker.BeginInvoke()

        Assert-FixtureReady -State $state -TimeoutSeconds 30

        $fixture = [pscustomobject]@{
            State = $state
            Worker = $worker
            Async = $async
            Material = $material
        }
        $fixture | Add-Member -MemberType ScriptProperty -Name Prefix -Value { $this.State.Prefix }
        $fixture | Add-Member -MemberType ScriptProperty -Name Port -Value {
            if ($null -eq $this.State.Prefix) { return 0 }
            return ([Uri]$this.State.Prefix).Port
        }
        $fixture | Add-Member -MemberType ScriptProperty -Name Listener -Value { $this.State.Listener }
        return $fixture
    } catch {
        # Startup failure path: remove this run's key material before surfacing.
        try { Remove-FixtureCertificateMaterial -Material $material } catch { Write-Verbose 'startup material cleanup failed' }
        throw
    }
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
        if ($PSCmdlet.ShouldProcess('loopback TLS fixture', 'stop loopback TLS fixture')) {
            if ($null -ne $Fixture.State.Listener -and $Fixture.State.Listener.Server -and $Fixture.State.Listener.Server.IsBound) {
                $Fixture.State.Listener.Stop()
            } elseif ($null -ne $Fixture.State.Listener) {
                $Fixture.State.Listener.Stop()
            }
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
        if ($null -ne $Fixture.State.Listener) { $Fixture.State.Listener.Stop() }
    } catch { $failures += 'listener disposal failed' }
    try {
        Remove-FixtureCertificateMaterial -Material $Fixture.Material
    } catch { $failures += 'fixture certificate material removal failed' }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
}

Export-ModuleMember -Function Start-SnipeItLoopbackFixture, Get-SnipeItLoopbackEvidence, Stop-SnipeItLoopbackFixture
