# Copyright (c) 2026 Incursa LLC.
# Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

[CmdletBinding()]
param(
    [string] $CampaignId = "adaptive-receive-credit-same-connection-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))",

    [string] $OutputPath,

    [string] $FewPhaseId = 'adaptive-runtime.few-streams.baseline.v1',

    [string] $ManyPhaseId = 'adaptive-runtime.stream-wave.multiplex-burst.v1',

    [string] $RecoveryPhaseId = 'adaptive-runtime.balanced.recovery.planned.v1',

    [ValidateRange(1, 512)]
    [int] $FewStreamsPerConnection = 16,

    [ValidateRange(1, 512)]
    [int] $ManyStreamsPerConnection = 100,

    [ValidateRange(1, 1024 * 1024)]
    [int] $FewPayloadBytes = 65536,

    [ValidateRange(1, 1024 * 1024)]
    [int] $ManyPayloadBytes = 1024,

    [string] $ServerProjectPath,

    [string] $ServerBinaryPath,

    [switch] $NoBuild,

    [switch] $NoRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedServerProjectPath = if ([string]::IsNullOrWhiteSpace($ServerProjectPath)) {
    Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\IncursaRawQuicServer.csproj'
}
elseif ([System.IO.Path]::IsPathRooted($ServerProjectPath)) {
    [System.IO.Path]::GetFullPath($ServerProjectPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ServerProjectPath))
}
$resolvedServerBinaryPath = if ([string]::IsNullOrWhiteSpace($ServerBinaryPath)) {
    Join-Path $repoRoot 'eng\protocol-lab\servers\IncursaRawQuicServer\bin\Release\net10.0\IncursaRawQuicServer.dll'
}
elseif ([System.IO.Path]::IsPathRooted($ServerBinaryPath)) {
    [System.IO.Path]::GetFullPath($ServerBinaryPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $ServerBinaryPath))
}
$resolvedOutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $repoRoot ".artifacts\adaptive-runtime\$CampaignId\same-connection-phase-execution.json"
}
elseif ([System.IO.Path]::IsPathRooted($OutputPath)) {
    [System.IO.Path]::GetFullPath($OutputPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputPath))
}

if (Test-Path -LiteralPath $resolvedOutputPath) {
    throw "Append-only same-connection proof path already exists: $resolvedOutputPath"
}

if (-not [System.Net.Quic.QuicConnection]::IsSupported) {
    throw 'System.Net.Quic is not supported on this host; same-connection phase execution cannot run honestly.'
}

if (-not (Test-Path -LiteralPath $resolvedServerProjectPath -PathType Leaf)) {
    throw "Campaign host project was not found: $resolvedServerProjectPath"
}

if (-not $NoBuild) {
    $buildArguments = @('build', $resolvedServerProjectPath, '-c', 'Release')
    if ($NoRestore) {
        $buildArguments += '--no-restore'
    }

    & dotnet @buildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Same-connection campaign host build failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path -LiteralPath $resolvedServerBinaryPath -PathType Leaf)) {
    throw "Campaign host binary was not found: $resolvedServerBinaryPath"
}

Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class AdaptiveRuntimeAnyCertificateValidator
{
    public static bool AcceptAny(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
    {
        return true;
    }
}
"@
$certificateValidationDelegate = [System.Delegate]::CreateDelegate(
    [System.Net.Security.RemoteCertificateValidationCallback],
    [AdaptiveRuntimeAnyCertificateValidator].GetMethod('AcceptAny'))

function Invoke-ProbePhase {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Quic.QuicConnection] $Connection,

        [Parameter(Mandatory = $true)]
        [string] $PhaseId,

        [Parameter(Mandatory = $true)]
        [string] $PhaseLabel,

        [Parameter(Mandatory = $true)]
        [int] $PhaseOrder,

        [Parameter(Mandatory = $true)]
        [int] $StreamsPerConnection,

        [Parameter(Mandatory = $true)]
        [int] $PayloadBytes
    )

    $openedStreams = [System.Collections.Generic.List[object]]::new()
    for ($streamIndex = 1; $streamIndex -le $StreamsPerConnection; $streamIndex++) {
        $stream = $Connection.OpenOutboundStreamAsync([System.Net.Quic.QuicStreamType]::Bidirectional).GetAwaiter().GetResult()
        $seed = [System.Text.Encoding]::UTF8.GetBytes("$PhaseId/$streamIndex")
        $payload = New-Object byte[] $PayloadBytes
        for ($payloadIndex = 0; $payloadIndex -lt $payload.Length; $payloadIndex++) {
            $payload[$payloadIndex] = $seed[$payloadIndex % $seed.Length]
        }
        $null = $stream.WriteAsync($payload, 0, $payload.Length, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        $stream.CompleteWrites()
        [void] $openedStreams.Add([pscustomobject]@{
            Stream = $stream
            Payload = $payload
        })
    }

    $completedStreams = 0
    foreach ($entry in $openedStreams) {
        $buffer = New-Object byte[] $entry.Payload.Length
        $offset = 0
        while ($offset -lt $buffer.Length) {
            $bytesRead = $entry.Stream.ReadAsync(
                $buffer,
                $offset,
                $buffer.Length - $offset,
                [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($bytesRead -le 0) {
                break
            }

            $offset += $bytesRead
        }

        $null = $entry.Stream.DisposeAsync().GetAwaiter().GetResult()
        if ($offset -ne $entry.Payload.Length) {
            throw "Phase '$PhaseId' returned $offset bytes for one stream, expected $($entry.Payload.Length)."
        }

        $expectedHash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($entry.Payload))
        $actualHash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($buffer))
        if (-not [string]::Equals($expectedHash, $actualHash, [StringComparison]::Ordinal)) {
            throw "Phase '$PhaseId' returned an unexpected payload echo."
        }

        $completedStreams += 1
    }

    return ,([ordered]@{
        phaseId = $PhaseId
        phaseLabel = $PhaseLabel
        phaseOrder = $PhaseOrder
        connections = 1
        streamsPerConnection = $StreamsPerConnection
        payloadBytes = $PayloadBytes
        completedStreams = $completedStreams
        exactPayloadValidated = $true
    })
}

$outputDirectory = Split-Path -Parent $resolvedOutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$serverStdoutPath = Join-Path $outputDirectory 'same-connection-server.stdout.log'
$serverStderrPath = Join-Path $outputDirectory 'same-connection-server.stderr.log'

$previousDebugValue = [Environment]::GetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG', 'Process')
[Environment]::SetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG', '1', 'Process')
try {
    $startProcessParameters = @{
        FilePath = 'dotnet'
        ArgumentList = @("`"$resolvedServerBinaryPath`"")
        RedirectStandardOutput = $serverStdoutPath
        RedirectStandardError = $serverStderrPath
        PassThru = $true
    }
    if ([OperatingSystem]::IsWindows()) {
        $startProcessParameters['WindowStyle'] = 'Hidden'
    }
    $serverProcess = Start-Process @startProcessParameters
}
finally {
    [Environment]::SetEnvironmentVariable('PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG', $previousDebugValue, 'Process')
}

try {
    $endpoint = $null
    for ($index = 0; $index -lt 200; $index++) {
        Start-Sleep -Milliseconds 100
        if (Test-Path -LiteralPath $serverStdoutPath -PathType Leaf) {
            $endpointMatch = Select-String -Path $serverStdoutPath -Pattern '^QUIC_ENDPOINT=(.+)$' -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($null -ne $endpointMatch) {
                $endpoint = $endpointMatch.Matches[0].Groups[1].Value.Trim()
                break
            }
        }

        if ($serverProcess.HasExited) {
            $startupError = if (Test-Path -LiteralPath $serverStderrPath -PathType Leaf) {
                [string]::Join(' | ', (Get-Content -LiteralPath $serverStderrPath))
            }
            else {
                $null
            }
            throw "Same-connection campaign host exited before publishing QUIC_ENDPOINT (exitCode=$($serverProcess.ExitCode)): $startupError"
        }
    }

    if ([string]::IsNullOrWhiteSpace($endpoint)) {
        throw "Same-connection campaign host did not publish QUIC_ENDPOINT: $serverStdoutPath"
    }

    $endpointHost, $endpointPortText = $endpoint.Split(':', 2)
    $remoteEndPoint = [System.Net.IPEndPoint]::new(
        [System.Net.IPAddress]::Parse($endpointHost),
        [int] $endpointPortText)

    $clientAuthenticationOptions = [System.Net.Security.SslClientAuthenticationOptions]::new()
    $clientAuthenticationOptions.ApplicationProtocols = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]::new()
    $clientAuthenticationOptions.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::new('plab-raw-quic'))
    $clientAuthenticationOptions.TargetHost = $endpointHost
    $clientAuthenticationOptions.RemoteCertificateValidationCallback = $certificateValidationDelegate

    $clientConnectionOptions = [System.Net.Quic.QuicClientConnectionOptions]::new()
    $clientConnectionOptions.RemoteEndPoint = $remoteEndPoint
    $clientConnectionOptions.ClientAuthenticationOptions = $clientAuthenticationOptions
    $clientConnectionOptions.IdleTimeout = [TimeSpan]::FromSeconds(30)
    $clientConnectionOptions.HandshakeTimeout = [TimeSpan]::FromSeconds(10)
    $clientConnectionOptions.DefaultCloseErrorCode = 0
    $clientConnectionOptions.DefaultStreamErrorCode = 0

    $connection = [System.Net.Quic.QuicConnection]::ConnectAsync($clientConnectionOptions).GetAwaiter().GetResult()
    try {
        $phaseExecutions = [System.Collections.Generic.List[object]]::new()
        $localEndPointBefore = $connection.LocalEndPoint.ToString()
        $remoteEndPointBefore = $connection.RemoteEndPoint.ToString()

        $fewPhaseExecution = @(Invoke-ProbePhase `
                -Connection $connection `
                -PhaseId $FewPhaseId `
                -PhaseLabel 'Few-stream baseline on one real connection' `
                -PhaseOrder 1 `
                -StreamsPerConnection $FewStreamsPerConnection `
                -PayloadBytes $FewPayloadBytes)
        [void] $phaseExecutions.Add($fewPhaseExecution[-1])

        $manyPhaseExecution = @(Invoke-ProbePhase `
                -Connection $connection `
                -PhaseId $ManyPhaseId `
                -PhaseLabel 'Many-stream burst on the preserved connection' `
                -PhaseOrder 2 `
                -StreamsPerConnection $ManyStreamsPerConnection `
                -PayloadBytes $ManyPayloadBytes)
        [void] $phaseExecutions.Add($manyPhaseExecution[-1])

        $recoveryPhaseExecution = @(Invoke-ProbePhase `
                -Connection $connection `
                -PhaseId $RecoveryPhaseId `
                -PhaseLabel 'Few-stream recovery return on the preserved connection' `
                -PhaseOrder 3 `
                -StreamsPerConnection $FewStreamsPerConnection `
                -PayloadBytes $FewPayloadBytes)
        [void] $phaseExecutions.Add($recoveryPhaseExecution[-1])

        $localEndPointAfter = $connection.LocalEndPoint.ToString()
        $remoteEndPointAfter = $connection.RemoteEndPoint.ToString()

        Start-Sleep -Milliseconds 250
    }
    finally {
        try {
            $connection.CloseAsync(0, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        }
        catch {
        }
        try {
            $connection.DisposeAsync().GetAwaiter().GetResult()
        }
        catch {
        }
    }

    Start-Sleep -Milliseconds 250
}
finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}

$stderrLines = if (Test-Path -LiteralPath $serverStderrPath -PathType Leaf) {
    @(Get-Content -LiteralPath $serverStderrPath)
}
else {
    @()
}
$acceptedConnectionMatches = @($stderrLines | ForEach-Object {
    [regex]::Match($_, 'accepted connection #(\d+)')
} | Where-Object Success)
$acceptedConnectionIndices = @($acceptedConnectionMatches | ForEach-Object { [int] $_.Groups[1].Value })
$acceptedStreamCount = @($stderrLines | Where-Object {
    $_ -match 'accepted inbound stream #'
}).Count
$expectedStreamCount = (2 * $FewStreamsPerConnection) + $ManyStreamsPerConnection
$singleConnectionPreserved = $acceptedConnectionIndices.Count -eq 1 -and
    $acceptedConnectionIndices[0] -eq 1 -and
    $acceptedStreamCount -eq $expectedStreamCount -and
    $localEndPointBefore -eq $localEndPointAfter -and
    $remoteEndPointBefore -eq $remoteEndPointAfter

if (-not $singleConnectionPreserved) {
    throw "Same-connection executor did not preserve one real connection across phases. See $serverStderrPath."
}

$executionArtifact = [ordered]@{
    schemaVersion = 'adaptive-runtime-same-connection-phase-execution-v1'
    campaignId = $CampaignId
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('O')
    executionModel = 'single_real_connection'
    activePolicyAuthorized = $false
    onlineLearningAuthorized = $false
    protocolLabSubmissionAuthorized = $false
    executorScriptPath = $PSCommandPath
    executorScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    serverBinaryPath = $resolvedServerBinaryPath
    serverBinarySha256 = (Get-FileHash -LiteralPath $resolvedServerBinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    phaseExecutions = @($phaseExecutions)
    proof = [ordered]@{
        clientLocalEndPointBefore = $localEndPointBefore
        clientLocalEndPointAfter = $localEndPointAfter
        clientRemoteEndPointBefore = $remoteEndPointBefore
        clientRemoteEndPointAfter = $remoteEndPointAfter
        sameClientLocalEndPointPreserved = $localEndPointBefore -eq $localEndPointAfter
        sameClientRemoteEndPointPreserved = $remoteEndPointBefore -eq $remoteEndPointAfter
        serverAcceptedConnectionCount = $acceptedConnectionIndices.Count
        serverAcceptedConnectionIndices = @($acceptedConnectionIndices)
        serverAcceptedInboundStreamCount = $acceptedStreamCount
        expectedInboundStreamCount = $expectedStreamCount
        singleConnectionPreserved = $singleConnectionPreserved
        serverStdoutPath = $serverStdoutPath
        serverStderrPath = $serverStderrPath
    }
    notes = @(
        'This proof uses one real System.Net.Quic client connection against the repo-owned raw QUIC campaign host.',
        'The preserved local and remote endpoints plus the server accepted-connection log must all agree before the proof is retained.',
        'This artifact proves same-connection few-to-many-to-few execution only; it does not authorize active policy use or ProtocolLab publication.'
    )
}

$executionArtifactJson = $executionArtifact | ConvertTo-Json -Depth 20
$executionSchemaPath = Join-Path $repoRoot 'schemas\adaptive-runtime-same-connection-phase-execution-v1.schema.json'
if (-not ($executionArtifactJson | Test-Json -SchemaFile $executionSchemaPath)) {
    throw "Same-connection phase execution proof failed schema validation: $executionSchemaPath"
}

$executionArtifactJson | Set-Content -LiteralPath $resolvedOutputPath -Encoding utf8
Write-Host "Same-connection phase execution proof: $resolvedOutputPath"
