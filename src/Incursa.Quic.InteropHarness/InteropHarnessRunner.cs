// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic;
using Incursa.Quic.Http3;
using Incursa.Quic.Qlog;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessRunner
{
    private const int UnsupportedExitCode = 127;
    private const int StreamCopyBufferSize = 4096;
    private const int MaxHttp09RequestLineBytes = 4096;
    private const int QuicStreamBodyWriteChunkSize = 1024;
    // The upstream keyupdate cell expects a key update during the first MB transferred.
    private const long KeyUpdateTriggerBytes = 1_000_000;
    private const int HttpStatusOk = 200;
    private const string CongestionControllerExhaustedMessage = "The congestion controller cannot send another ordinary packet.";
    private const string FlowControlCreditExhaustedMessage = "Writes that wait for additional flow-control credit are not supported by this slice.";
    private static readonly TimeSpan InteropRequestWaitTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan KeyUpdateResponseReadTimeout = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan MulticonnectLossHandshakeBudget = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CongestionRetryDelay = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan CongestionRetryTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ConnectionMigrationSendCreditRetryTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ConnectionMigrationSendCreditAttemptTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ServerKnownPlanPostResponseLingerTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ServerZeroRttOpenPlanRequestGapTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan VersionNegotiationPostSendGracePeriod = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ServerOpenPlanPostResponseLingerTimeout = InteropRequestWaitTimeout;
    private static readonly uint VersionNegotiationProbeVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);

    private sealed record SequentialTransferPlan(
        Uri RequestUri,
        IPEndPoint RemoteEndPoint,
        string RelativePath,
        string SourcePath,
        string DestinationPath);

    internal sealed record ServerTransferDispatchPlan(
        IPEndPoint ListenEndPoint,
        int ExpectedRequestCount,
        int ConfiguredRequestCount);

    internal sealed record ServerMulticonnectDispatchPlan(
        IPEndPoint ListenEndPoint,
        int ExpectedConnectionCount,
        int ConfiguredConnectionCount);

    private sealed record SequentialTransferPlanBuildResult(
        bool Success,
        IReadOnlyList<SequentialTransferPlan>? TransferPlans,
        string? ErrorMessage);

    internal sealed record ServerTransferDispatchPlanBuildResult(
        bool Success,
        ServerTransferDispatchPlan? Plan,
        string? ErrorMessage);

    internal sealed record ServerResumptionDispatchCounts(
        int FirstConnectionExpectedRequestCount,
        int ResumedConnectionExpectedRequestCount,
        int ConfiguredRequestCount);

    internal sealed record ServerMulticonnectDispatchPlanBuildResult(
        bool Success,
        ServerMulticonnectDispatchPlan? Plan,
        string? ErrorMessage);

    private static InteropHarnessPreflightPlanner CreatePlanner(InteropHarnessEnvironment settings, TextWriter stdout)
    {
        return new InteropHarnessPreflightPlanner(settings, stdout);
    }

    internal static void ApplyMulticonnectLossTimingOptions(QuicClientConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.HandshakeTimeout = MulticonnectLossHandshakeBudget;
        options.IdleTimeout = MulticonnectLossHandshakeBudget;
    }

    internal static int Run(System.Collections.IDictionary environment, TextWriter stdout, TextWriter stderr)
    {
        return Run(environment, stdout, stderr, InteropHarnessEnvironment.CertificatePath, InteropHarnessEnvironment.PrivateKeyPath);
    }

    internal static int Run(
        System.Collections.IDictionary environment,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        if (!InteropHarnessEnvironment.TryCreate(environment, out InteropHarnessEnvironment? settingsCandidate, out string? errorMessage) ||
            settingsCandidate is null)
        {
            stderr.WriteLine(errorMessage);
            return 1;
        }

        InteropHarnessEnvironment settings = settingsCandidate;
        return settings.Role switch
        {
            InteropHarnessRole.Client => RunClient(settings, stdout, stderr),
            InteropHarnessRole.Server => RunServer(settings, stdout, stderr, certificatePath, privateKeyPath),
            _ => 1,
        };
    }

    private static int RunClient(InteropHarnessEnvironment settings, TextWriter stdout, TextWriter stderr)
    {
        if (IsSupportedHarnessTestCase(settings))
        {
            WriteSslKeyLogExportEnabled(stdout, settings);
        }

        return settings.TestCase switch
        {
            "handshake" => RunHandshakeClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "versionnegotiation" => RunVersionNegotiationClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "retry" => RunRetryClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "multiconnect" => RunMulticonnectClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "v2" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "chacha20" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "handshakecorruption" => RunHandshakeClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "transfercorruption" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "rebind-port" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "rebind-addr" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "connectionmigration" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "http3" => RunHttp3ClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "keyupdate" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "resumption" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "transfer" => RunTransferClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            _ => ReturnUnsupported(settings, stdout, "client"),
        };
    }

    private static int RunServer(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        if (IsSupportedHarnessTestCase(settings))
        {
            WriteSslKeyLogExportEnabled(stdout, settings);
        }

        return settings.TestCase switch
        {
            "handshake" => RunHandshakeServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "versionnegotiation" => RunVersionNegotiationServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "retry" => RunRetryServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "multiconnect" => RunMulticonnectServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "v2" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "chacha20" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "handshakecorruption" => RunHandshakeServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "transfercorruption" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "rebind-port" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "rebind-addr" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "connectionmigration" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "http3" => RunHttp3ServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "keyupdate" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "resumption" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "transfer" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "zerortt" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            _ => ReturnUnsupported(settings, stdout, "server"),
        };
    }

    private static async Task<int> RunHandshakeClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                WriteLineAndFlush(stderr, transferPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            SequentialTransferPlan firstPlan = transferPlans[0];
            IPEndPoint remoteEndPoint = firstPlan.RemoteEndPoint;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={settings.TestCase}, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, firstPlan.RequestUri.Host);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            WriteDeterministicClientKeySelection(settings, stdout);
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(settings, qlogScope, clientOptions).ConfigureAwait(false);

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={settings.TestCase}, requestCount={settings.Requests.Count} completed managed client bootstrap.");

            for (int index = 0; index < transferPlans.Count; index++)
            {
                SequentialTransferPlan transferPlan = transferPlans[index];
                long bytesDownloaded = await DownloadHttp09ResponseAsync(
                    connection,
                    transferPlan,
                    stdout,
                    settings.TestCase,
                    settings.Requests.Count,
                    index,
                    transferPlans.Count,
                    InteropRequestWaitTimeout).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={settings.TestCase}, requestCount={settings.Requests.Count} completed managed {settings.TestCase} download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, stream {index + 1}/{transferPlans.Count}.");
            }

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", settings.TestCase, ex);
            return 1;
        }
    }

    private static async Task<int> RunVersionNegotiationClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(requestUri);
            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=versionnegotiation, requestCount={settings.Requests.Count} connecting to {remoteEndPoint} with reserved version 0x{VersionNegotiationProbeVersion:X8}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);
            clientOptions.HandshakeTimeout = InteropRequestWaitTimeout;

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }

            WriteDeterministicClientKeySelection(settings, stdout);

            QuicConnection? connection = null;
            try
            {
                connection = await ConnectWithQlogCaptureAsync(
                    settings,
                    qlogScope,
                    clientOptions,
                    supportedVersions: [VersionNegotiationProbeVersion]).ConfigureAwait(false);

                WriteLineAndFlush(
                    stderr,
                    $"interop harness: role=client, testcase=versionnegotiation unexpectedly established a supported connection while using reserved version 0x{VersionNegotiationProbeVersion:X8}.");
                return 1;
            }
            catch (QuicException ex) when (ex.QuicError == QuicError.VersionNegotiationError)
            {
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase=versionnegotiation, requestCount={settings.Requests.Count} observed version negotiation using reserved version 0x{VersionNegotiationProbeVersion:X8} and aborted the connection attempt.");
                return 0;
            }
            finally
            {
                if (connection is not null)
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", "versionnegotiation", ex);
            return 1;
        }
    }

    private static async Task<int> RunPostHandshakeStreamClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(requestUri);
            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=post-handshake-stream, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            WriteDeterministicClientKeySelection(settings, stdout);
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(settings, qlogScope, clientOptions).ConfigureAwait(false);
            QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).ConfigureAwait(false);

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=post-handshake-stream, requestCount={settings.Requests.Count} opened stream {stream.Id}.");
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", "post-handshake-stream", ex);
            return 1;
        }
    }

    private static async Task<int> RunHandshakeServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? tlsErrorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out string? certificateErrorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, certificateErrorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                    ListenBacklog = 1,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(settings, qlogScope, listenerOptions).ConfigureAwait(false);
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase={settings.TestCase}, requestCount={settings.Requests.Count} listening on {listenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase={settings.TestCase}, requestCount={settings.Requests.Count} completed managed listener bootstrap.");

                int servedRequestCount = await ServeHttp09RequestsAsync(
                    connection,
                    stdout,
                    settings.TestCase,
                    expectedRequestCount: settings.Requests.Count,
                    configuredRequestCount: settings.Requests.Count).ConfigureAwait(false);

                if (servedRequestCount == 0)
                {
                    WriteLineAndFlush(stderr, $"interop harness: role=server, testcase={settings.TestCase} did not observe an HTTP/0.9 request stream.");
                    return 1;
                }

                if (settings.Requests.Count > 0)
                {
                    await LingerForPeerCloseAfterFinalResponseAsync(
                        connection,
                        stdout,
                        settings.TestCase,
                        settings.Requests.Count,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                }

                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", settings.TestCase, ex);
            return 1;
        }
    }

    private static async Task<int> RunVersionNegotiationServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? tlsErrorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out string? certificateErrorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, certificateErrorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                    ListenBacklog = 1,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                };

                VersionNegotiationSentObserver versionNegotiationObserver = new();
                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }

                await using QuicListener listener = await ListenWithQlogCaptureAsync(
                    settings,
                    qlogScope,
                    listenerOptions,
                    diagnosticsSinkFactory: () => versionNegotiationObserver).ConfigureAwait(false);
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=versionnegotiation, requestCount={settings.Requests.Count} listening on {listenEndPoint}.");
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=versionnegotiation, requestCount={settings.Requests.Count} waiting for reserved client version 0x{VersionNegotiationProbeVersion:X8}.");

                if (!await WaitForVersionNegotiationSentAsync(versionNegotiationObserver, InteropRequestWaitTimeout).ConfigureAwait(false))
                {
                    WriteLineAndFlush(
                        stderr,
                        $"interop harness: role=server, testcase=versionnegotiation did not observe the reserved-version Version Negotiation response within {InteropRequestWaitTimeout}.");
                    return 1;
                }

                // Keep the server alive briefly so the client's reserved-version Initial lands in the trace before compose aborts.
                await Task.Delay(VersionNegotiationPostSendGracePeriod).ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=versionnegotiation, requestCount={settings.Requests.Count} completed managed listener bootstrap after sending version negotiation.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", "versionnegotiation", ex);
            return 1;
        }
    }

    private static async Task<int> RunPostHandshakeStreamServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? tlsErrorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out string? certificateErrorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, certificateErrorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                    ListenBacklog = 1,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(settings, qlogScope, listenerOptions).ConfigureAwait(false);
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=post-handshake-stream, requestCount={settings.Requests.Count} listening on {listenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                QuicStream stream = await connection.AcceptInboundStreamAsync().ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=post-handshake-stream, requestCount={settings.Requests.Count} accepted stream {stream.Id}.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", "post-handshake-stream", ex);
            return 1;
        }
    }

    private static async Task<int> RunRetryClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                WriteLineAndFlush(stderr, transferPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            SequentialTransferPlan firstPlan = transferPlans[0];
            IPEndPoint remoteEndPoint = firstPlan.RemoteEndPoint;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, firstPlan.RequestUri.Host);
            QuicClientConnectionSettings clientSettings = QuicClientConnectionOptionsValidator.Capture(
                clientOptions,
                nameof(clientOptions),
                localHandshakePrivateKey: settings.LocalHandshakePrivateKey);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }

            WriteDeterministicClientKeySelection(settings, stdout);
            Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = qlogScope?.Capture.CreateClientDiagnosticsSinkFactory();
            await using QuicClientConnectionHost host = new(clientSettings, diagnosticsSinkFactory);
            Task<QuicConnection> connectTask = host.ConnectAsync().AsTask();
            bool retryObserved = false;
            bool replayDatagramSent = false;
            bool replayPacketValidated = false;
            bool replayPacketValidationFailed = false;

            while (!connectTask.IsCompleted)
            {
                if (!retryObserved
                    && host.TransitionHistory.Any(transition => transition.EventKind == QuicConnectionEventKind.RetryReceived))
                {
                    retryObserved = true;
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} observed exactly one Retry transition (token={host.RetryTokenFromRetryHex}) and is waiting for managed client bootstrap completion.");
                }

                int replayPacketValidationFailureCode = host.RetryBootstrapReplayPacketValidationFailureCode;
                if (!replayPacketValidationFailed
                    && !replayPacketValidated
                    && replayPacketValidationFailureCode != 0)
                {
                    replayPacketValidationFailed = true;
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} replay packet validation failed with code {replayPacketValidationFailureCode}.");
                }

                if (!replayDatagramSent && host.RetryBootstrapReplayDatagramSent)
                {
                    replayDatagramSent = true;
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} reissued the next Initial after Retry and is waiting for managed client bootstrap completion.");
                }

                if (!replayPacketValidated && host.RetryBootstrapReplayPacketValidated)
                {
                    replayPacketValidated = true;
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} validated the replayed Initial packet (retryToken={host.RetryTokenFromRetryHex}, replayToken={host.RetryBootstrapReplayPacketTokenHex}) and is waiting for managed client bootstrap completion.");
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} observed exactly one Retry transition and completed managed client bootstrap.");
                }

                await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
            }

            await using QuicConnection connection = await connectTask.ConfigureAwait(false);

            int retryTransitionCount = host.TransitionHistory.Count(transition => transition.EventKind == QuicConnectionEventKind.RetryReceived);
            if (retryTransitionCount != 1)
            {
                WriteLineAndFlush(
                    stderr,
                    $"interop harness: role=client, testcase=retry expected exactly one Retry transition but observed {retryTransitionCount}.");
                return 1;
            }

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} observed exactly one Retry transition and completed managed client bootstrap.");

            for (int index = 0; index < transferPlans.Count; index++)
            {
                SequentialTransferPlan transferPlan = transferPlans[index];
                long bytesDownloaded = await DownloadHttp09ResponseAsync(
                    connection,
                    transferPlan,
                    stdout,
                    settings.TestCase,
                    settings.Requests.Count,
                    index,
                    transferPlans.Count,
                    responseReadTimeout: InteropRequestWaitTimeout,
                    sendCreditRetryTimeout: InteropRequestWaitTimeout).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} completed managed retry download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, stream {index + 1}/{transferPlans.Count}.");
            }

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", "retry", ex);
            return 1;
        }
    }

    private static async Task<int> RunRetryServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? tlsErrorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out tlsErrorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }

                Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = qlogScope?.Capture.CreateServerDiagnosticsSinkFactory();
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerHost listenerHost = new(
                    listenEndPoint,
                    [InteropHarnessProtocols.QuicInterop],
                    (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                    listenBacklog: 1,
                    retryBootstrapEnabled: true,
                    diagnosticsSinkFactory: diagnosticsSinkFactory);

                await using (listenerHost)
                {
                    _ = listenerHost.RunAsync();
                    Task<QuicConnection> acceptTask = listenerHost.AcceptConnectionAsync().AsTask();
                    await Task.Yield();
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} listening on {listenEndPoint}, retry contract enabled.");

                    bool retryEmitted = false;
                    bool retryReplayValidated = false;
                    bool retryReplayAdmitted = false;
                    bool retryReplayValidationFailed = false;
                    while (!acceptTask.IsCompleted)
                    {
                        if (!retryEmitted && listenerHost.RetryBootstrapIssued)
                        {
                            retryEmitted = true;
                            WriteLineAndFlush(
                                stdout,
                                $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} issued exactly one Retry (token={listenerHost.RetryBootstrapTokenHex}) and is waiting for managed listener bootstrap completion.");
                        }

                        int retryReplayValidationFailureCode = listenerHost.RetryBootstrapReplayValidationFailureCode;
                        if (!retryReplayValidationFailed
                            && !retryReplayValidated
                            && retryReplayValidationFailureCode != 0)
                        {
                            retryReplayValidationFailed = true;
                            WriteLineAndFlush(
                                stdout,
                                $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} replay validation failed with code {retryReplayValidationFailureCode} (issuedToken={listenerHost.RetryBootstrapTokenHex}, replayToken={listenerHost.RetryBootstrapReplayTokenHex}).");
                        }

                        if (!retryReplayValidated && listenerHost.RetryBootstrapReplayValidated)
                        {
                            retryReplayValidated = true;
                            WriteLineAndFlush(
                                stdout,
                                $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} validated the replayed Initial and is waiting for managed listener bootstrap completion.");
                        }

                        if (!retryReplayAdmitted && listenerHost.RetryBootstrapReplayAdmitted)
                        {
                            retryReplayAdmitted = true;
                            WriteLineAndFlush(
                                stdout,
                                $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} admitted the replayed Initial and is waiting for managed listener bootstrap completion.");
                        }

                        await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
                    }

                    await using QuicConnection connection = await acceptTask.ConfigureAwait(false);

                    if (!listenerHost.RetryBootstrapIssued)
                    {
                        WriteLineAndFlush(stderr, "interop harness: role=server, testcase=retry expected a Retry emission but none was observed.");
                        return 1;
                    }

                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase=retry, requestCount={settings.Requests.Count} issued exactly one Retry and completed managed listener bootstrap.");

                    int expectedRetryRequestCount = settings.Requests.Count > 0 ? settings.Requests.Count : 1;
                    int servedRequestCount = await ServeHttp09RequestsAsync(
                        connection,
                        stdout,
                        "retry",
                        expectedRequestCount: expectedRetryRequestCount,
                        configuredRequestCount: settings.Requests.Count).ConfigureAwait(false);

                    if (servedRequestCount == 0)
                    {
                        WriteLineAndFlush(stderr, "interop harness: role=server, testcase=retry did not observe an HTTP/0.9 request stream.");
                        return 1;
                    }

                    if (settings.Requests.Count > 0)
                    {
                        await LingerForPeerCloseAfterFinalResponseAsync(
                            connection,
                            stdout,
                            "retry",
                            settings.Requests.Count,
                            ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                    }

                    return 0;
                }
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", "retry", ex);
            return 1;
        }
    }

    private static Task<int> RunMulticonnectClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        return RunMulticonnectClientAsync(settings, stdout, stderr, InteropRequestWaitTimeout);
    }

    internal static async Task<int> RunMulticonnectClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        TimeSpan responseReadTimeout)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                WriteLineAndFlush(stderr, transferPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }

            for (int index = 0; index < transferPlans.Count; index++)
            {
                SequentialTransferPlan transferPlan = transferPlans[index];
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase=multiconnect, requestCount={settings.Requests.Count} connecting to {transferPlan.RemoteEndPoint}, target={transferPlan.RelativePath}, connection {index + 1}/{transferPlans.Count}.");

                QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(
                    transferPlan.RemoteEndPoint,
                    transferPlan.RequestUri.Host);
                ApplyMulticonnectLossTimingOptions(clientOptions);
                WriteDeterministicClientKeySelection(settings, stdout);
                await using QuicConnection connection = await ConnectWithQlogCaptureAsync(settings, qlogScope, clientOptions).ConfigureAwait(false);
                long bytesDownloaded = await DownloadHttp09ResponseAsync(
                    connection,
                    transferPlan,
                    stdout,
                    "multiconnect",
                    settings.Requests.Count,
                    index,
                    transferPlans.Count,
                    responseReadTimeout,
                    waitForPeerFinAfterExpectedBody: true).ConfigureAwait(false);
                await connection.CloseAsync(0).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase=multiconnect, requestCount={settings.Requests.Count} completed managed multiconnect download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, connection {index + 1}/{transferPlans.Count}.");

                if (index + 1 < transferPlans.Count)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
                }
            }

            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stdout, "client", "multiconnect", ex);
            return 1;
        }
    }

    private static async Task<int> RunTransferClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                WriteLineAndFlush(stderr, transferPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            SequentialTransferPlan firstPlan = transferPlans[0];
            IPEndPoint remoteEndPoint = firstPlan.RemoteEndPoint;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={settings.TestCase}, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}, targetCount={transferPlans.Count}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, firstPlan.RequestUri.Host);
            uint[]? supportedVersions = GetSupportedVersionsForTransferCase(settings);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            WriteDeterministicClientKeySelection(settings, stdout);
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(
                settings,
                qlogScope,
                clientOptions,
                supportedVersions: supportedVersions).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={settings.TestCase}, requestCount={settings.Requests.Count} completed managed client bootstrap.");
            string testCase = settings.TestCase;
            if (testCase == "resumption")
            {
                const int ResumptionConnectionCount = 2;

                if (transferPlans.Count < ResumptionConnectionCount)
                {
                    throw new InvalidOperationException($"interop harness: role=client, testcase=resumption requires at least {ResumptionConnectionCount} REQUESTS URLs.");
                }

                SequentialTransferPlan firstResumptionPlan = transferPlans[0];
                SequentialTransferPlan[] resumedTransferPlans = [.. transferPlans.Skip(1)];

                long firstBytesDownloaded = await DownloadHttp09ResponseAsync(
                    connection,
                    firstResumptionPlan,
                    stdout,
                    testCase,
                    settings.Requests.Count,
                    0,
                    1,
                    responseReadTimeout: InteropRequestWaitTimeout,
                    sendCreditRetryTimeout: InteropRequestWaitTimeout).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} completed managed resumption download to {firstResumptionPlan.DestinationPath} from {firstResumptionPlan.RequestUri.PathAndQuery}, bytes={firstBytesDownloaded}, connection 1/{ResumptionConnectionCount}.");

                long detachedSnapshotWaitStartedAt = Stopwatch.GetTimestamp();
                TimeSpan detachedSnapshotTimeout = TimeSpan.FromSeconds(60);
                QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null;
                while (!connection.TryExportDetachedResumptionTicketSnapshot(out detachedResumptionTicketSnapshot)
                    || detachedResumptionTicketSnapshot is null)
                {
                    if (Stopwatch.GetElapsedTime(detachedSnapshotWaitStartedAt) >= detachedSnapshotTimeout)
                    {
                        throw new InvalidOperationException("interop harness: role=client, testcase=resumption did not receive a detached resumption ticket snapshot in time.");
                    }

                    await Task.Delay(CongestionRetryDelay).ConfigureAwait(false);
                }

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} captured detached resumption ticket after connection 1/{ResumptionConnectionCount}.");

                if (!detachedResumptionTicketSnapshot.HasResumptionCredentialMaterial)
                {
                    throw new InvalidOperationException("interop harness: role=client, testcase=resumption captured an incomplete detached resumption ticket snapshot.");
                }

                await connection.CloseAsync(0).ConfigureAwait(false);

                QuicClientConnectionOptions resumedClientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, resumedTransferPlans[0].RequestUri.Host);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}, target={resumedTransferPlans[0].RelativePath}, resumed connection {ResumptionConnectionCount}/{ResumptionConnectionCount}.");
                await using QuicConnection resumedConnection = await ConnectWithQlogCaptureAsync(
                    settings,
                    qlogScope,
                    resumedClientOptions,
                    detachedResumptionTicketSnapshot).ConfigureAwait(false);

                if (resumedConnection.ResumptionAttemptDisposition != QuicTlsResumptionAttemptDisposition.Accepted)
                {
                    throw new InvalidOperationException($"interop harness: role=client, testcase=resumption failed to negotiate a resumed connection; disposition={resumedConnection.ResumptionAttemptDisposition}.");
                }

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} established resumed connection 2/2 with disposition={resumedConnection.ResumptionAttemptDisposition}.");

                for (int index = 0; index < resumedTransferPlans.Length; index++)
                {
                    SequentialTransferPlan transferPlan = resumedTransferPlans[index];
                    long bytesDownloaded = await DownloadHttp09ResponseAsync(
                        resumedConnection,
                        transferPlan,
                        stdout,
                        testCase,
                        settings.Requests.Count,
                        index,
                        resumedTransferPlans.Length,
                        responseReadTimeout: InteropRequestWaitTimeout,
                        sendCreditRetryTimeout: InteropRequestWaitTimeout).ConfigureAwait(false);

                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} completed managed resumption download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, connection {ResumptionConnectionCount}/{ResumptionConnectionCount}.");
                }

                await resumedConnection.CloseAsync(0).ConfigureAwait(false);
                return 0;
            }

            bool keyUpdateInitiated = false;

            for (int index = 0; index < transferPlans.Count; index++)
            {
                SequentialTransferPlan transferPlan = transferPlans[index];
                long bytesDownloaded = await DownloadHttp09ResponseAsync(
                    connection,
                    transferPlan,
                    stdout,
                    settings.TestCase,
                    settings.Requests.Count,
                    index,
                    transferPlans.Count,
                    responseReadTimeout: testCase == "keyupdate" ? KeyUpdateResponseReadTimeout : InteropRequestWaitTimeout,
                    sendCreditRetryTimeout: InteropRequestWaitTimeout,
                    bytesDownloadedObserver: bytesDownloaded =>
                    {
                        if (testCase != "keyupdate" || keyUpdateInitiated || bytesDownloaded < KeyUpdateTriggerBytes)
                        {
                            return;
                        }

                        keyUpdateInitiated = true;
                        bool observedKeyUpdateBeforeTrigger = connection.HasObservedOneRttKeyUpdate;
                        if (!connection.TryInitiateOneRttKeyUpdate())
                        {
                            if (!observedKeyUpdateBeforeTrigger && !connection.HasObservedOneRttKeyUpdate)
                            {
                                throw new InvalidOperationException("interop harness: role=client, testcase=keyupdate failed to initiate or observe a one-RTT key update after transferring the first megabyte.");
                            }

                            WriteLineAndFlush(
                                stdout,
                                $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} observed one-RTT key update after {bytesDownloaded} bytes transferred.");

                            return;
                        }

                        WriteLineAndFlush(
                            stdout,
                            $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} initiated one-RTT key update after {bytesDownloaded} bytes transferred.");
                    }).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={settings.Requests.Count} completed managed {testCase} download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, stream {index + 1}/{transferPlans.Count}.");
            }

            if (testCase == "keyupdate" && !keyUpdateInitiated)
            {
                throw new InvalidOperationException("interop harness: role=client, testcase=keyupdate did not transfer enough bytes to initiate a one-RTT key update.");
            }

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", settings.TestCase, ex);
            return 1;
        }
    }

    private static uint[]? GetSupportedVersionsForTransferCase(InteropHarnessEnvironment settings)
    {
        return settings.TestCase == "v2"
            ? [QuicVersionNegotiation.Version2]
            : null;
    }

    private static async Task<int> RunHttp3ClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC HTTP/3 client bootstrap is not supported in this runtime.");
                return 1;
            }

            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                WriteLineAndFlush(stderr, transferPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            SequentialTransferPlan firstPlan = transferPlans[0];
            IPEndPoint remoteEndPoint = firstPlan.RemoteEndPoint;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=http3, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}, targetCount={transferPlans.Count}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedHttp3ClientOptions(remoteEndPoint, firstPlan.RequestUri.Host);
            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }

            WriteDeterministicClientKeySelection(settings, stdout);
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(settings, qlogScope, clientOptions).ConfigureAwait(false);
            await using Http3Client client = await Http3Client.AttachAsync(
                connection,
                new Http3ClientOptions
                {
                    UserAgent = "incursa-quic-interop-http3",
                    CompleteResponseOnContentLength = true,
                    DiagnosticsSink = CreateHttp3QlogDiagnosticsSink(qlogScope, isServer: false),
                }).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=http3, requestCount={settings.Requests.Count} completed managed HTTP/3 client bootstrap.");

            long totalBytesDownloaded = 0;
            for (int index = 0; index < transferPlans.Count; index++)
            {
                totalBytesDownloaded += await DownloadHttp3ResponseAsync(
                    client,
                    transferPlans[index],
                    stdout,
                    index,
                    transferPlans.Count).ConfigureAwait(false);
            }

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=http3, requestCount={settings.Requests.Count} completed managed HTTP/3 downloads, bytes={totalBytesDownloaded}, streamCount={transferPlans.Count}.");

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "client", settings.TestCase, ex);
            return 1;
        }
    }

    private static async Task<long> DownloadHttp3ResponseAsync(
        Http3Client client,
        SequentialTransferPlan transferPlan,
        TextWriter stdout,
        int requestIndex,
        int requestCount)
    {
        Http3Response response = await client.GetAsync(transferPlan.RequestUri).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusOk)
        {
            throw new InvalidOperationException($"HTTP/3 GET {transferPlan.RequestUri.PathAndQuery} returned status {response.StatusCode}.");
        }

        string? destinationDirectory = Path.GetDirectoryName(transferPlan.DestinationPath);
        if (!string.IsNullOrEmpty(destinationDirectory))
        {
            Directory.CreateDirectory(destinationDirectory);
        }

        await File.WriteAllBytesAsync(transferPlan.DestinationPath, response.Body).ConfigureAwait(false);
        WriteLineAndFlush(
            stdout,
            $"interop harness: role=client, testcase=http3 completed managed HTTP/3 download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={response.Body.Length}, stream {requestIndex + 1}/{requestCount}.");
        return response.Body.Length;
    }

    private static async Task<int> RunHttp3ServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC HTTP/3 listener bootstrap is not supported in this runtime.");
                return 1;
            }

            string? errorMessage;
            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out errorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out errorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            using (CancellationTokenSource completionSignal = new())
            {
                int expectedRequestCount = settings.Requests.Count;
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = new IPEndPoint(IPAddress.IPv6Any, 443),
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
                    ListenBacklog = Math.Max(1, expectedRequestCount),
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedHttp3ServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }

                await using QuicListener listener = await ListenWithQlogCaptureAsync(settings, qlogScope, listenerOptions).ConfigureAwait(false);
                InteropHttp3FileHandler handler = new(settings, stdout, expectedRequestCount, completionSignal);
                await using Http3Server server = Http3Server.Attach(
                    listener,
                    handler,
                    new Http3ServerOptions
                    {
                        DiagnosticsSink = CreateHttp3QlogDiagnosticsSink(qlogScope, isServer: true),
                    });
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=http3, requestCount={settings.Requests.Count} listening on {listenerOptions.ListenEndPoint}.");

                await server.ServeAsync(completionSignal.Token).ConfigureAwait(false);
                return 0;
            }
        }
        catch (OperationCanceledException) when (settings.Requests.Count > 0)
        {
            return 0;
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", settings.TestCase, ex);
            return 1;
        }
    }

    private static async Task<int> RunMulticonnectServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            ServerMulticonnectDispatchPlanBuildResult dispatchPlanResult = await TryCreateServerMulticonnectDispatchPlanAsync(settings, planner).ConfigureAwait(false);
            if (!dispatchPlanResult.Success)
            {
                WriteLineAndFlush(stderr, dispatchPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(dispatchPlanResult.Plan);
            ServerMulticonnectDispatchPlan dispatchPlan = dispatchPlanResult.Plan;

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out string? tlsErrorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, tlsErrorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out string? certificateErrorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, certificateErrorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = dispatchPlan.ListenEndPoint,
                    ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                    ListenBacklog = dispatchPlan.ExpectedConnectionCount,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(settings, qlogScope, listenerOptions).ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=multiconnect, requestCount={dispatchPlan.ConfiguredConnectionCount} listening on {dispatchPlan.ListenEndPoint}, connectionCount={dispatchPlan.ExpectedConnectionCount}.");

                int servedConnectionCount = 0;
                int remainingExpectedConnections = dispatchPlan.ExpectedConnectionCount > 0 ? dispatchPlan.ExpectedConnectionCount : int.MaxValue;
                while (servedConnectionCount < remainingExpectedConnections)
                {
                    QuicConnection connection;
                    using CancellationTokenSource acceptTimeout = new(InteropRequestWaitTimeout);
                    try
                    {
                        connection = await listener.AcceptConnectionAsync(acceptTimeout.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (dispatchPlan.ExpectedConnectionCount == 0 && servedConnectionCount > 0)
                    {
                        break;
                    }
                    catch (OperationCanceledException) when (dispatchPlan.ExpectedConnectionCount == 0)
                    {
                        WriteLineAndFlush(stderr, "interop harness: role=server, testcase=multiconnect did not observe a managed connection.");
                        return 1;
                    }

                    if (dispatchPlan.ExpectedConnectionCount == 0)
                    {
                        WriteLineAndFlush(
                            stdout,
                            $"interop harness: role=server, testcase=multiconnect, requestCount={dispatchPlan.ConfiguredConnectionCount} accepted managed connection {servedConnectionCount + 1}.");
                        int servedRequestCount = await ServeHttp09RequestsAsync(
                            connection,
                            stdout,
                            "multiconnect",
                            expectedRequestCount: 1,
                            configuredRequestCount: dispatchPlan.ConfiguredConnectionCount).ConfigureAwait(false);

                        if (servedRequestCount == 0)
                        {
                            WriteLineAndFlush(stderr, "interop harness: role=server, testcase=multiconnect did not observe an HTTP/0.9 request stream.");
                            return 1;
                        }

                        _ = DisposeConnectionAfterPostResponseLingerAsync(
                            connection,
                            stdout,
                            "multiconnect",
                            dispatchPlan.ConfiguredConnectionCount,
                            ServerOpenPlanPostResponseLingerTimeout);
                        servedConnectionCount++;
                        continue;
                    }

                    await using (connection.ConfigureAwait(false))
                    {
                        string connectionProgressLabel = $"{servedConnectionCount + 1}/{dispatchPlan.ExpectedConnectionCount}";
                        WriteLineAndFlush(
                            stdout,
                            $"interop harness: role=server, testcase=multiconnect, requestCount={dispatchPlan.ConfiguredConnectionCount} accepted managed connection {connectionProgressLabel}.");
                        int servedRequestCount = await ServeHttp09RequestsAsync(
                            connection,
                            stdout,
                            "multiconnect",
                            expectedRequestCount: 1,
                            configuredRequestCount: dispatchPlan.ConfiguredConnectionCount).ConfigureAwait(false);

                        if (servedRequestCount == 0)
                        {
                            WriteLineAndFlush(stderr, "interop harness: role=server, testcase=multiconnect did not observe an HTTP/0.9 request stream.");
                            return 1;
                        }

                        await LingerForPeerCloseAfterFinalResponseAsync(
                            connection,
                            stdout,
                            "multiconnect",
                            dispatchPlan.ConfiguredConnectionCount,
                            ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                        servedConnectionCount++;
                    }
                }

                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", "multiconnect", ex);
            return 1;
        }
    }

    internal static async Task<ServerMulticonnectDispatchPlanBuildResult> TryCreateServerMulticonnectDispatchPlanAsync(
        InteropHarnessEnvironment settings,
        InteropHarnessPreflightPlanner planner)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(planner);

        if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
        {
            return new ServerMulticonnectDispatchPlanBuildResult(false, null, errorMessage);
        }

        int expectedConnectionCount = 0;
        int configuredConnectionCount = settings.Requests.Count;
        if (settings.Requests.Count > 0)
        {
            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                return new ServerMulticonnectDispatchPlanBuildResult(false, null, transferPlanResult.ErrorMessage);
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            requestUri = transferPlans[0].RequestUri;
            expectedConnectionCount = transferPlans.Count;
            configuredConnectionCount = transferPlans.Count;
        }

        IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
        return new ServerMulticonnectDispatchPlanBuildResult(
            true,
            new ServerMulticonnectDispatchPlan(listenEndPoint, expectedConnectionCount, configuredConnectionCount),
            null);
    }

    private static async Task<int> RunTransferServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            InteropHarnessPreflightPlanner planner = CreatePlanner(settings, stdout);

            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            ServerTransferDispatchPlanBuildResult dispatchPlanResult = await TryCreateServerTransferDispatchPlanAsync(settings, planner).ConfigureAwait(false);
            if (!dispatchPlanResult.Success)
            {
                WriteLineAndFlush(stderr, dispatchPlanResult.ErrorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(dispatchPlanResult.Plan);
            ServerTransferDispatchPlan dispatchPlan = dispatchPlanResult.Plan;

            string? errorMessage;
            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out errorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out errorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = dispatchPlan.ListenEndPoint,
                    ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                    ListenBacklog = 1,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(planner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(settings, qlogScope, listenerOptions).ConfigureAwait(false);
                string testCase = settings.TestCase;
                if (testCase is "resumption" or "zerortt")
                {
                    const int ResumptionConnectionCount = 2;

                    if (!TryCreateServerResumptionDispatchCounts(
                        dispatchPlan,
                        testCase,
                        testCase == "zerortt" ? 0 : 1,
                        out ServerResumptionDispatchCounts? resumptionDispatchCounts,
                        out string? resumptionDispatchError) ||
                        resumptionDispatchCounts is null)
                    {
                        WriteLineAndFlush(stderr, resumptionDispatchError ?? string.Empty);
                        return 1;
                    }

                    ValueTask<QuicConnection> firstAcceptTask = listener.AcceptConnectionAsync();
                    await Task.Yield();
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={resumptionDispatchCounts.ConfiguredRequestCount} listening on {dispatchPlan.ListenEndPoint}, connectionCount={ResumptionConnectionCount}.");

                    await using QuicConnection firstConnection = await firstAcceptTask.ConfigureAwait(false);
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={resumptionDispatchCounts.ConfiguredRequestCount} accepted managed connection 1/{ResumptionConnectionCount}.");
                    int firstServedRequestCount = await ServeHttp09RequestsAsync(
                        firstConnection,
                        stdout,
                        testCase,
                        expectedRequestCount: resumptionDispatchCounts.FirstConnectionExpectedRequestCount,
                        configuredRequestCount: resumptionDispatchCounts.ConfiguredRequestCount).ConfigureAwait(false);

                    if (firstServedRequestCount == 0)
                    {
                        WriteLineAndFlush(stderr, $"interop harness: role=server, testcase={testCase} did not observe an HTTP/0.9 request stream on the first connection.");
                        return 1;
                    }

                    ValueTask<QuicConnection> resumedAcceptTask = listener.AcceptConnectionAsync();
                    await Task.Yield();

                    await LingerForPeerCloseAfterFinalResponseAsync(
                        firstConnection,
                        stdout,
                        testCase,
                        resumptionDispatchCounts.ConfiguredRequestCount,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);

                    await using QuicConnection resumedConnection = await resumedAcceptTask.ConfigureAwait(false);
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={resumptionDispatchCounts.ConfiguredRequestCount} accepted managed connection {ResumptionConnectionCount}/{ResumptionConnectionCount}.");
                    int resumedServedRequestCount = await ServeHttp09RequestsAsync(
                        resumedConnection,
                        stdout,
                        testCase,
                        expectedRequestCount: resumptionDispatchCounts.ResumedConnectionExpectedRequestCount,
                        configuredRequestCount: resumptionDispatchCounts.ConfiguredRequestCount,
                        requestWaitTimeout: GetServerRequestWaitTimeout(testCase, resumptionDispatchCounts.ConfiguredRequestCount)).ConfigureAwait(false);

                    if (resumedServedRequestCount == 0)
                    {
                        WriteLineAndFlush(stderr, $"interop harness: role=server, testcase={testCase} did not observe an HTTP/0.9 request stream on the resumed connection.");
                        return 1;
                    }

                    await LingerForPeerCloseAfterFinalResponseAsync(
                        resumedConnection,
                        stdout,
                        testCase,
                        resumptionDispatchCounts.ConfiguredRequestCount,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                    return 0;
                }

                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase={testCase}, requestCount={dispatchPlan.ConfiguredRequestCount} listening on {dispatchPlan.ListenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase={testCase}, requestCount={dispatchPlan.ConfiguredRequestCount} completed managed listener bootstrap.");
                int servedRequestCount = await ServeHttp09RequestsAsync(
                    connection,
                    stdout,
                    testCase,
                    expectedRequestCount: dispatchPlan.ExpectedRequestCount,
                    configuredRequestCount: dispatchPlan.ConfiguredRequestCount).ConfigureAwait(false);

                if (servedRequestCount == 0)
                {
                    WriteLineAndFlush(stderr, $"interop harness: role=server, testcase={testCase} did not observe an HTTP/0.9 request stream.");
                    return 1;
                }

                if (dispatchPlan.ExpectedRequestCount > 0)
                {
                    await LingerForPeerCloseAfterFinalResponseAsync(
                        connection,
                        stdout,
                        testCase,
                        dispatchPlan.ConfiguredRequestCount,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                }

                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteFailureDetails(stderr, "server", settings.TestCase, ex);
            return 1;
        }
    }

    internal static async Task<ServerTransferDispatchPlanBuildResult> TryCreateServerTransferDispatchPlanAsync(
        InteropHarnessEnvironment settings,
        InteropHarnessPreflightPlanner planner)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(planner);

        if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
        {
            return new ServerTransferDispatchPlanBuildResult(false, null, errorMessage);
        }

        int expectedRequestCount = 0;
        int configuredRequestCount = settings.Requests.Count;
        if (settings.Requests.Count > 0)
        {
            SequentialTransferPlanBuildResult transferPlanResult = await TryCreateSequentialTransferPlans(settings).ConfigureAwait(false);
            if (!transferPlanResult.Success)
            {
                return new ServerTransferDispatchPlanBuildResult(false, null, transferPlanResult.ErrorMessage);
            }

            ArgumentNullException.ThrowIfNull(transferPlanResult.TransferPlans);
            IReadOnlyList<SequentialTransferPlan> transferPlans = transferPlanResult.TransferPlans;
            requestUri = transferPlans[0].RequestUri;
            expectedRequestCount = transferPlans.Count;
            configuredRequestCount = transferPlans.Count;
        }

        IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
        return new ServerTransferDispatchPlanBuildResult(
            true,
            new ServerTransferDispatchPlan(listenEndPoint, expectedRequestCount, configuredRequestCount),
            null);
    }

    internal static bool TryCreateServerResumptionDispatchCounts(
        ServerTransferDispatchPlan dispatchPlan,
        out ServerResumptionDispatchCounts? counts,
        out string? errorMessage)
        => TryCreateServerResumptionDispatchCounts(
            dispatchPlan,
            "resumption",
            emptySecondConnectionExpectedRequestCount: 1,
            out counts,
            out errorMessage);

    internal static bool TryCreateServerResumptionDispatchCounts(
        ServerTransferDispatchPlan dispatchPlan,
        string testCase,
        int emptySecondConnectionExpectedRequestCount,
        out ServerResumptionDispatchCounts? counts,
        out string? errorMessage)
    {
        ArgumentNullException.ThrowIfNull(dispatchPlan);
        ArgumentException.ThrowIfNullOrWhiteSpace(testCase);

        const int ResumptionConnectionCount = 2;

        if (dispatchPlan.ConfiguredRequestCount == 0)
        {
            counts = new ServerResumptionDispatchCounts(
                FirstConnectionExpectedRequestCount: 1,
                ResumedConnectionExpectedRequestCount: emptySecondConnectionExpectedRequestCount,
                ConfiguredRequestCount: emptySecondConnectionExpectedRequestCount == 0 ? 0 : ResumptionConnectionCount);
            errorMessage = null;
            return true;
        }

        if (dispatchPlan.ConfiguredRequestCount < ResumptionConnectionCount)
        {
            counts = null;
            errorMessage = $"interop harness: role=server, testcase={testCase} requires at least {ResumptionConnectionCount} REQUESTS URLs when server REQUESTS is explicitly configured.";
            return false;
        }

        counts = new ServerResumptionDispatchCounts(
            FirstConnectionExpectedRequestCount: 1,
            ResumedConnectionExpectedRequestCount: dispatchPlan.ConfiguredRequestCount - 1,
            ConfiguredRequestCount: dispatchPlan.ConfiguredRequestCount);
        errorMessage = null;
        return true;
    }

    internal static TimeSpan GetServerRequestWaitTimeout(string testCase, int configuredRequestCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(testCase);

        return string.Equals(testCase, "zerortt", StringComparison.Ordinal)
            && configuredRequestCount == 0
            ? ServerZeroRttOpenPlanRequestGapTimeout
            : InteropRequestWaitTimeout;
    }

    private static async Task<SequentialTransferPlanBuildResult> TryCreateSequentialTransferPlans(
        InteropHarnessEnvironment settings)
    {
        if (settings.Requests.Count == 0)
        {
            return new SequentialTransferPlanBuildResult(false, null, "REQUESTS must contain at least one URL for testcase dispatch.");
        }

        List<SequentialTransferPlan> plans = [];
        string? expectedHost = null;
        int expectedPort = 0;

        foreach (string request in settings.Requests)
        {
            if (!Uri.TryCreate(request, UriKind.Absolute, out Uri? requestUri) || requestUri is null)
            {
                return new SequentialTransferPlanBuildResult(false, null, $"REQUESTS entry '{request}' is not a valid absolute URL.");
            }

            if (!string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return new SequentialTransferPlanBuildResult(false, null, $"REQUESTS entry '{request}' must use https for testcase dispatch.");
            }

            if (!InteropHarnessPreflightPlanner.TryGetTransferPaths(
                requestUri,
                out string? relativePath,
                out string? sourcePath,
                out string? destinationPath,
                out string? errorMessage) ||
                relativePath is null ||
                sourcePath is null ||
                destinationPath is null)
            {
                return new SequentialTransferPlanBuildResult(false, null, errorMessage);
            }

            ArgumentNullException.ThrowIfNull(relativePath);
            ArgumentNullException.ThrowIfNull(sourcePath);
            ArgumentNullException.ThrowIfNull(destinationPath);

            if (expectedHost is null)
            {
                expectedHost = requestUri.Host;
                expectedPort = requestUri.Port;
            }
            else if (!string.Equals(expectedHost, requestUri.Host, StringComparison.OrdinalIgnoreCase) || requestUri.Port != expectedPort)
            {
                return new SequentialTransferPlanBuildResult(false, null, $"REQUESTS entry '{requestUri}' must target the same host and port as the first request URL.");
            }

            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            plans.Add(new SequentialTransferPlan(requestUri, remoteEndPoint, relativePath, sourcePath, destinationPath));
        }

        return new SequentialTransferPlanBuildResult(true, plans, null);
    }

    private static async Task<long> DownloadHttp09ResponseAsync(
        QuicConnection connection,
        SequentialTransferPlan transferPlan,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        int requestIndex,
        int totalRequestCount,
        TimeSpan responseReadTimeout = default,
        TimeSpan? sendCreditRetryTimeout = null,
        Action<long>? bytesDownloadedObserver = null,
        bool waitForPeerFinAfterExpectedBody = true)
    {
        TimeSpan effectiveSendCreditRetryTimeout = sendCreditRetryTimeout ?? CongestionRetryTimeout;

        await using QuicStream stream = await RetryTransientSendCreditAsync(
            () => connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional),
            "Timed out waiting for QUIC stream open send credit.",
            retryTimeout: effectiveSendCreditRetryTimeout).ConfigureAwait(false);
        WriteLineAndFlush(
            stdout,
            $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} opened {testCase} request stream {requestIndex + 1}/{totalRequestCount} for {transferPlan.RequestUri.PathAndQuery}.");

        byte[] requestBytes = BuildHttp09GetRequestBytes(transferPlan.RequestUri);
        await RetryTransientSendCreditAsync(
            () => new ValueTask(stream.WriteAsync(requestBytes, 0, requestBytes.Length)),
            "Timed out waiting for QUIC stream send credit.",
            "Timed out waiting for QUIC stream flow-control credit.",
            effectiveSendCreditRetryTimeout).ConfigureAwait(false);
        await RetryTransientSendCreditAsync(
            () => stream.CompleteWritesAsync(),
            "Timed out waiting for QUIC stream FIN send credit.",
            "Timed out waiting for QUIC stream FIN flow-control credit.",
            effectiveSendCreditRetryTimeout).ConfigureAwait(false);
        WriteLineAndFlush(
            stdout,
            $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} sent HTTP/0.9 request line for {transferPlan.RequestUri.PathAndQuery}.");

        Directory.CreateDirectory(Path.GetDirectoryName(transferPlan.DestinationPath)!);
        string stagingPath = transferPlan.DestinationPath + ".partial";

        try
        {
            await using FileStream destinationStream = new(
                stagingPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: StreamCopyBufferSize,
                useAsync: true);

            FileInfo sourceInfo = new(transferPlan.SourcePath);
            if (sourceInfo.Exists)
            {
                await CopyHttp09ResponseBodyAsync(
                    stream,
                    destinationStream,
                    sourceInfo.Length,
                    stdout,
                    testCase,
                    configuredRequestCount,
                    requestIndex,
                    totalRequestCount,
                    transferPlan.RequestUri.PathAndQuery,
                    responseReadTimeout,
                    bytesDownloadedObserver).ConfigureAwait(false);
                if (waitForPeerFinAfterExpectedBody)
                {
                    await WaitForHttp09ResponseFinAsync(
                        stream,
                        testCase,
                        requestIndex,
                        totalRequestCount,
                        transferPlan.RequestUri.PathAndQuery,
                        responseReadTimeout).ConfigureAwait(false);
                }
            }
            else
            {
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} source length unavailable for {transferPlan.RequestUri.PathAndQuery}; reading response until peer FIN.");
                await CopyHttp09ResponseBodyUntilEndAsync(
                    stream,
                    destinationStream,
                    stdout,
                    testCase,
                    configuredRequestCount,
                    requestIndex,
                    totalRequestCount,
                    transferPlan.RequestUri.PathAndQuery,
                    responseReadTimeout,
                    bytesDownloadedObserver).ConfigureAwait(false);
            }

            await destinationStream.FlushAsync().ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (File.Exists(stagingPath))
                {
                    File.Delete(stagingPath);
                }
            }
            catch
            {
                // Best-effort cleanup only.
            }

            throw;
        }

        if (File.Exists(transferPlan.DestinationPath))
        {
            File.Delete(transferPlan.DestinationPath);
        }

        File.Move(stagingPath, transferPlan.DestinationPath);
        return new FileInfo(transferPlan.DestinationPath).Length;
    }

    internal static async Task WaitForHttp09ResponseFinAsync(
        Stream responseStream,
        string testCase,
        int requestIndex,
        int totalRequestCount,
        string requestPath,
        TimeSpan responseReadTimeout = default)
    {
        ArgumentNullException.ThrowIfNull(responseStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(testCase);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);

        byte[] finProbeBuffer = new byte[1];
        int bytesRead;
        if (responseReadTimeout > TimeSpan.Zero && responseReadTimeout != Timeout.InfiniteTimeSpan)
        {
            using CancellationTokenSource responseTimeout = new(responseReadTimeout);
            try
            {
                bytesRead = await responseStream.ReadAsync(finProbeBuffer, 0, finProbeBuffer.Length, responseTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (responseTimeout.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"Timed out waiting for {testCase} response stream FIN for {requestPath} after the expected body bytes were received.",
                    ex);
            }
        }
        else
        {
            bytesRead = await responseStream.ReadAsync(finProbeBuffer, 0, finProbeBuffer.Length).ConfigureAwait(false);
        }

        if (bytesRead != 0)
        {
            throw new InvalidOperationException(
                $"The {testCase} response for {requestPath} returned {bytesRead} extra bytes after the expected body length on stream {requestIndex + 1}/{totalRequestCount}.");
        }
    }

    internal static async Task<long> CopyHttp09ResponseBodyUntilEndAsync(
        Stream responseStream,
        Stream destinationStream,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        int requestIndex,
        int totalRequestCount,
        string requestPath,
        TimeSpan responseReadTimeout = default,
        Action<long>? bytesDownloadedObserver = null)
    {
        ArgumentNullException.ThrowIfNull(responseStream);
        ArgumentNullException.ThrowIfNull(destinationStream);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentException.ThrowIfNullOrWhiteSpace(testCase);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);

        byte[] responseBuffer = new byte[StreamCopyBufferSize];
        long bytesDownloaded = 0;

        while (true)
        {
            int bytesRead;
            if (responseReadTimeout > TimeSpan.Zero && responseReadTimeout != Timeout.InfiniteTimeSpan)
            {
                using CancellationTokenSource responseTimeout = new(responseReadTimeout);
                try
                {
                    bytesRead = await responseStream.ReadAsync(responseBuffer, 0, responseBuffer.Length, responseTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException ex) when (responseTimeout.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"Timed out waiting for {testCase} response stream FIN for {requestPath} after reading {bytesDownloaded} bytes.",
                        ex);
                }
            }
            else
            {
                bytesRead = await responseStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).ConfigureAwait(false);
            }

            if (bytesRead == 0)
            {
                return bytesDownloaded;
            }

            await destinationStream.WriteAsync(responseBuffer, 0, bytesRead).ConfigureAwait(false);
            bytesDownloaded += bytesRead;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} read {bytesRead} bytes (total={bytesDownloaded}) from {requestPath}, stream {requestIndex + 1}/{totalRequestCount}.");
            bytesDownloadedObserver?.Invoke(bytesDownloaded);
        }
    }

    internal static async Task<long> CopyHttp09ResponseBodyAsync(
        Stream responseStream,
        Stream destinationStream,
        long expectedBodyBytes,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        int requestIndex,
        int totalRequestCount,
        string requestPath,
        TimeSpan responseReadTimeout = default,
        Action<long>? bytesDownloadedObserver = null)
    {
        ArgumentNullException.ThrowIfNull(responseStream);
        ArgumentNullException.ThrowIfNull(destinationStream);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentException.ThrowIfNullOrWhiteSpace(testCase);
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        if (expectedBodyBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedBodyBytes));
        }

        if (expectedBodyBytes == 0)
        {
            return 0;
        }

        byte[] responseBuffer = new byte[StreamCopyBufferSize];
        long bytesDownloaded = 0;

        while (bytesDownloaded < expectedBodyBytes)
        {
            int bytesToRead = (int)Math.Min(responseBuffer.Length, expectedBodyBytes - bytesDownloaded);
            int bytesRead;
            if (responseReadTimeout > TimeSpan.Zero && responseReadTimeout != Timeout.InfiniteTimeSpan)
            {
                using CancellationTokenSource responseTimeout = new(responseReadTimeout);
                try
                {
                    bytesRead = await responseStream.ReadAsync(responseBuffer, 0, bytesToRead, responseTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException ex) when (responseTimeout.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"Timed out waiting for {testCase} response bytes up to the expected body length for {requestPath}.",
                        ex);
                }
            }
            else
            {
                bytesRead = await responseStream.ReadAsync(responseBuffer, 0, bytesToRead).ConfigureAwait(false);
            }

            if (bytesRead == 0)
            {
                throw new InvalidOperationException(
                    $"The peer closed the response stream for {requestPath} after {bytesDownloaded} bytes, but the expected body length is {expectedBodyBytes} bytes.");
            }

            await destinationStream.WriteAsync(responseBuffer, 0, bytesRead).ConfigureAwait(false);
            bytesDownloaded += bytesRead;
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} read {bytesRead} bytes (total={bytesDownloaded}) from {requestPath}, stream {requestIndex + 1}/{totalRequestCount}.");
            bytesDownloadedObserver?.Invoke(bytesDownloaded);
        }

        return bytesDownloaded;
    }

    internal static Task<T> RetryTransientSendCreditAsync<T>(
        Func<ValueTask<T>> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return RetryTransientSendCreditAsync(
            _ => operation(),
            congestionTimeoutMessage,
            flowControlTimeoutMessage,
            retryTimeout,
            operationAttemptTimeout: null);
    }

    internal static async Task<T> RetryTransientSendCreditAsync<T>(
        Func<CancellationToken, ValueTask<T>> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null,
        TimeSpan? operationAttemptTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentException.ThrowIfNullOrWhiteSpace(congestionTimeoutMessage);

        TimeSpan effectiveRetryTimeout = retryTimeout ?? CongestionRetryTimeout;
        TimeSpan effectiveAttemptTimeout = operationAttemptTimeout ?? TimeSpan.FromSeconds(5);
        if (effectiveAttemptTimeout > effectiveRetryTimeout)
        {
            effectiveAttemptTimeout = effectiveRetryTimeout;
        }

        long startedAt = Stopwatch.GetTimestamp();

        while (true)
        {
            using CancellationTokenSource attemptTimeout = new(effectiveAttemptTimeout);

            try
            {
                return await operation(attemptTimeout.Token).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex) when (IsTransientCongestionExhaustion(ex))
            {
                if (Stopwatch.GetElapsedTime(startedAt) >= effectiveRetryTimeout)
                {
                    throw new TimeoutException(congestionTimeoutMessage, ex);
                }

                await Task.Delay(CongestionRetryDelay).ConfigureAwait(false);
            }
            catch (NotSupportedException ex) when (flowControlTimeoutMessage is not null && IsTransientFlowControlCreditExhaustion(ex))
            {
                if (Stopwatch.GetElapsedTime(startedAt) >= effectiveRetryTimeout)
                {
                    throw new TimeoutException(flowControlTimeoutMessage, ex);
                }

                await Task.Delay(CongestionRetryDelay).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (attemptTimeout.IsCancellationRequested)
            {
                if (Stopwatch.GetElapsedTime(startedAt) >= effectiveRetryTimeout)
                {
                    throw new TimeoutException(congestionTimeoutMessage, ex);
                }

                await Task.Delay(CongestionRetryDelay).ConfigureAwait(false);
            }
        }
    }

    internal static Task RetryTransientSendCreditAsync(
        Func<ValueTask> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return RetryTransientSendCreditAsync(
            _ => operation(),
            congestionTimeoutMessage,
            flowControlTimeoutMessage,
            retryTimeout,
            operationAttemptTimeout: null);
    }

    internal static async Task RetryTransientSendCreditAsync(
        Func<CancellationToken, ValueTask> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null,
        TimeSpan? operationAttemptTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await RetryTransientSendCreditAsync(
            async cancellationToken =>
            {
                await operation(cancellationToken).ConfigureAwait(false);
                return true;
            },
            congestionTimeoutMessage,
            flowControlTimeoutMessage,
            retryTimeout,
            operationAttemptTimeout).ConfigureAwait(false);
    }

    private static async Task<int> ServeHttp09RequestsAsync(
        QuicConnection connection,
        TextWriter stdout,
        string testCase,
        int expectedRequestCount,
        int configuredRequestCount,
        TimeSpan requestWaitTimeout = default)
    {
        int servedRequestCount = 0;
        int remainingExpectedRequests = expectedRequestCount > 0 ? expectedRequestCount : int.MaxValue;
        TimeSpan effectiveRequestWaitTimeout = requestWaitTimeout == default ? InteropRequestWaitTimeout : requestWaitTimeout;

        while (servedRequestCount < remainingExpectedRequests)
        {
            using CancellationTokenSource requestTimeout = new(effectiveRequestWaitTimeout);

            QuicStream stream;
            try
            {
                stream = await connection.AcceptInboundStreamAsync(requestTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (expectedRequestCount == 0 && servedRequestCount > 0)
            {
                break;
            }
            catch (QuicException ex) when (
                ShouldTreatServerCloseAsRequestLoopCompletion(
                    ex,
                    expectedRequestCount,
                    servedRequestCount))
            {
                // Server-role handshake runs intentionally start with REQUESTS="". Once at least one
                // request has been served, a peer APPLICATION_CLOSE 0 is the expected clean teardown.
                break;
            }

            await using (stream.ConfigureAwait(false))
            {
                try
                {
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} accepted {testCase} request stream {servedRequestCount + 1}.");

                    string requestTarget = await ReadHttp09RequestTargetAsync(stream).ConfigureAwait(false);
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} parsed HTTP/0.9 request target {requestTarget} on stream {servedRequestCount + 1}.");
                    await WaitForHttp09RequestFinAsync(
                        stream,
                        stdout,
                        testCase,
                        configuredRequestCount,
                        servedRequestCount,
                        requestTarget,
                        effectiveRequestWaitTimeout).ConfigureAwait(false);

                    if (!InteropHarnessPreflightPlanner.TryGetTransferPathsFromRequestTarget(
                        requestTarget,
                        out string? relativePath,
                        out string? sourcePath,
                        out _,
                        out string? errorMessage) ||
                        relativePath is null ||
                        sourcePath is null)
                    {
                        throw new InvalidOperationException(errorMessage ?? $"Unable to resolve a mounted source path for request target '{requestTarget}'.");
                    }

                    FileInfo sourceInfo = new(sourcePath);
                    if (!sourceInfo.Exists)
                    {
                        throw new FileNotFoundException($"Interop source file '{sourcePath}' was not found for request target '{requestTarget}'.", sourcePath);
                    }

                    await using FileStream sourceStream = new(
                        sourcePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        bufferSize: StreamCopyBufferSize,
                        useAsync: true);

                    TimeSpan? sendCreditRetryTimeout = testCase == "connectionmigration"
                        ? ConnectionMigrationSendCreditRetryTimeout
                        : null;
                    TimeSpan? sendCreditAttemptTimeout = testCase == "connectionmigration"
                        ? ConnectionMigrationSendCreditAttemptTimeout
                        : null;

                    await CopyToQuicStreamWithRetryAsync(
                        sourceStream,
                        stream,
                        sendCreditRetryTimeout,
                        sendCreditAttemptTimeout).ConfigureAwait(false);
                    await CompleteQuicStreamWritesWithRetryAsync(
                        stream,
                        sendCreditRetryTimeout,
                        sendCreditAttemptTimeout).ConfigureAwait(false);
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} completed managed {testCase} response from {sourcePath} for target={relativePath}, bytes={sourceInfo.Length}, stream {servedRequestCount + 1}.");
                }
                catch
                {
                    TryAbortStreamWriteSide(stream);
                    await TryCloseConnectionForFailedRequestAsync(connection).ConfigureAwait(false);
                    throw;
                }
            }

            servedRequestCount++;
        }

        return servedRequestCount;
    }

    internal static bool ShouldTreatServerCloseAsRequestLoopCompletion(
        QuicException exception,
        int expectedRequestCount,
        int servedRequestCount)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return expectedRequestCount == 0
            && servedRequestCount > 0
            && (
                (exception.QuicError == QuicError.ConnectionAborted && exception.ApplicationErrorCode == 0)
                || (exception.QuicError == QuicError.TransportError && exception.TransportErrorCode == 0));
    }

    private static async Task LingerForPeerCloseAfterFinalResponseAsync(
        QuicConnection connection,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        TimeSpan lingerTimeout)
    {
        using CancellationTokenSource peerCloseTimeout = new(lingerTimeout);

        try
        {
            QuicStream unexpectedStream = await connection.AcceptInboundStreamAsync(peerCloseTimeout.Token).ConfigureAwait(false);
            await unexpectedStream.DisposeAsync().ConfigureAwait(false);
        }
        catch (QuicException ex) when (
            ex.QuicError == QuicError.ConnectionAborted
            && ex.ApplicationErrorCode == 0)
        {
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} observed peer close after final {testCase} response.");
            return;
        }
        catch (OperationCanceledException) when (peerCloseTimeout.IsCancellationRequested)
        {
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} completed server-side post-response linger after final {testCase} response.");
            return;
        }

        throw new InvalidOperationException(
            $"interop harness: role=server, testcase={testCase} observed an unexpected stream after the final response.");
    }

    private static async Task DisposeConnectionAfterPostResponseLingerAsync(
        QuicConnection connection,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        TimeSpan lingerTimeout)
    {
        await using (connection.ConfigureAwait(false))
        {
            try
            {
                await LingerForPeerCloseAfterFinalResponseAsync(
                    connection,
                    stdout,
                    testCase,
                    configuredRequestCount,
                    lingerTimeout).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} post-response linger ended with {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    internal static async Task<string> ReadHttp09RequestTargetAsync(Stream stream)
    {
        byte[] requestLineBuffer = new byte[MaxHttp09RequestLineBytes];
        int bytesRead = 0;

        while (bytesRead < requestLineBuffer.Length)
        {
            int read = await stream.ReadAsync(
                    requestLineBuffer.AsMemory(bytesRead, requestLineBuffer.Length - bytesRead),
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            bytesRead += read;
            if (requestLineBuffer[bytesRead - 1] == (byte)'\n')
            {
                break;
            }
        }

        if (bytesRead == 0 || requestLineBuffer[Math.Max(bytesRead - 1, 0)] != (byte)'\n')
        {
            throw new InvalidOperationException("HTTP/0.9 request line did not terminate with LF before EOF.");
        }

        int lineLength = bytesRead - 1;
        if (lineLength > 0 && requestLineBuffer[lineLength - 1] == (byte)'\r')
        {
            lineLength--;
        }

        string requestLine = Encoding.ASCII.GetString(requestLineBuffer, 0, lineLength);
        string[] requestParts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (requestParts.Length != 2 || !string.Equals(requestParts[0], "GET", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"HTTP/0.9 request line '{requestLine}' was not in the supported 'GET <target>' form.");
        }

        string requestTarget = requestParts[1];
        if (string.IsNullOrWhiteSpace(requestTarget))
        {
            throw new InvalidOperationException("HTTP/0.9 request target must not be empty.");
        }

        bool absoluteRequestTarget = Uri.TryCreate(requestTarget, UriKind.Absolute, out _);
        if (!absoluteRequestTarget && !requestTarget.StartsWith("/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"HTTP/0.9 request target '{requestTarget}' must be an absolute path or URL.");
        }

        return requestTarget;
    }

    internal static async Task WaitForHttp09RequestFinAsync(
        Stream stream,
        TextWriter stdout,
        string testCase,
        int configuredRequestCount,
        int requestIndex,
        string requestTarget,
        TimeSpan requestFinTimeout)
    {
        byte[] buffer = new byte[StreamCopyBufferSize];
        using CancellationTokenSource timeout = new(requestFinTimeout);

        int bytesRead;
        try
        {
            bytesRead = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (timeout.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Timed out waiting for HTTP/0.9 request FIN after target {requestTarget}.",
                ex);
        }

        if (bytesRead == 0)
        {
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=server, testcase={testCase}, requestCount={configuredRequestCount} observed HTTP/0.9 request FIN for {requestTarget} on stream {requestIndex + 1}.");
            return;
        }

        throw new InvalidOperationException(
            $"HTTP/0.9 request for {requestTarget} included {bytesRead} unexpected byte(s) after the request line.");
    }

    private static byte[] BuildHttp09GetRequestBytes(Uri requestUri)
    {
        string requestTarget = string.IsNullOrEmpty(requestUri.PathAndQuery)
            ? "/"
            : requestUri.PathAndQuery;
        return Encoding.ASCII.GetBytes($"GET {requestTarget}\r\n");
    }

    private static async Task CopyToQuicStreamWithRetryAsync(
        Stream sourceStream,
        QuicStream destinationStream,
        TimeSpan? sendCreditRetryTimeout = null,
        TimeSpan? sendCreditAttemptTimeout = null)
    {
        byte[] buffer = new byte[QuicStreamBodyWriteChunkSize];

        while (true)
        {
            int bytesRead = await sourceStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            await WriteQuicStreamChunkWithRetryAsync(
                destinationStream,
                buffer,
                bytesRead,
                sendCreditRetryTimeout,
                sendCreditAttemptTimeout).ConfigureAwait(false);
        }
    }

    private static async Task WriteQuicStreamChunkWithRetryAsync(
        QuicStream stream,
        byte[] buffer,
        int count,
        TimeSpan? sendCreditRetryTimeout = null,
        TimeSpan? sendCreditAttemptTimeout = null)
    {
        await RetryTransientSendCreditAsync(
            cancellationToken => new ValueTask(stream.WriteAsync(buffer, 0, count, cancellationToken)),
            "Timed out waiting for QUIC stream send credit.",
            "Timed out waiting for QUIC stream flow-control credit.",
            sendCreditRetryTimeout ?? CongestionRetryTimeout,
            sendCreditAttemptTimeout).ConfigureAwait(false);
    }

    private static async Task CompleteQuicStreamWritesWithRetryAsync(
        QuicStream stream,
        TimeSpan? sendCreditRetryTimeout = null,
        TimeSpan? sendCreditAttemptTimeout = null)
    {
        await RetryTransientSendCreditAsync(
            cancellationToken => stream.CompleteWritesAsync(cancellationToken),
            "Timed out waiting for QUIC stream FIN send credit.",
            "Timed out waiting for QUIC stream FIN flow-control credit.",
            sendCreditRetryTimeout ?? CongestionRetryTimeout,
            sendCreditAttemptTimeout).ConfigureAwait(false);
    }

    private static bool IsTransientCongestionExhaustion(InvalidOperationException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return string.Equals(exception.Message, CongestionControllerExhaustedMessage, StringComparison.Ordinal);
    }

    private static bool IsTransientFlowControlCreditExhaustion(NotSupportedException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return string.Equals(exception.Message, FlowControlCreditExhaustedMessage, StringComparison.Ordinal);
    }

    private static void TryAbortStreamWriteSide(QuicStream stream)
    {
        try
        {
            stream.Abort(QuicAbortDirection.Write, 1);
        }
        catch
        {
            // Best-effort failure signaling only.
        }
    }

    private static async Task TryCloseConnectionForFailedRequestAsync(QuicConnection connection)
    {
        try
        {
            await connection.CloseAsync(1).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort failure signaling only.
        }
    }

    private static int ReturnUnsupported(InteropHarnessEnvironment settings, TextWriter stdout, string roleName)
    {
        WriteSslKeyLogExportNotImplemented(stdout, settings);
        WriteLineAndFlush(
            stdout,
            $"interop harness: role={roleName}, testcase={settings.TestCase}, requestCount={settings.Requests.Count} is currently unsupported.");
        return UnsupportedExitCode;
    }

    private static void WriteLineAndFlush(TextWriter writer, string message)
    {
        writer.WriteLine(message);
        writer.Flush();
    }

    private static void WriteFailureDetails(
        TextWriter writer,
        string roleName,
        string testCase,
        Exception exception)
    {
        WriteLineAndFlush(
            writer,
            $"interop harness: role={roleName}, testcase={testCase} failed: {exception.Message}");
        WriteLineAndFlush(writer, exception.ToString());

        if (exception is QuicException quicException)
        {
            WriteLineAndFlush(
                writer,
                $"interop harness: role={roleName}, testcase={testCase}, quic error={quicException.QuicError}, application error code={quicException.ApplicationErrorCode}.");
        }
    }

    private static void WriteQlogCaptureEnabled(
        TextWriter stdout,
        InteropHarnessEnvironment settings,
        InteropHarnessQlogCaptureScope qlogScope)
    {
        WriteLineAndFlush(
            stdout,
            $"interop harness: role={settings.Role.ToString().ToLowerInvariant()}, testcase={settings.TestCase}, qlog capture enabled at {qlogScope.OutputPath}.");
    }

    private static void WriteSslKeyLogExportNotImplemented(
        TextWriter stdout,
        InteropHarnessEnvironment settings)
    {
        if (settings.SslKeyLogFile is null)
        {
            return;
        }

        WriteLineAndFlush(
            stdout,
            $"interop harness: role={settings.Role.ToString().ToLowerInvariant()}, testcase={settings.TestCase}, SSLKEYLOGFILE is set but this unsupported testcase does not execute keylog export.");
    }

    private static void WriteSslKeyLogExportEnabled(
        TextWriter stdout,
        InteropHarnessEnvironment settings)
    {
        if (settings.SslKeyLogFile is null)
        {
            return;
        }

        WriteLineAndFlush(
            stdout,
            $"interop harness: role={settings.Role.ToString().ToLowerInvariant()}, testcase={settings.TestCase}, SSLKEYLOGFILE export enabled at {settings.SslKeyLogFile}.");
    }

    private static bool IsSupportedHarnessTestCase(InteropHarnessEnvironment settings)
    {
        return (settings.TestCase is
            "handshake" or
            "versionnegotiation" or
            "post-handshake-stream" or
            "retry" or
            "multiconnect" or
            "v2" or
            "chacha20" or
            "handshakecorruption" or
            "transfercorruption" or
            "rebind-port" or
            "rebind-addr" or
            "connectionmigration" or
            "http3" or
            "keyupdate" or
            "resumption" or
            "transfer")
            || (settings.Role == InteropHarnessRole.Server && settings.TestCase == "zerortt");
    }

    private static void WriteDeterministicClientKeySelection(
        InteropHarnessEnvironment settings,
        TextWriter stdout)
    {
        if (settings.Role != InteropHarnessRole.Client || settings.LocalHandshakePrivateKey.IsEmpty)
        {
            return;
        }

        WriteLineAndFlush(
            stdout,
            $"interop harness: role=client, testcase={settings.TestCase}, using deterministic local handshake key from harness configuration.");
    }

    private static ValueTask<QuicConnection> ConnectWithQlogCaptureAsync(
        InteropHarnessEnvironment settings,
        InteropHarnessQlogCaptureScope? qlogScope,
        QuicClientConnectionOptions options,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null,
        CancellationToken cancellationToken = default,
        uint[]? supportedVersions = null)
    {
        return qlogScope is null
            ? QuicConnection.ConnectAsync(
                options,
                detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot,
                cancellationToken: cancellationToken,
                diagnosticsSink: null,
                localHandshakePrivateKey: settings.LocalHandshakePrivateKey,
                allowClientPeerInitialReplacementBeforeTranscript: AllowClientPeerInitialReplacementBeforeTranscript(settings),
                tlsKeyLogSecretObserver: InteropHarnessSslKeyLogWriter.CreateObserver(settings.SslKeyLogFile),
                supportedVersions: supportedVersions)
            : qlogScope.Capture.ConnectAsync(
                options,
                settings.LocalHandshakePrivateKey,
                cancellationToken,
                AllowClientPeerInitialReplacementBeforeTranscript(settings),
                detachedResumptionTicketSnapshot,
                InteropHarnessSslKeyLogWriter.CreateObserver(settings.SslKeyLogFile),
                supportedVersions);
    }

    private static bool AllowClientPeerInitialReplacementBeforeTranscript(InteropHarnessEnvironment settings)
    {
        return settings.Role == InteropHarnessRole.Client
            && string.Equals(settings.TestCase, "multiconnect", StringComparison.Ordinal);
    }

    private static ValueTask<QuicListener> ListenWithQlogCaptureAsync(
        InteropHarnessEnvironment settings,
        InteropHarnessQlogCaptureScope? qlogScope,
        QuicListenerOptions options,
        CancellationToken cancellationToken = default,
        Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = null)
    {
        if (qlogScope is null)
        {
            return QuicListener.ListenAsync(
                options,
                cancellationToken,
                diagnosticsSinkFactory: diagnosticsSinkFactory,
                tlsKeyLogSecretObserver: InteropHarnessSslKeyLogWriter.CreateObserver(settings.SslKeyLogFile));
        }

        if (diagnosticsSinkFactory is null)
        {
            return qlogScope.Capture.ListenAsync(
                options,
                cancellationToken,
                InteropHarnessSslKeyLogWriter.CreateObserver(settings.SslKeyLogFile));
        }

        return QuicListener.ListenAsync(
            options,
            cancellationToken,
            () => new CompositeDiagnosticsSink(
                qlogScope.Capture.CreateServerDiagnosticsSinkFactory().Invoke(),
                diagnosticsSinkFactory()),
            InteropHarnessSslKeyLogWriter.CreateObserver(settings.SslKeyLogFile));
    }

    private static IHttp3DiagnosticsSink? CreateHttp3QlogDiagnosticsSink(
        InteropHarnessQlogCaptureScope? qlogScope,
        bool isServer)
    {
        return qlogScope is null
            ? null
            : new QuicQlogHttp3DiagnosticsSink(qlogScope.Capture, isServer);
    }

    private static async Task<bool> WaitForVersionNegotiationSentAsync(
        VersionNegotiationSentObserver observer,
        TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            if (observer.SawVersionNegotiationSent)
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
        }

        return observer.SawVersionNegotiationSent;
    }

    private sealed class VersionNegotiationSentObserver : IQuicDiagnosticsSink
    {
        private int sawVersionNegotiationSent;

        public bool SawVersionNegotiationSent => Volatile.Read(ref sawVersionNegotiationSent) != 0;

        public bool IsEnabled => true;

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            if (diagnosticEvent.Kind == QuicDiagnosticKind.VersionNegotiationSent)
            {
                Interlocked.Exchange(ref sawVersionNegotiationSent, 1);
            }
        }
    }

    private sealed class CompositeDiagnosticsSink : IQuicDiagnosticsSink
    {
        private readonly IQuicDiagnosticsSink primary;
        private readonly IQuicDiagnosticsSink secondary;

        public CompositeDiagnosticsSink(IQuicDiagnosticsSink primary, IQuicDiagnosticsSink secondary)
        {
            this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
            this.secondary = secondary ?? throw new ArgumentNullException(nameof(secondary));
        }

        public bool IsEnabled => primary.IsEnabled || secondary.IsEnabled;

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            primary.Emit(diagnosticEvent);
            secondary.Emit(diagnosticEvent);
        }
    }

    internal static bool TryGetDispatchRequestUri(
        InteropHarnessEnvironment settings,
        out Uri? requestUri,
        out string? errorMessage,
        bool allowEmptyRequests = false)
    {
        InteropHarnessPreflightPlanner planner = new(settings, TextWriter.Null);
        return planner.TryGetDispatchRequestUri(out requestUri, out errorMessage, allowEmptyRequests);
    }

    internal static async ValueTask<IPEndPoint> ResolveHandshakeListenEndPointAsync(Uri? requestUri)
    {
        return await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
    }
}
