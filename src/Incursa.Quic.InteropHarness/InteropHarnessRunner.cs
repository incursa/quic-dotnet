using Incursa.Quic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessRunner
{
    private const int UnsupportedExitCode = 127;
    private const int StreamCopyBufferSize = 4096;
    private const int MaxHttp09RequestLineBytes = 4096;
    private const int QuicStreamBodyWriteChunkSize = 1024;
    private const string CongestionControllerExhaustedMessage = "The congestion controller cannot send another ordinary packet.";
    private const string FlowControlCreditExhaustedMessage = "Writes that wait for additional flow-control credit are not supported by this slice.";
    private static readonly TimeSpan InteropRequestWaitTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan CongestionRetryDelay = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan CongestionRetryTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ServerKnownPlanPostResponseLingerTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ServerOpenPlanPostResponseLingerTimeout = InteropRequestWaitTimeout;

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

    internal sealed record ServerMulticonnectDispatchPlanBuildResult(
        bool Success,
        ServerMulticonnectDispatchPlan? Plan,
        string? ErrorMessage);

    private static InteropHarnessPreflightPlanner CreatePlanner(InteropHarnessEnvironment settings, TextWriter stdout)
    {
        return new InteropHarnessPreflightPlanner(settings, stdout);
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
        WriteSslKeyLogExportNotImplemented(stdout, settings);

        return settings.TestCase switch
        {
            "handshake" => RunHandshakeClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "retry" => RunRetryClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "multiconnect" => RunMulticonnectClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
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
        WriteSslKeyLogExportNotImplemented(stdout, settings);

        return settings.TestCase switch
        {
            "handshake" => RunHandshakeServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "retry" => RunRetryServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "multiconnect" => RunMulticonnectServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "transfer" => RunTransferServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
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
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

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
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} completed managed client bootstrap.");

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
                    $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} completed managed handshake download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, stream {index + 1}/{transferPlans.Count}.");
            }

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=handshake failed: {ex.Message}");
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
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=post-handshake-stream failed: {ex.Message}");
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
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(qlogScope, listenerOptions).ConfigureAwait(false);
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=handshake, requestCount={settings.Requests.Count} listening on {listenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=handshake, requestCount={settings.Requests.Count} completed managed listener bootstrap.");

                int servedRequestCount = await ServeHttp09RequestsAsync(
                    connection,
                    stdout,
                    "handshake",
                    expectedRequestCount: settings.Requests.Count,
                    configuredRequestCount: settings.Requests.Count).ConfigureAwait(false);

                if (servedRequestCount == 0)
                {
                    WriteLineAndFlush(stderr, "interop harness: role=server, testcase=handshake did not observe an HTTP/0.9 request stream.");
                    return 1;
                }

                if (settings.Requests.Count > 0)
                {
                    await LingerForPeerCloseAfterFinalResponseAsync(
                        connection,
                        stdout,
                        "handshake",
                        settings.Requests.Count,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                }

                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=handshake failed: {ex.Message}");
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
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(qlogScope, listenerOptions).ConfigureAwait(false);
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
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=post-handshake-stream failed: {ex.Message}");
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
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=retry failed: {ex.Message}");
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
                    (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
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
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=retry failed: {ex.Message}");
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
                    responseReadTimeout).ConfigureAwait(false);
                await connection.CloseAsync(0).ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase=multiconnect, requestCount={settings.Requests.Count} completed managed multiconnect download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, connection {index + 1}/{transferPlans.Count}.");
            }

            return 0;
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stdout, $"interop harness: role=client, testcase=multiconnect failed: {ex.Message}");
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
                $"interop harness: role=client, testcase=transfer, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}, targetCount={transferPlans.Count}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, firstPlan.RequestUri.Host);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            WriteDeterministicClientKeySelection(settings, stdout);
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(settings, qlogScope, clientOptions).ConfigureAwait(false);

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
                    $"interop harness: role=client, testcase=transfer, requestCount={settings.Requests.Count} completed managed transfer download to {transferPlan.DestinationPath} from {transferPlan.RequestUri.PathAndQuery}, bytes={bytesDownloaded}, stream {index + 1}/{transferPlans.Count}.");
            }

            await connection.CloseAsync(0).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=transfer failed: {ex.Message}");
            WriteLineAndFlush(stderr, ex.ToString());
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
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(qlogScope, listenerOptions).ConfigureAwait(false);
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
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=multiconnect failed: {ex.Message}");
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
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
                };

                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }
                await using QuicListener listener = await ListenWithQlogCaptureAsync(qlogScope, listenerOptions).ConfigureAwait(false);
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=transfer, requestCount={dispatchPlan.ConfiguredRequestCount} listening on {dispatchPlan.ListenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                int servedRequestCount = await ServeHttp09RequestsAsync(
                    connection,
                    stdout,
                    "transfer",
                    expectedRequestCount: dispatchPlan.ExpectedRequestCount,
                    configuredRequestCount: dispatchPlan.ConfiguredRequestCount).ConfigureAwait(false);

                if (servedRequestCount == 0)
                {
                    WriteLineAndFlush(stderr, "interop harness: role=server, testcase=transfer did not observe an HTTP/0.9 request stream.");
                    return 1;
                }

                if (dispatchPlan.ExpectedRequestCount > 0)
                {
                    await LingerForPeerCloseAfterFinalResponseAsync(
                        connection,
                        stdout,
                        "transfer",
                        dispatchPlan.ConfiguredRequestCount,
                        ServerKnownPlanPostResponseLingerTimeout).ConfigureAwait(false);
                }

                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=transfer failed: {ex.Message}");
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
        TimeSpan? sendCreditRetryTimeout = null)
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
                        bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length, responseTimeout.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException ex) when (responseTimeout.IsCancellationRequested)
                    {
                        throw new TimeoutException(
                            $"Timed out waiting for {testCase} response bytes or EOF for {transferPlan.RequestUri.PathAndQuery}.",
                            ex);
                    }
                }
                else
                {
                    bytesRead = await stream.ReadAsync(responseBuffer, 0, responseBuffer.Length).ConfigureAwait(false);
                }

                if (bytesRead == 0)
                {
                    break;
                }

                await destinationStream.WriteAsync(responseBuffer, 0, bytesRead).ConfigureAwait(false);
                bytesDownloaded += bytesRead;
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=client, testcase={testCase}, requestCount={configuredRequestCount} read {bytesRead} bytes (total={bytesDownloaded}) from {transferPlan.RequestUri.PathAndQuery}, stream {requestIndex + 1}/{totalRequestCount}.");
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

    internal static async Task<T> RetryTransientSendCreditAsync<T>(
        Func<ValueTask<T>> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentException.ThrowIfNullOrWhiteSpace(congestionTimeoutMessage);

        TimeSpan effectiveRetryTimeout = retryTimeout ?? CongestionRetryTimeout;
        long startedAt = Stopwatch.GetTimestamp();

        while (true)
        {
            try
            {
                return await operation().ConfigureAwait(false);
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
        }
    }

    internal static async Task RetryTransientSendCreditAsync(
        Func<ValueTask> operation,
        string congestionTimeoutMessage,
        string? flowControlTimeoutMessage = null,
        TimeSpan? retryTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        await RetryTransientSendCreditAsync(
            async () =>
            {
                await operation().ConfigureAwait(false);
                return true;
            },
            congestionTimeoutMessage,
            flowControlTimeoutMessage,
            retryTimeout).ConfigureAwait(false);
    }

    private static async Task<int> ServeHttp09RequestsAsync(
        QuicConnection connection,
        TextWriter stdout,
        string testCase,
        int expectedRequestCount,
        int configuredRequestCount)
    {
        int servedRequestCount = 0;
        int remainingExpectedRequests = expectedRequestCount > 0 ? expectedRequestCount : int.MaxValue;

        while (servedRequestCount < remainingExpectedRequests)
        {
            using CancellationTokenSource requestTimeout = new(InteropRequestWaitTimeout);

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

                    await CopyToQuicStreamWithRetryAsync(sourceStream, stream).ConfigureAwait(false);
                    await CompleteQuicStreamWritesWithRetryAsync(stream).ConfigureAwait(false);
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
            && exception.QuicError == QuicError.ConnectionAborted
            && exception.ApplicationErrorCode == 0;
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

    private static async Task<string> ReadHttp09RequestTargetAsync(QuicStream stream)
    {
        byte[] requestLineBuffer = new byte[MaxHttp09RequestLineBytes];
        int bytesRead = 0;

        while (bytesRead < requestLineBuffer.Length)
        {
            int read = await stream.ReadAsync(requestLineBuffer, bytesRead, 1).ConfigureAwait(false);
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

    private static byte[] BuildHttp09GetRequestBytes(Uri requestUri)
    {
        string requestTarget = string.IsNullOrEmpty(requestUri.PathAndQuery)
            ? "/"
            : requestUri.PathAndQuery;
        return Encoding.ASCII.GetBytes($"GET {requestTarget}\r\n");
    }

    private static async Task CopyToQuicStreamWithRetryAsync(Stream sourceStream, QuicStream destinationStream)
    {
        byte[] buffer = new byte[QuicStreamBodyWriteChunkSize];

        while (true)
        {
            int bytesRead = await sourceStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            await WriteQuicStreamChunkWithRetryAsync(destinationStream, buffer, bytesRead).ConfigureAwait(false);
        }
    }

    private static async Task WriteQuicStreamChunkWithRetryAsync(QuicStream stream, byte[] buffer, int count)
    {
        await RetryTransientSendCreditAsync(
            () => new ValueTask(stream.WriteAsync(buffer, 0, count)),
            "Timed out waiting for QUIC stream send credit.",
            "Timed out waiting for QUIC stream flow-control credit.").ConfigureAwait(false);
    }

    private static async Task CompleteQuicStreamWritesWithRetryAsync(QuicStream stream)
    {
        await RetryTransientSendCreditAsync(
            () => stream.CompleteWritesAsync(),
            "Timed out waiting for QUIC stream FIN send credit.",
            "Timed out waiting for QUIC stream FIN flow-control credit.").ConfigureAwait(false);
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
            $"interop harness: role={settings.Role.ToString().ToLowerInvariant()}, testcase={settings.TestCase}, SSLKEYLOGFILE is set but keylog export is not yet implemented.");
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
        CancellationToken cancellationToken = default)
    {
        return qlogScope is null
            ? QuicConnection.ConnectAsync(
                options,
                detachedResumptionTicketSnapshot: null,
                cancellationToken: cancellationToken,
                diagnosticsSink: null,
                localHandshakePrivateKey: settings.LocalHandshakePrivateKey)
            : qlogScope.Capture.ConnectAsync(options, settings.LocalHandshakePrivateKey, cancellationToken);
    }

    private static ValueTask<QuicListener> ListenWithQlogCaptureAsync(
        InteropHarnessQlogCaptureScope? qlogScope,
        QuicListenerOptions options,
        CancellationToken cancellationToken = default)
    {
        return qlogScope is null
            ? QuicListener.ListenAsync(options, cancellationToken)
            : qlogScope.Capture.ListenAsync(options, cancellationToken);
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
