using Incursa.Quic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessRunner
{
    private const int UnsupportedExitCode = 127;

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
        return settings.TestCase switch
        {
            "handshake" => RunHandshakeClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            "retry" => RunRetryClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
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
        return settings.TestCase switch
        {
            "handshake" => RunHandshakeServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "post-handshake-stream" => RunPostHandshakeStreamServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            "retry" => RunRetryServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
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

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(requestUri);
            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(qlogScope, clientOptions).ConfigureAwait(false);

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} completed managed client bootstrap.");
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
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(qlogScope, clientOptions).ConfigureAwait(false);
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
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
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
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
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

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true) ||
                requestUri is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=retry, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);
            QuicClientConnectionSettings clientSettings = QuicClientConnectionOptionsValidator.Capture(clientOptions, nameof(clientOptions));

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }

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
                using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
                if (qlogScope is not null)
                {
                    WriteQlogCaptureEnabled(stdout, settings, qlogScope);
                }

                Func<IQuicDiagnosticsSink>? diagnosticsSinkFactory = qlogScope?.Capture.CreateServerDiagnosticsSinkFactory();
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerHost listenerHost = new(
                    listenEndPoint,
                    [SslApplicationProtocol.Http3],
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

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            ArgumentNullException.ThrowIfNull(requestUri);
            if (!InteropHarnessPreflightPlanner.TryGetTransferPaths(requestUri, out string? relativePath, out string? sourcePath, out string? destinationPath, out errorMessage) ||
                relativePath is null ||
                sourcePath is null ||
                destinationPath is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=transfer, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}, target={relativePath}.");

            QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);

            using InteropHarnessQlogCaptureScope? qlogScope = planner.CreateQlogCaptureScope();
            if (qlogScope is not null)
            {
                WriteQlogCaptureEnabled(stdout, settings, qlogScope);
            }
            await using QuicConnection connection = await ConnectWithQlogCaptureAsync(qlogScope, clientOptions).ConfigureAwait(false);
            await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).ConfigureAwait(false);

            await using FileStream sourceStream = new(
                sourcePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                useAsync: true);

            await sourceStream.CopyToAsync(stream).ConfigureAwait(false);
            await stream.DisposeAsync().ConfigureAwait(false);

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=transfer, requestCount={settings.Requests.Count} completed managed transfer to {destinationPath} from {sourcePath}.");
            return 0;
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=transfer failed: {ex.Message}");
            return 1;
        }
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

            if (!planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage, allowEmptyRequests: true))
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropHarnessPreflightPlanner.TryGetTransferPaths(requestUri, out string? relativePath, out string? sourcePath, out string? destinationPath, out errorMessage) ||
                relativePath is null ||
                sourcePath is null ||
                destinationPath is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

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
                IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
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
                    $"interop harness: role=server, testcase=transfer, requestCount={settings.Requests.Count} listening on {listenEndPoint}, target={relativePath}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                await using QuicStream stream = await connection.AcceptInboundStreamAsync().ConfigureAwait(false);
                FileInfo sourceInfo = new(sourcePath);
                if (!sourceInfo.Exists)
                {
                    WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=transfer missing source file '{sourcePath}'.");
                    return 1;
                }

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=transfer, requestCount={settings.Requests.Count} transferring {sourceInfo.Length} bytes from {sourcePath} to {destinationPath}.");

                Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
                await using FileStream destinationStream = new(
                    destinationPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 4096,
                    useAsync: true);

                await stream.CopyToAsync(destinationStream).ConfigureAwait(false);
                await destinationStream.FlushAsync().ConfigureAwait(false);
                await stream.DisposeAsync().ConfigureAwait(false);

                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=transfer, requestCount={settings.Requests.Count} completed managed transfer from {sourcePath} to {destinationPath}.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=transfer failed: {ex.Message}");
            return 1;
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

    private static ValueTask<QuicConnection> ConnectWithQlogCaptureAsync(
        InteropHarnessQlogCaptureScope? qlogScope,
        QuicClientConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        return qlogScope is null
            ? QuicConnection.ConnectAsync(options, cancellationToken)
            : qlogScope.Capture.ConnectAsync(options, cancellationToken);
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
