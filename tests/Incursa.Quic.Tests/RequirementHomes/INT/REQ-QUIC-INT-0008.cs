using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0008")]
public sealed class REQ_QUIC_INT_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointHostShellBridgesTheLibraryRuntimeThroughAConnectedUdpSocketAndRoutesInboundHandshakeDatagrams()
    {
        var (serverSocket, clientSocket, serverEndPoint, clientEndPoint) = InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();

        try
        {
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            Assert.True(endpoint.TryRegisterConnection(handle, runtime));

            byte[] routeConnectionId = [0x10, 0x11];
            Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId));

            QuicTlsPacketProtectionMaterial material = InteropEndpointHostTestSupport.CreateHandshakeMaterial();
            QuicTransportParameters localTransportParameters = InteropEndpointHostTestSupport.CreateBootstrapLocalTransportParameters();

            Assert.True(endpoint.Host.TryPostEvent(handle, new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material))));

            ConcurrentQueue<QuicConnectionIngressResult> ingressResults = new();
            ConcurrentQueue<QuicConnectionTransitionResult> transitionResults = new();
            ConcurrentQueue<QuicConnectionEffect> effectResults = new();
            using ManualResetEventSlim ingressSeen = new(false);
            using ManualResetEventSlim packetReceivedSeen = new(false);
            using ManualResetEventSlim bootstrapSeen = new(false);

            using InteropEndpointHost shell = new(
                endpoint,
                serverSocket,
                new QuicConnectionPathIdentity(
                    clientEndPoint.Address.ToString(),
                    serverEndPoint.Address.ToString(),
                    clientEndPoint.Port,
                    serverEndPoint.Port),
                ingressObserver: ingressResult =>
                {
                    ingressResults.Enqueue(ingressResult);
                    ingressSeen.Set();
                },
                transitionObserver: transitionResult =>
                {
                    transitionResults.Enqueue(transitionResult);
                    if (transitionResult.EventKind == QuicConnectionEventKind.PacketReceived)
                    {
                        packetReceivedSeen.Set();
                    }
                    else if (transitionResult.EventKind == QuicConnectionEventKind.HandshakeBootstrapRequested)
                    {
                        bootstrapSeen.Set();
                    }
                },
                effectObserver: effect =>
                {
                    effectResults.Enqueue(effect);
                });

            _ = shell.RunAsync();

            Assert.True(endpoint.Host.TryPostEvent(handle, new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 3,
                LocalTransportParameters: localTransportParameters)));
            Assert.True(bootstrapSeen.Wait(TimeSpan.FromSeconds(5)));

            byte[] serverHelloTranscript = InteropEndpointHostTestSupport.CreateServerHelloTranscript();

            byte[] serverHelloPacket = InteropEndpointHostTestSupport.BuildProtectedHandshakePacket(
                material,
                serverHelloTranscript,
                routeConnectionId);

            int bytesSent = clientSocket.Send(serverHelloPacket);
            Assert.Equal(serverHelloPacket.Length, bytesSent);

            Assert.True(ingressSeen.Wait(TimeSpan.FromSeconds(5)));
            Assert.All(ingressResults, result => Assert.True(result.RoutedToConnection));
            QuicConnectionIngressResult ingressResult = ingressResults.First();
            Assert.True(ingressResult.RoutedToConnection);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, ingressResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
            Assert.Equal(handle, ingressResult.Handle);

            Assert.True(packetReceivedSeen.Wait(TimeSpan.FromSeconds(5)));
            Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);
            Assert.True(runtime.TlsState.HandshakeKeysAvailable);
            Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);
            Assert.Null(runtime.TlsState.PeerTransportParameters);
            Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
            Assert.DoesNotContain(effectResults, effect => effect is QuicConnectionSendDatagramEffect);
            QuicConnectionTransitionResult packetReceivedResult = GetPacketReceivedTransitionResult(transitionResults);
            Assert.Equal(QuicConnectionEventKind.PacketReceived, packetReceivedResult.EventKind);
            Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        }
        finally
        {
            serverSocket.Dispose();
            clientSocket.Dispose();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostOwnsHonestInitialDcidBootstrapStateBeforeConnect()
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint()),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = GetPrivateField<byte[]>(host, "initialDestinationConnectionId");
        byte[] routeConnectionId = GetPrivateField<byte[]>(host, "routeConnectionId");
        QuicConnection connection = GetPrivateField<QuicConnection>(host, "connection");
        QuicConnectionRuntime runtime = GetPrivateField<QuicConnectionRuntime>(connection, "runtime");
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = GetPrivateField<QuicHandshakeFlowCoordinator>(runtime, "handshakeFlowCoordinator");

        Assert.Equal(8, initialDestinationConnectionId.Length);
        Assert.Equal(8, routeConnectionId.Length);
        Assert.Equal(initialDestinationConnectionId, GetPrivateField<byte[]>(handshakeFlowCoordinator, "initialDestinationConnectionId"));
        Assert.Empty(GetPrivateField<byte[]>(handshakeFlowCoordinator, "destinationConnectionId"));
        Assert.Equal(routeConnectionId, GetPrivateField<byte[]>(handshakeFlowCoordinator, "sourceConnectionId"));
        Assert.NotNull(GetPrivateField<QuicInitialPacketProtection>(runtime, "initialPacketProtection"));
        Assert.Equal(QuicTlsRole.Client, runtime.TlsState.Role);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostEmitsTheRealServerHandshakeResponseAfterInitialAdmission()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        clientSocket.Connect(listenEndPoint);

        byte[] clientInitialDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];

        byte[] clientSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];

        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            listenBacklog: 1);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        int bytesSent = clientSocket.Send(clientInitialPacket);
        Assert.Equal(clientInitialPacket.Length, bytesSent);

        byte[] responseBuffer = new byte[4096];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(bytesReceived > 0);

        Assert.True(QuicPacketParser.TryParseLongHeader(
            responseBuffer.AsSpan(0, bytesReceived),
            out QuicLongHeaderPacket responseHeader));
        Assert.Equal(1u, responseHeader.Version);
        Assert.Equal(QuicLongPacketTypeBits.Handshake, responseHeader.LongPacketTypeBits);
        Assert.Equal(clientSourceConnectionId, responseHeader.DestinationConnectionId.ToArray());
        Assert.Equal(8, responseHeader.SourceConnectionId.Length);
        Assert.NotEqual(clientSourceConnectionId, responseHeader.SourceConnectionId.ToArray());
        Assert.True(responseHeader.VersionSpecificData.Length > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostStillEmitsTheHandshakeResponseAfterAnAsyncConnectionCallbackDelay()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        clientSocket.Connect(listenEndPoint);

        byte[] clientInitialDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];

        byte[] clientSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        ];

        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            async (_, _, cancellationToken) =>
            {
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            },
            listenBacklog: 1);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        int bytesSent = clientSocket.Send(clientInitialPacket);
        Assert.Equal(clientInitialPacket.Length, bytesSent);

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        callbackRelease.TrySetResult(true);

        byte[] responseBuffer = new byte[4096];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(bytesReceived > 0);

        Assert.True(QuicPacketParser.TryParseLongHeader(
            responseBuffer.AsSpan(0, bytesReceived),
            out QuicLongHeaderPacket responseHeader));
        Assert.Equal(1u, responseHeader.Version);
        Assert.Equal(clientSourceConnectionId, responseHeader.DestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HarnessHandshakeTestcaseDispatchesIntoTheManagedBootstrapPath()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string requests = $"https://127.0.0.1:{listenEndPoint.Port}/handshake";
        string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

        await using HarnessProcess serverProcess = HarnessProcess.Start("server", "handshake", requests, harnessDll);
        await serverProcess.WaitForListeningAsync(TimeSpan.FromSeconds(10));

        await using HarnessProcess clientProcess = HarnessProcess.Start("client", "handshake", requests, harnessDll);
        await clientProcess.WaitForStdoutContainsAsync("connecting to", TimeSpan.FromSeconds(10));
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        Assert.Contains("role=server, testcase=handshake", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("role=client, testcase=handshake", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("listening on", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connecting to", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported", serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RealClientBootstrapPacketCanDriveTheServerRuntimeWhenReplayedDirectly()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using Socket captureSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        captureSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        IPEndPoint listenEndPoint = (IPEndPoint)captureSocket.LocalEndPoint!;
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenEndPoint),
            "options");

        await using QuicClientConnectionHost clientHost = new(settings);
        Task<QuicConnection> connectTask = clientHost.ConnectAsync().AsTask();

        byte[] datagramBuffer = new byte[4096];
        EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        SocketReceiveFromResult receiveResult = await captureSocket.ReceiveFromAsync(
            datagramBuffer.AsMemory(),
            SocketFlags.None,
            remoteEndPoint,
            receiveTimeout.Token);

        byte[] capturedDatagram = datagramBuffer[..receiveResult.ReceivedBytes];
        IPEndPoint clientEndPoint = (IPEndPoint)receiveResult.RemoteEndPoint;

        Assert.True(QuicPacketParser.TryParseLongHeader(capturedDatagram, out QuicLongHeaderPacket longHeader));
        Assert.Equal(QuicLongPacketTypeBits.Initial, longHeader.LongPacketTypeBits);

        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            "options",
            [SslApplicationProtocol.Http3]);

        byte[] serverSourceConnectionId =
        [
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        ];

        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(longHeader.DestinationConnectionId.ToArray()));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId(longHeader.SourceConnectionId.ToArray()));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));

        QuicTransportParameters serverTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
            serverSourceConnectionId);

        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: serverTransportParameters),
            nowTicks: 1).StateChanged);

        QuicConnectionPathIdentity clientPath = new(
            clientEndPoint.Address.ToString(),
            listenEndPoint.Address.ToString(),
            clientEndPoint.Port,
            listenEndPoint.Port);

        QuicConnectionTransitionResult initialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                clientPath,
                capturedDatagram),
            nowTicks: 2);

        await clientHost.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => connectTask);

        Assert.True(
            initialResult.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect),
            $"Captured client Initial did not drive the server runtime. Runtime={QuicLoopbackEstablishmentTestSupport.DescribeConnection(new QuicConnection(serverRuntime, new QuicClientConnectionOptions(), null))}");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PemLoadedServerCertificateDiagnosticCapturesTheFirstMissingHandshakeCompletionGate()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-int-diagnostics");
        using X509Certificate2 sourceCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        string certificatePemPath = fixture.CreateFile("cert.pem", sourceCertificate.ExportCertificatePem());

        using ECDsa sourcePrivateKey = sourceCertificate.GetECDsaPrivateKey()!;
        string privateKeyPemPath = fixture.CreateFile("priv.key", sourcePrivateKey.ExportPkcs8PrivateKeyPem());

        Assert.True(
            InteropTlsMaterials.TryLoad(certificatePemPath, privateKeyPemPath, out InteropTlsMaterials? materials, out string? errorMessage),
            errorMessage ?? "PEM materials failed to load.");
        Assert.NotNull(materials);
        Assert.True(
            materials!.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out errorMessage),
            errorMessage ?? "PEM-backed server certificate failed to load.");
        Assert.NotNull(serverCertificate);
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        QuicConnection? observedServerConnection = null;

        await using QuicListener listener = await QuicListener.ListenAsync(new QuicListenerOptions
        {
            ListenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint(),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = async (connection, _, cancellationToken) =>
            {
                observedServerConnection = connection;
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate!);
            },
        });

        IPEndPoint listenEndPoint = GetPrivateField<QuicListenerHost>(listener, "host")
            .GetType()
            .GetField("socket", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(GetPrivateField<QuicListenerHost>(listener, "host")) is Socket socket
            ? (IPEndPoint)socket.LocalEndPoint!
            : throw new InvalidOperationException("Listener socket unavailable.");

        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenEndPoint),
            "options");

        await using QuicClientConnectionHost clientHost = new(settings);
        Task<QuicConnection> connectTask = clientHost.ConnectAsync().AsTask();
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        callbackRelease.TrySetResult(true);

        Task completed = await Task.WhenAny(
            Task.WhenAll(connectTask, acceptTask),
            Task.Delay(TimeSpan.FromSeconds(3)));

        if (completed == connectTask || completed == acceptTask || (connectTask.IsCompleted && acceptTask.IsCompleted))
        {
            await using QuicConnection clientConnection = await connectTask;
            await using QuicConnection serverConnection = await acceptTask;
            throw new Xunit.Sdk.XunitException(
                $"Diagnostic expected the PEM-backed path to stall, but both sides completed. Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}; Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}");
        }

        QuicListenerHost listenerHost = GetPrivateField<QuicListenerHost>(listener, "host");
        string clientDescription = QuicLoopbackEstablishmentTestSupport.DescribeClientHost(clientHost);
        string serverDescription = observedServerConnection is null
            ? DescribeFirstPendingServerConnection(listenerHost)
            : QuicLoopbackEstablishmentTestSupport.DescribeConnection(observedServerConnection);

        Assert.False(connectTask.IsCompleted, $"Client unexpectedly completed. Client={clientDescription}; Server={serverDescription}");
        Assert.False(acceptTask.IsCompleted, $"Server unexpectedly completed. Client={clientDescription}; Server={serverDescription}");
        Assert.Contains("PeerHandshakeTranscriptCompleted=False", clientDescription, StringComparison.Ordinal);
        Assert.Contains("PeerTP=<null>", clientDescription, StringComparison.Ordinal);
        Assert.Contains("InitialIngress=0", clientDescription, StringComparison.Ordinal);
        Assert.Contains("HandshakeIngress=0", clientDescription, StringComparison.Ordinal);
        Assert.Contains("InitialEgress=0", clientDescription, StringComparison.Ordinal);
        Assert.Contains("HandshakeEgress=0", clientDescription, StringComparison.Ordinal);
        Assert.Contains("PeerHandshakeTranscriptCompleted=False", serverDescription, StringComparison.Ordinal);
        Assert.Contains("PeerTP=<null>", serverDescription, StringComparison.Ordinal);
        Assert.Contains("InitialIngress=0", serverDescription, StringComparison.Ordinal);
        Assert.Contains("HandshakeIngress=0", serverDescription, StringComparison.Ordinal);
        Assert.Contains("InitialEgress=0", serverDescription, StringComparison.Ordinal);
        Assert.Contains("HandshakeEgress=0", serverDescription, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteMissesRemainUnroutableAndDoNotReachTheRuntimeConsumer()
    {
        var (serverSocket, clientSocket, serverEndPoint, clientEndPoint) = InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();

        try
        {
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            Assert.True(endpoint.TryRegisterConnection(handle, runtime));

            ConcurrentQueue<QuicConnectionIngressResult> ingressResults = new();
            ConcurrentQueue<QuicConnectionTransitionResult> transitionResults = new();
            ConcurrentQueue<QuicConnectionEffect> effectResults = new();
            using ManualResetEventSlim ingressSeen = new(false);

            using InteropEndpointHost shell = new(
                endpoint,
                serverSocket,
                new QuicConnectionPathIdentity(
                    clientEndPoint.Address.ToString(),
                    serverEndPoint.Address.ToString(),
                    clientEndPoint.Port,
                    serverEndPoint.Port),
                ingressObserver: ingressResult =>
                {
                    ingressResults.Enqueue(ingressResult);
                    ingressSeen.Set();
                },
                transitionObserver: transitionResult => transitionResults.Enqueue(transitionResult),
                effectObserver: effect => effectResults.Enqueue(effect));

            _ = shell.RunAsync();

            QuicTlsPacketProtectionMaterial material = InteropEndpointHostTestSupport.CreateHandshakeMaterial();
            byte[] peerTranscript = InteropEndpointHostTestSupport.CreateClientHandshakeTranscript(
                InteropEndpointHostTestSupport.CreatePeerTransportParameters());
            byte[] protectedPeerPacket = InteropEndpointHostTestSupport.BuildProtectedHandshakePacket(
                material,
                peerTranscript,
                [0x30, 0x31]);

            int bytesSent = clientSocket.Send(protectedPeerPacket);
            Assert.Equal(protectedPeerPacket.Length, bytesSent);

            Assert.True(ingressSeen.Wait(TimeSpan.FromSeconds(5)));
            QuicConnectionIngressResult ingressResult = Assert.Single(ingressResults);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, ingressResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
            Assert.Null(ingressResult.Handle);
            Assert.Empty(transitionResults);
            Assert.Empty(effectResults);
        }
        finally
        {
            serverSocket.Dispose();
            clientSocket.Dispose();
        }
    }

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return Assert.IsType<T>(field!.GetValue(target));
    }

    private static string DescribeFirstPendingServerConnection(QuicListenerHost listenerHost)
    {
        FieldInfo? connectionsField = typeof(QuicListenerHost).GetField("connections", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(connectionsField);

        object? connectionsObject = connectionsField!.GetValue(listenerHost);
        Assert.NotNull(connectionsObject);

        System.Collections.IEnumerable connections = Assert.IsAssignableFrom<System.Collections.IEnumerable>(connectionsObject);
        foreach (object? entry in connections)
        {
            if (entry is null)
            {
                continue;
            }

            PropertyInfo? valueProperty = entry.GetType().GetProperty("Value", BindingFlags.Public | BindingFlags.Instance);
            object? pendingState = valueProperty?.GetValue(entry);
            if (pendingState is null)
            {
                continue;
            }

            FieldInfo? connectionField = pendingState.GetType().GetField("Connection", BindingFlags.Public | BindingFlags.Instance);
            if (connectionField?.GetValue(pendingState) is QuicConnection connection)
            {
                return QuicLoopbackEstablishmentTestSupport.DescribeConnection(connection);
            }
        }

        return "<no pending server connection>";
    }

    private static QuicConnectionTransitionResult GetPacketReceivedTransitionResult(ConcurrentQueue<QuicConnectionTransitionResult> transitionResults)
    {
        foreach (QuicConnectionTransitionResult result in transitionResults)
        {
            if (result.EventKind == QuicConnectionEventKind.PacketReceived)
            {
                return result;
            }
        }

        throw new InvalidOperationException("PacketReceived transition was not observed.");
    }

    private sealed class RecordingTextWriter : TextWriter
    {
        private readonly StringBuilder builder = new();
        private readonly object gate = new();

        public override Encoding Encoding => Encoding.UTF8;

        public override void WriteLine(string? value)
        {
            lock (gate)
            {
                builder.AppendLine(value);
            }
        }

        public override Task WriteLineAsync(string? value)
        {
            WriteLine(value);
            return Task.CompletedTask;
        }

        public bool Contains(string value)
        {
            lock (gate)
            {
                return builder.ToString().Contains(value, StringComparison.OrdinalIgnoreCase);
            }
        }

        public override string ToString()
        {
            lock (gate)
            {
                return builder.ToString();
            }
        }
    }

    private static void TryDeleteEmptyDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return;
        }

        try
        {
            if (Directory.EnumerateFileSystemEntries(directory).Any())
            {
                return;
            }

            Directory.Delete(directory, recursive: false);
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }

    private sealed class HarnessProcess : IAsyncDisposable
    {
        private readonly StringBuilder stdoutBuilder = new();
        private readonly StringBuilder stderrBuilder = new();
        private readonly object gate = new();
        private readonly Task stdoutTask;
        private readonly Task stderrTask;
        private readonly TaskCompletionSource<bool> listeningSeen = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int disposed;

        private HarnessProcess(Process process)
        {
            Process = process;
            stdoutTask = ConsumeAsync(process.StandardOutput, line =>
            {
                lock (gate)
                {
                    stdoutBuilder.AppendLine(line);
                }

                if (line.Contains("listening on", StringComparison.OrdinalIgnoreCase))
                {
                    listeningSeen.TrySetResult(true);
                }
            });
            stderrTask = ConsumeAsync(process.StandardError, line =>
            {
                lock (gate)
                {
                    stderrBuilder.AppendLine(line);
                }
            });
        }

        public Process Process { get; }

        public string Stdout
        {
            get
            {
                lock (gate)
                {
                    return stdoutBuilder.ToString();
                }
            }
        }

        public string Stderr
        {
            get
            {
                lock (gate)
                {
                    return stderrBuilder.ToString();
                }
            }
        }

        public static HarnessProcess Start(string role, string testCase, string requests, string harnessDll)
        {
            ProcessStartInfo startInfo = new("dotnet")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            startInfo.ArgumentList.Add(harnessDll);
            startInfo.Environment["ROLE"] = role;
            startInfo.Environment["TESTCASE"] = testCase;
            startInfo.Environment["REQUESTS"] = requests;

            Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start the interop harness process.");
            return new HarnessProcess(process);
        }

        public async Task WaitForListeningAsync(TimeSpan timeout)
        {
            Task completed = await Task.WhenAny(listeningSeen.Task, Process.WaitForExitAsync(), Task.Delay(timeout)).ConfigureAwait(false);
            if (completed == listeningSeen.Task)
            {
                await listeningSeen.Task.ConfigureAwait(false);
                return;
            }

            throw new TimeoutException(
                $"The server harness did not announce listening within {timeout}.\nSTDOUT:\n{Stdout}\nSTDERR:\n{Stderr}");
        }

        public async Task WaitForStdoutContainsAsync(string value, TimeSpan timeout)
        {
            DateTime deadline = DateTime.UtcNow + timeout;

            while (DateTime.UtcNow < deadline)
            {
                if (Stdout.Contains(value, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (Process.HasExited)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
            }

            throw new TimeoutException(
                $"The harness process did not write '{value}' within {timeout}.\nSTDOUT:\n{Stdout}\nSTDERR:\n{Stderr}");
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            try
            {
                bool hasExited = false;
                try
                {
                    hasExited = Process.HasExited;
                }
                catch (InvalidOperationException)
                {
                    return;
                }

                if (!hasExited)
                {
                    try
                    {
                        Process.Kill(entireProcessTree: true);
                    }
                    catch
                    {
                        // Best-effort cleanup only.
                    }

                    try
                    {
                        await Process.WaitForExitAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                        // Best-effort cleanup only.
                    }
                }
            }
            finally
            {
                Process.Dispose();
            }
        }

        private static async Task ConsumeAsync(StreamReader reader, Action<string> onLine)
        {
            while (true)
            {
                string? line = await reader.ReadLineAsync().ConfigureAwait(false);
                if (line is null)
                {
                    return;
                }

                onLine(line);
            }
        }
    }

} 
