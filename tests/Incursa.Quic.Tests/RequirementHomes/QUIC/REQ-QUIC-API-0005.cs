using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0005">The listener and client surfaces carry configuration through QuicListenerOptions, QuicClientConnectionOptions, QuicPeerCertificatePolicy, and QuicServerConnectionOptions, and the supported client TLS subset is explicit, standard-shaped on the mainstream path, reject-first for still-unsupported knobs, and honest about the supported stream-capacity callback subset rather than implied.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0005")]
public sealed class REQ_QUIC_API_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionOptions_ExposeTheSupportedStreamCapacityCallbackKnob()
    {
        PropertyInfo? callbackProperty = typeof(QuicConnectionOptions).GetProperty(nameof(QuicConnectionOptions.StreamCapacityCallback));

        Assert.NotNull(callbackProperty);
        Assert.Equal(typeof(Action<QuicConnection, QuicStreamCapacityChangedArgs>), callbackProperty!.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicListenerOptions_ExposeOnlyTheApprovedKnobs()
    {
        string[] propertyNames = typeof(QuicListenerOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ApplicationProtocols",
            "ConnectionOptionsCallback",
            "ListenBacklog",
            "ListenEndPoint",
        }, propertyNames);

        PropertyInfo? callbackProperty = typeof(QuicListenerOptions).GetProperty(nameof(QuicListenerOptions.ConnectionOptionsCallback));
        Assert.NotNull(callbackProperty);
        Assert.Equal(typeof(Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>>), callbackProperty.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicServerConnectionOptions_ExposeOnlyTheApprovedServerKnobs()
    {
        QuicServerConnectionOptions options = new();

        Assert.Equal(100, options.MaxInboundBidirectionalStreams);
        Assert.Equal(10, options.MaxInboundUnidirectionalStreams);

        string[] propertyNames = typeof(QuicServerConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ServerAuthenticationOptions",
        }, propertyNames);

        PropertyInfo? authProperty = typeof(QuicServerConnectionOptions).GetProperty(nameof(QuicServerConnectionOptions.ServerAuthenticationOptions));
        Assert.NotNull(authProperty);
        Assert.Equal(typeof(SslServerAuthenticationOptions), authProperty.PropertyType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicClientConnectionOptions_ExposeOnlyTheApprovedClientKnobs()
    {
        string[] propertyNames = typeof(QuicClientConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ClientAuthenticationOptions",
            "LocalEndPoint",
            "PeerCertificatePolicy",
            "RemoteEndPoint",
        }, propertyNames);

        QuicClientConnectionOptions options = new();
        Assert.Null(options.LocalEndPoint);
        Assert.Null(options.ClientAuthenticationOptions);
        Assert.Null(options.PeerCertificatePolicy);
        Assert.Null(options.RemoteEndPoint);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicPeerCertificatePolicy_ExposeOnlyTheApprovedKnobs()
    {
        string[] propertyNames = typeof(QuicPeerCertificatePolicy)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "ExactPeerLeafCertificateDer",
            "ExplicitTrustMaterialSha256",
        }, propertyNames);

        PropertyInfo? exactPeerLeafCertificateDerProperty = typeof(QuicPeerCertificatePolicy).GetProperty(nameof(QuicPeerCertificatePolicy.ExactPeerLeafCertificateDer));
        Assert.NotNull(exactPeerLeafCertificateDerProperty);
        Assert.Equal(typeof(ReadOnlyMemory<byte>), exactPeerLeafCertificateDerProperty!.PropertyType);

        PropertyInfo? explicitTrustMaterialSha256Property = typeof(QuicPeerCertificatePolicy).GetProperty(nameof(QuicPeerCertificatePolicy.ExplicitTrustMaterialSha256));
        Assert.NotNull(explicitTrustMaterialSha256Property);
        Assert.Equal(typeof(ReadOnlyMemory<byte>), explicitTrustMaterialSha256Property!.PropertyType);

        QuicPeerCertificatePolicy policy = new();
        Assert.True(policy.ExactPeerLeafCertificateDer.IsEmpty);
        Assert.True(policy.ExplicitTrustMaterialSha256.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsStillUnsupportedClientTlsSettingsDeterministically()
    {
        QuicClientConnectionOptions emptyAlpnOptions = CreateClientOptions();
        emptyAlpnOptions.ClientAuthenticationOptions.ApplicationProtocols = [];
        Assert.Throws<ArgumentException>(() => QuicConnection.ConnectAsync(emptyAlpnOptions));

        QuicClientConnectionOptions protocolOptions = CreateClientOptions();
        protocolOptions.ClientAuthenticationOptions.EnabledSslProtocols = SslProtocols.Tls12;
        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(protocolOptions));

        QuicClientConnectionOptions renegotiationOptions = CreateClientOptions();
        renegotiationOptions.ClientAuthenticationOptions.AllowRenegotiation = true;
        Assert.Throws<NotSupportedException>(() => QuicConnection.ConnectAsync(renegotiationOptions));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionOptionsCallback_IsInvokedThroughTheRealListenerPath()
    {
        int invocationCount = 0;
        QuicConnection? observedConnection = null;
        string? observedServerName = null;
        SslProtocols observedProtocols = default;
        CancellationToken observedToken = default;
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions options = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = async (connection, clientHello, cancellationToken) =>
            {
                invocationCount++;
                observedConnection = connection;
                observedServerName = clientHello.ServerName;
                observedProtocols = clientHello.SslProtocols;
                observedToken = cancellationToken;
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            },
        };

        await using QuicListener listener = await QuicListener.ListenAsync(options);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(connectTask.IsCompleted);
        Assert.False(acceptTask.IsCompleted);

        callbackRelease.TrySetResult(true);

        Task completionTask = Task.WhenAll(connectTask, acceptTask);
        Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
        if (completedTask != completionTask)
        {
            throw new TimeoutException(
                $"Loopback callback path did not complete. Server runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(observedConnection)}");
        }

        await completionTask;

        QuicConnection clientConnection = await connectTask;
        QuicConnection serverConnection = await acceptTask;

        try
        {
            Assert.Same(serverConnection, observedConnection);
            Assert.True(string.IsNullOrEmpty(observedServerName));
            Assert.Equal(SslProtocols.Tls13, observedProtocols);
            Assert.False(observedToken.IsCancellationRequested);
            Assert.Equal(1, invocationCount);
            Assert.NotSame(clientConnection, serverConnection);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task StreamCapacityCallback_FiresWithInitialPeerCapacityOnSupportedLoopbackPath()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<QuicStreamCapacityChangedArgs> callbackObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int callbackCount = 0;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) =>
            {
                QuicServerConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
                options.MaxInboundBidirectionalStreams = 3;
                options.MaxInboundUnidirectionalStreams = 2;
                return ValueTask.FromResult(options);
            },
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, args) =>
        {
            Interlocked.Increment(ref callbackCount);
            callbackObserved.TrySetResult(args);
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicStreamCapacityChangedArgs args = await callbackObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(3, args.BidirectionalIncrement);
            Assert.Equal(2, args.UnidirectionalIncrement);
            await Task.Delay(200);
            Assert.Equal(1, Volatile.Read(ref callbackCount));
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamCapacityCallback_IsNotInvokedForZeroPeerCapacity()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        int callbackCount = 0;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) =>
            {
                QuicServerConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
                options.MaxInboundBidirectionalStreams = 0;
                options.MaxInboundUnidirectionalStreams = 0;
                return ValueTask.FromResult(options);
            },
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        clientOptions.StreamCapacityCallback = (_, _) => Interlocked.Increment(ref callbackCount);

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            await Task.Delay(200);
            Assert.Equal(0, Volatile.Read(ref callbackCount));
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task InternalClientHost_ReceivesServerFlightDuringLoopbackEstablishment()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> callbackRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        QuicConnection? observedConnection = null;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = async (connection, _, cancellationToken) =>
            {
                observedConnection = connection;
                callbackEntered.TrySetResult(true);
                await callbackRelease.Task.WaitAsync(cancellationToken);
                return QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            },
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        QuicClientConnectionSettings clientSettings = QuicClientConnectionOptionsValidator.Capture(clientOptions, nameof(clientOptions));

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        await using QuicClientConnectionHost clientHost = new(clientSettings);

        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = clientHost.ConnectAsync().AsTask();

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        callbackRelease.TrySetResult(true);

        Task completionTask = Task.WhenAll(connectTask, acceptTask);
        Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
        if (completedTask != completionTask)
        {
            throw new TimeoutException(
                $"Internal client host did not complete. Client runtime: {QuicLoopbackEstablishmentTestSupport.DescribeClientHost(clientHost)}; Server runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(observedConnection)}");
        }

        await completionTask;

        QuicConnection clientConnection = await connectTask;
        QuicConnection serverConnection = await acceptTask;

        try
        {
            Assert.NotNull(clientConnection);
            Assert.NotNull(serverConnection);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QuicServerConnectionOptionsValidator_RejectsUnsupportedServerTlsSettingsDeterministically()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicServerConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        options.ServerAuthenticationOptions!.EnabledSslProtocols = SslProtocols.Tls12;

        Assert.Throws<NotSupportedException>(() => QuicServerConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            [SslApplicationProtocol.Http3]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManagedClientHello_RoundTripsThroughServerTranscriptProgress()
    {
        QuicTransportParameters clientTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        QuicTransportParameters serverTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters([
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        ]);

        QuicTlsKeySchedule clientKeySchedule = new(QuicTlsRole.Client);
        Assert.True(clientKeySchedule.TryCreateClientHello(clientTransportParameters, out byte[] clientHello));

        QuicTlsTranscriptProgress serverProgress = new(QuicTlsRole.Server);
        serverProgress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = serverProgress.Advance(QuicTlsRole.Server);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, clientHelloStep.HandshakeMessageType);
        Assert.NotNull(clientHelloStep.TransportParameters);
        Assert.False(clientHelloStep.KeyShare.IsEmpty);

        QuicTlsKeySchedule serverKeySchedule = new(QuicTlsRole.Server, CreateScalar(0x22));
        IReadOnlyList<QuicTlsStateUpdate> updates = serverKeySchedule.ProcessTranscriptStep(
            clientHelloStep,
            serverTransportParameters);

        Assert.Contains(updates, update => update.Kind == QuicTlsUpdateKind.CryptoDataAvailable && update.EncryptionLevel == QuicTlsEncryptionLevel.Handshake);
        Assert.True(serverKeySchedule.HandshakeSecretsDerived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientBridge_StartHandshake_ProducesInitialCryptoForRuntimeStyleTransportParameters()
    {
        byte[] routeConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];

        QuicTransportParameters runtimeTransportParameters = new()
        {
            MaxIdleTimeout = 0,
            InitialMaxData = 0,
            InitialMaxStreamDataBidiLocal = 0,
            InitialMaxStreamDataBidiRemote = 0,
            InitialMaxStreamDataUni = 0,
            InitialMaxStreamsBidi = 0,
            InitialMaxStreamsUni = 0,
            ActiveConnectionIdLimit = 2,
            InitialSourceConnectionId = routeConnectionId,
        };

        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Client);
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(runtimeTransportParameters);

        Assert.Contains(updates, update => update.Kind == QuicTlsUpdateKind.LocalTransportParametersReady);
        QuicTlsStateUpdate? cryptoDataAvailable = updates.FirstOrDefault(update =>
            update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
            && update.EncryptionLevel == QuicTlsEncryptionLevel.Initial);
        Assert.True(cryptoDataAvailable.HasValue);
        Assert.True(cryptoDataAvailable.Value.CryptoData.Length > 0);
        Assert.True(driver.TryApply(cryptoDataAvailable.Value));
        Assert.True(driver.State.InitialEgressCryptoBuffer.BufferedBytes > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManagedClientInitialPacket_IsPaddedToTheVersion1MinimumDatagramSize()
    {
        byte[] routeConnectionId = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
        byte[] initialDestinationConnectionId = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

        QuicTransportParameters clientTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(routeConnectionId);
        QuicTlsKeySchedule clientKeySchedule = new(QuicTlsRole.Client);
        Assert.True(clientKeySchedule.TryCreateClientHello(clientTransportParameters, out byte[] clientHello));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = new(initialDestinationConnectionId, routeConnectionId);
        Assert.True(handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
            clientHello,
            cryptoPayloadOffset: 0,
            initialPacketProtection,
            out byte[] protectedPacket));

        Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, protectedPacket.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(protectedPacket, out QuicLongHeaderPacket header));
        Assert.Equal(initialDestinationConnectionId, header.DestinationConnectionId.ToArray());
        Assert.Equal(routeConnectionId, header.SourceConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntime_EmitsARealInitialResponseDatagramForTheSupportedLoopbackHandshake()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            nameof(serverCertificate),
            [SslApplicationProtocol.Http3]);

        byte[] clientInitialDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        byte[] clientSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];
        byte[] serverSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        ];

        QuicTransportParameters clientTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
            clientSourceConnectionId);
        QuicTlsKeySchedule clientKeySchedule = new(QuicTlsRole.Client);
        Assert.True(clientKeySchedule.TryCreateClientHello(clientTransportParameters, out byte[] clientHello));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtection clientInitialProtection));

        QuicHandshakeFlowCoordinator clientInitialFlowCoordinator = new(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);
        Assert.True(clientInitialFlowCoordinator.TryBuildProtectedInitialPacket(
            clientHello,
            cryptoPayloadOffset: 0,
            clientInitialProtection,
            out byte[] clientInitialPacket));

        QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(clientInitialDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId(clientSourceConnectionId));
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
            "127.0.0.1",
            "127.0.0.1",
            54321,
            44321);

        QuicConnectionTransitionResult initialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                clientPath,
                clientInitialPacket),
            nowTicks: 2);

        Assert.True(initialResult.StateChanged);
        Assert.True(
            initialResult.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect),
            $"Initial transition effects: {string.Join(", ", initialResult.Effects.Select(effect => effect.GetType().Name))}");
        Assert.NotNull(serverRuntime.ActivePath);
        Assert.Equal(clientPath, serverRuntime.ActivePath.Value.Identity);
        Assert.Equal(0, serverRuntime.TlsState.InitialEgressCryptoBuffer.BufferedBytes);
        Assert.True(serverRuntime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeProtectMaterial));

        QuicHandshakeFlowCoordinator serverHandshakeFlowCoordinator = new(
            clientSourceConnectionId,
            serverSourceConnectionId);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtection serverInitialPacketProtection));
        QuicConnectionSendDatagramEffect? initialSendEffect = null;
        byte[]? openedInitialPacket = null;
        int initialPayloadOffset = default;
        int initialPayloadLength = default;
        foreach (QuicConnectionSendDatagramEffect effect in initialResult.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            if (serverHandshakeFlowCoordinator.TryOpenInitialPacket(
                effect.Datagram.Span,
                serverInitialPacketProtection,
                out openedInitialPacket,
                out initialPayloadOffset,
                out initialPayloadLength))
            {
                initialSendEffect = effect;
                break;
            }
        }

        Assert.NotNull(initialSendEffect);
        Assert.NotNull(openedInitialPacket);
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedInitialPacket,
            out _,
            out uint openedInitialVersion,
            out ReadOnlySpan<byte> openedInitialDestinationConnectionId,
            out ReadOnlySpan<byte> openedInitialSourceConnectionId,
            out _));
        Assert.Equal(1u, openedInitialVersion);
        Assert.Equal(clientSourceConnectionId, openedInitialDestinationConnectionId.ToArray());
        Assert.Equal(serverSourceConnectionId, openedInitialSourceConnectionId.ToArray());
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
            out QuicCryptoFrame initialCryptoFrame,
            out int initialCryptoFrameBytesWritten));
        Assert.True(initialCryptoFrameBytesWritten > 0);
        QuicConnectionSendDatagramEffect? handshakeSendEffect = null;
        byte[]? openedHandshakePacket = null;
        int handshakePayloadOffset = default;
        int handshakePayloadLength = default;
        foreach (QuicConnectionSendDatagramEffect effect in initialResult.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            if (serverHandshakeFlowCoordinator.TryOpenHandshakePacket(
                effect.Datagram.Span,
                handshakeProtectMaterial,
                out openedHandshakePacket,
                out handshakePayloadOffset,
                out handshakePayloadLength))
            {
                handshakeSendEffect = effect;
                break;
            }
        }

        Assert.NotNull(handshakeSendEffect);
        Assert.NotNull(openedHandshakePacket);
        Assert.True(handshakeSendEffect.Datagram.Length > 0);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame handshakeCryptoFrame,
            out int handshakeCryptoFrameBytesWritten));
        Assert.True(handshakeCryptoFrameBytesWritten > 0);
        FieldInfo? runtimeCoordinatorField = typeof(QuicConnectionRuntime).GetField("handshakeFlowCoordinator", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(runtimeCoordinatorField);
        QuicHandshakeFlowCoordinator runtimeHandshakeFlowCoordinator = Assert.IsType<QuicHandshakeFlowCoordinator>(runtimeCoordinatorField.GetValue(serverRuntime));
        FieldInfo? initialDestinationConnectionIdField = typeof(QuicHandshakeFlowCoordinator).GetField("initialDestinationConnectionId", BindingFlags.Instance | BindingFlags.NonPublic);
        FieldInfo? destinationConnectionIdField = typeof(QuicHandshakeFlowCoordinator).GetField("destinationConnectionId", BindingFlags.Instance | BindingFlags.NonPublic);
        FieldInfo? sourceConnectionIdField = typeof(QuicHandshakeFlowCoordinator).GetField("sourceConnectionId", BindingFlags.Instance | BindingFlags.NonPublic);
        FieldInfo? nextPacketNumberField = typeof(QuicHandshakeFlowCoordinator).GetField("nextPacketNumber", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(initialDestinationConnectionIdField);
        Assert.NotNull(destinationConnectionIdField);
        Assert.NotNull(sourceConnectionIdField);
        Assert.NotNull(nextPacketNumberField);
        Assert.Equal(clientInitialDestinationConnectionId, (byte[]?)initialDestinationConnectionIdField.GetValue(runtimeHandshakeFlowCoordinator));
        Assert.Equal(clientSourceConnectionId, (byte[]?)destinationConnectionIdField.GetValue(runtimeHandshakeFlowCoordinator));
        Assert.Equal(serverSourceConnectionId, (byte[]?)sourceConnectionIdField.GetValue(runtimeHandshakeFlowCoordinator));
        Assert.Equal(2UL, (ulong)nextPacketNumberField.GetValue(runtimeHandshakeFlowCoordinator)!);
        Assert.True(runtimeHandshakeFlowCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCryptoFrame.CryptoData,
            handshakeCryptoFrame.Offset,
            handshakeProtectMaterial,
            out byte[] runtimeHandshakePacket));
        Assert.True(runtimeHandshakePacket.Length > 0);
        Assert.True(runtimeHandshakeFlowCoordinator.TryOpenHandshakePacket(
            runtimeHandshakePacket,
            handshakeProtectMaterial,
            out byte[] reopenedRuntimePacket,
            out int reopenedPayloadOffset,
            out int reopenedPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            reopenedRuntimePacket.AsSpan(reopenedPayloadOffset, reopenedPayloadLength),
            out QuicCryptoFrame reopenedCryptoFrame,
            out int reopenedCryptoFrameBytesWritten));
        Assert.True(reopenedCryptoFrameBytesWritten > 0);
        Assert.True(serverRuntime.ActivePath.Value.AmplificationState.RemainingSendBudget >= (ulong)runtimeHandshakePacket.Length);
    }

    private static bool TryBuildProtectedHandshakePacketProbe(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        QuicTlsPacketProtectionMaterial material,
        out byte[] protectedPacket)
    {
        protectedPacket = [];

        if (cryptoPayload.IsEmpty
            || !QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection protection))
        {
            return false;
        }

        Span<byte> cryptoFrameBuffer = stackalloc byte[cryptoPayload.Length + 32];
        if (!QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(cryptoPayloadOffset, cryptoPayload),
            cryptoFrameBuffer,
            out int cryptoFrameBytesWritten))
        {
            return false;
        }

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId,
            sourceConnectionId,
            [0x00, 0x00, 0x00, 0x0B],
            cryptoFrameBuffer[..cryptoFrameBytesWritten]);

        byte[] protectedPacketBuffer = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        if (!protection.TryProtect(plaintextPacket, protectedPacketBuffer, out int protectedBytesWritten))
        {
            return false;
        }

        if (protectedBytesWritten != protectedPacketBuffer.Length)
        {
            return false;
        }

        protectedPacket = protectedPacketBuffer;
        return true;
    }

    private static bool TryBuildHandshakePlaintextPacketProbe(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        out byte[] plaintextPacket)
    {
        plaintextPacket = [];

        Span<byte> cryptoFrameBuffer = stackalloc byte[cryptoPayload.Length + 32];
        if (!QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(cryptoPayloadOffset, cryptoPayload),
            cryptoFrameBuffer,
            out int cryptoFrameBytesWritten))
        {
            return false;
        }

        plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId,
            sourceConnectionId,
            [0x00, 0x00, 0x00, 0x0B],
            cryptoFrameBuffer[..cryptoFrameBytesWritten]);
        return true;
    }

    private static string DescribePacketDifference(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
    {
        int firstMismatch = -1;
        int limit = Math.Min(actual.Length, expected.Length);
        for (int i = 0; i < limit; i++)
        {
            if (actual[i] != expected[i])
            {
                firstMismatch = i;
                break;
            }
        }

        if (firstMismatch < 0 && actual.Length != expected.Length)
        {
            firstMismatch = limit;
        }

        int start = Math.Max(0, firstMismatch - 4);
        int length = Math.Min(12, Math.Max(actual.Length, expected.Length) - start);

        static string FormatSlice(ReadOnlySpan<byte> bytes, int start, int length)
        {
            if (start >= bytes.Length)
            {
                return "<end>";
            }

            int actualLength = Math.Min(length, bytes.Length - start);
            return string.Join(", ", bytes.Slice(start, actualLength).ToArray());
        }

        return $"FirstMismatch={firstMismatch}; ActualLen={actual.Length}; ExpectedLen={expected.Length}; Actual[{start}..]={FormatSlice(actual, start, length)}; Expected[{start}..]={FormatSlice(expected, start, length)}";
    }

    private static QuicClientConnectionOptions CreateClientOptions()
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 443),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            },
        };
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static string DescribeCryptoBuffer(QuicCryptoBuffer buffer)
    {
        BindingFlags bindingFlags = BindingFlags.Instance | BindingFlags.NonPublic;
        Type bufferType = typeof(QuicCryptoBuffer);
        FieldInfo? entriesField = bufferType.GetField("entries", bindingFlags);
        FieldInfo? bufferedBytesField = bufferType.GetField("bufferedBytes", bindingFlags);
        FieldInfo? nextReadOffsetField = bufferType.GetField("nextReadOffset", bindingFlags);
        FieldInfo? discardFutureFramesField = bufferType.GetField("discardFutureFrames", bindingFlags);

        object? entriesValue = entriesField?.GetValue(buffer);
        int entryCount = entriesValue is System.Collections.ICollection collection ? collection.Count : -1;
        List<string> entries = [];

        if (entriesValue is System.Collections.IEnumerable enumerable)
        {
            foreach (object? entry in enumerable)
            {
                if (entry is null)
                {
                    entries.Add("<null>");
                    continue;
                }

                PropertyInfo? offsetProperty = entry.GetType().GetProperty("Offset", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                PropertyInfo? dataProperty = entry.GetType().GetProperty("Data", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                ulong offset = offsetProperty is null ? 0 : (ulong)offsetProperty.GetValue(entry)!;
                byte[]? data = dataProperty?.GetValue(entry) as byte[];
                entries.Add($"[{offset}, len={(data?.Length ?? 0)}]");
            }
        }

        return string.Join(
            "; ",
            [
                $"BufferedBytes={bufferedBytesField?.GetValue(buffer) ?? "<n/a>"}",
                $"NextReadOffset={nextReadOffsetField?.GetValue(buffer) ?? "<n/a>"}",
                $"DiscardFutureFrames={discardFutureFramesField?.GetValue(buffer) ?? "<n/a>"}",
                $"EntryCount={entryCount}",
                $"Entries={string.Join(", ", entries)}",
            ]);
    }

    private static string DescribeSendEffects(IReadOnlyList<QuicConnectionEffect> effects)
    {
        List<string> sendDatagrams = [];

        foreach (QuicConnectionEffect effect in effects)
        {
            if (effect is not QuicConnectionSendDatagramEffect sendDatagramEffect)
            {
                continue;
            }

            if (QuicPacketParser.TryParseLongHeader(sendDatagramEffect.Datagram.Span, out QuicLongHeaderPacket header))
            {
                string packetType = header.LongPacketTypeBits switch
                {
                    QuicLongPacketTypeBits.Initial => "Initial",
                    QuicLongPacketTypeBits.ZeroRtt => "ZeroRtt",
                    QuicLongPacketTypeBits.Handshake => "Handshake",
                    QuicLongPacketTypeBits.Retry => "Retry",
                    _ => $"0x{header.LongPacketTypeBits:X2}",
                };

                sendDatagrams.Add($"{packetType}@{header.DestinationConnectionId.Length}:{header.SourceConnectionId.Length}");
                continue;
            }

            sendDatagrams.Add("<unparsed>");
        }

        return sendDatagrams.Count == 0
            ? "<none>"
            : string.Join(", ", sendDatagrams);
    }
}
