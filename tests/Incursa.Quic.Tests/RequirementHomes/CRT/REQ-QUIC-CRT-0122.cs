using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0122")]
public sealed class REQ_QUIC_CRT_0122
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayRetainsTheInitialClientHelloAndRetryMetadataExactlyOnce()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] initialSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] retryPacketDestinationConnectionId = initialSourceConnectionId.ToArray();
        byte[] retrySourceConnectionId = [0x31, 0x32, 0x33];
        byte[] retryToken = [0x41, 0x42, 0x43, 0x44];
        byte[] retryPacket = CreateRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            retryPacket,
            new QuicConnectionPathIdentity("203.0.113.20", "198.51.100.30", 443, 12345));

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.Retry, ingressResult.HandlingKind);
        Assert.Null(ingressResult.Handle);

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(retrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(retryToken, retryMetadata.RetryToken);
        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            [0x91, 0x92, 0x93, 0x94],
            retryPacket,
            out _));

        QuicConnectionRuntime runtime = CreateClientRuntime(originalDestinationConnectionId, initialSourceConnectionId);
        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(initialSourceConnectionId)),
            nowTicks: 0);

        QuicConnectionSendDatagramEffect[] bootstrapDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(bootstrapDatagrams);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            retrySourceConnectionId,
            out QuicInitialPacketProtection retryServerProtection));

        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.True(packetCoordinator.TryOpenInitialPacket(
            bootstrapDatagrams[0].Datagram.Span,
            serverProtection,
            out byte[] openedBootstrapPacket,
            out _,
            out _));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedBootstrapPacket,
            out _,
            out uint bootstrapVersion,
            out ReadOnlySpan<byte> bootstrapDestinationConnectionId,
            out ReadOnlySpan<byte> bootstrapSourceConnectionId,
            out ReadOnlySpan<byte> bootstrapVersionSpecificData));
        Assert.Equal(1u, bootstrapVersion);
        Assert.Equal(originalDestinationConnectionId, bootstrapDestinationConnectionId.ToArray());
        Assert.Equal(initialSourceConnectionId, bootstrapSourceConnectionId.ToArray());
        Assert.True(QuicVariableLengthInteger.TryParse(
            bootstrapVersionSpecificData,
            out ulong bootstrapTokenLength,
            out int bootstrapTokenLengthBytes));
        Assert.Equal(0UL, bootstrapTokenLength);
        Assert.Equal(0, bootstrapVersionSpecificData.Slice(bootstrapTokenLengthBytes, 0).Length);
        CryptoFrameSnapshot[] bootstrapFrames = OpenInitialCryptoFrames(
            packetCoordinator,
            serverProtection,
            bootstrapDatagrams);

        int initialPacketCountBeforeRetry = 0;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets)
        {
            if (sentPacket.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial)
            {
                initialPacketCountBeforeRetry++;
            }
        }

        Assert.True(initialPacketCountBeforeRetry > 0);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                retryMetadata.RetrySourceConnectionId,
                retryMetadata.RetryToken),
            nowTicks: 1);

        QuicConnectionSendDatagramEffect[] replayDatagrams = retryResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(replayDatagrams);

        Assert.False(packetCoordinator.TryOpenInitialPacket(
            replayDatagrams[0].Datagram.Span,
            serverProtection,
            out _,
            out _,
            out _));
        Assert.True(packetCoordinator.TryOpenInitialPacket(
            replayDatagrams[0].Datagram.Span,
            retryServerProtection,
            out byte[] openedReplayPacket,
            out _,
            out _));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedReplayPacket,
            out _,
            out uint replayVersion,
            out ReadOnlySpan<byte> replayDestinationConnectionId,
            out ReadOnlySpan<byte> replaySourceConnectionId,
            out ReadOnlySpan<byte> replayVersionSpecificData));
        Assert.Equal(1u, replayVersion);
        Assert.Equal(retrySourceConnectionId, replayDestinationConnectionId.ToArray());
        Assert.Equal(initialSourceConnectionId, replaySourceConnectionId.ToArray());
        Assert.True(QuicVariableLengthInteger.TryParse(
            replayVersionSpecificData,
            out ulong retryTokenLength,
            out int retryTokenLengthBytes));
        Assert.Equal((ulong)retryToken.Length, retryTokenLength);
        Assert.True(replayVersionSpecificData.Slice(retryTokenLengthBytes, retryToken.Length).SequenceEqual(retryToken));

        CryptoFrameSnapshot[] replayFrames = OpenInitialCryptoFrames(
            packetCoordinator,
            retryServerProtection,
            replayDatagrams);

        Assert.Equal(bootstrapFrames.Length, replayFrames.Length);
        for (int index = 0; index < bootstrapFrames.Length; index++)
        {
            Assert.Equal(bootstrapFrames[index].Offset, replayFrames[index].Offset);
            Assert.Equal(bootstrapFrames[index].EncodedLength, replayFrames[index].EncodedLength);
            Assert.Equal(bootstrapFrames[index].CryptoData, replayFrames[index].CryptoData);
        }

        int initialPacketCountAfterRetry = 0;
        bool observedTrackedReplayPacket = false;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets)
        {
            if (sentPacket.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial)
            {
                initialPacketCountAfterRetry++;
                observedTrackedReplayPacket |= sentPacket.Value.CryptoMetadata.HasValue
                    && sentPacket.Value.CryptoMetadata.Value.EncryptionLevel == QuicTlsEncryptionLevel.Initial;
            }
        }

        Assert.Equal(replayDatagrams.Length, initialPacketCountAfterRetry);
        Assert.True(observedTrackedReplayPacket);

        QuicConnectionTransitionResult duplicateRetryResult = runtime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 2,
                retryMetadata.RetrySourceConnectionId,
                retryMetadata.RetryToken),
            nowTicks: 2);

        Assert.False(duplicateRetryResult.StateChanged);
        Assert.Empty(duplicateRetryResult.Effects);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryProbeAfterRetryRetainsTheRetrySelectedInitialKeysAndToken()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);

        QuicConnectionTransitionResult retryResult = runtime.Transition(retryReceivedEvent, nowTicks: 1);
        Assert.Contains(retryResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] probeDatagrams = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(2, probeDatagrams.Length);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection originalServerProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryServerProtection));

        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.All(probeDatagrams, probeDatagram =>
        {
            Assert.False(packetCoordinator.TryOpenInitialPacket(
                probeDatagram.Datagram.Span,
                originalServerProtection,
                out _,
                out _,
                out _));
            Assert.True(packetCoordinator.TryOpenInitialPacket(
                probeDatagram.Datagram.Span,
                retryServerProtection,
                out byte[] openedProbePacket,
                out _,
                out _));

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                openedProbePacket,
                out _,
                out uint probeVersion,
                out ReadOnlySpan<byte> probeDestinationConnectionId,
                out _,
                out ReadOnlySpan<byte> probeVersionSpecificData));
            Assert.Equal(1u, probeVersion);
            Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, probeDestinationConnectionId.ToArray());
            Assert.True(QuicVariableLengthInteger.TryParse(
                probeVersionSpecificData,
                out ulong retryTokenLength,
                out int retryTokenLengthBytes));
            Assert.Equal((ulong)QuicS17P2P5P2TestSupport.RetryToken.Length, retryTokenLength);
            Assert.True(QuicS17P2P5P2TestSupport.RetryToken.AsSpan().SequenceEqual(
                probeVersionSpecificData.Slice(retryTokenLengthBytes, QuicS17P2P5P2TestSupport.RetryToken.Length)));

            Assert.Contains(
                runtime.SendRuntime.SentPackets.Values,
                sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Initial
                    && sentPacket.ProbePacket
                    && sentPacket.PacketBytes.Span.SequenceEqual(probeDatagram.Datagram.Span));
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetryMetadataParserRejectsTamperedIntegrityAndZeroLengthToken()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] retryPacketDestinationConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] retrySourceConnectionId = [0x31, 0x32, 0x33];
        byte[] retryToken = [0x41, 0x42, 0x43, 0x44];

        byte[] retryPacket = CreateRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(retrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(retryToken, retryMetadata.RetryToken);

        byte[] tamperedPacket = retryPacket.ToArray();
        tamperedPacket[^1] ^= 0x80;
        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            tamperedPacket,
            out _));

        byte[] zeroTokenPacket = CreateRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            []);
        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            zeroTokenPacket,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetrySourceConnectionIdValidationRequiresThePeerBindingToMatchReplayState()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] initialSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] retrySourceConnectionId = [0x31, 0x32, 0x33];

        QuicTransportParameters peerTransportParameters = new()
        {
            OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray(),
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
            RetrySourceConnectionId = retrySourceConnectionId.ToArray(),
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            originalDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry: true,
            retrySourceConnectionId,
            peerTransportParameters,
            out QuicConnectionIdBindingValidationError validationError));
        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);

        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            originalDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry: true,
            [0x91, 0x92, 0x93],
            peerTransportParameters,
            out validationError));
        Assert.Equal(QuicConnectionIdBindingValidationError.RetrySourceConnectionIdMismatch, validationError);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OrdinaryInitialSourceConnectionIdChangesWithTheSameInitialCryptoDoNotTriggerTheRetryReplayResetPath()
    {
        // Retry replay is an explicit event under REQ-QUIC-CRT-0122; an ordinary Initial source-CID
        // change without a Retry packet must not wipe the outstanding handshake-open state when the
        // peer's offset-0 Initial CRYPTO prefix still matches the same handshake attempt.
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] initialSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] firstServerSourceConnectionId = [0x31, 0x32, 0x33, 0x34];
        byte[] secondServerSourceConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] sharedServerScalar = CreateScalar(0x33);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", "198.51.100.20", 443, 12345);

        using QuicConnectionRuntime clientRuntime = CreateClientRuntime(
            originalDestinationConnectionId,
            initialSourceConnectionId);

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(initialSourceConnectionId)),
            nowTicks: 0);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams = bootstrapResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight firstFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            firstServerSourceConnectionId,
            sharedServerScalar,
            pathIdentity,
            clientInitialDatagrams);
        ServerHandshakeFlight secondFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            secondServerSourceConnectionId,
            sharedServerScalar,
            pathIdentity,
            clientInitialDatagrams);

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged);
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstHandshakeOpenMaterial));

        _ = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                secondFlight.InitialPacket),
            nowTicks: 2);

        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeOpenMaterialAfterDifferentInitial));
        Assert.True(firstHandshakeOpenMaterial.Matches(handshakeOpenMaterialAfterDifferentInitial));

        QuicConnectionTransitionResult handshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                firstFlight.HandshakePacket),
            nowTicks: 3);

        Assert.True(handshakeResult.StateChanged, DescribeHandshakeState(clientRuntime, handshakeResult));
        Assert.Equal(QuicConnectionPhase.Active, clientRuntime.Phase);
        Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeHandshakeState(clientRuntime, handshakeResult));
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable, DescribeHandshakeState(clientRuntime, handshakeResult));
    }

    private static QuicConnectionRuntime CreateClientRuntime(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345)));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        return runtime;
    }

    private static byte[] CreateRetryPacket(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacketDestinationConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> retryToken)
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));
        return retryPacket;
    }

    private static CryptoFrameSnapshot[] OpenInitialCryptoFrames(
        QuicHandshakeFlowCoordinator packetCoordinator,
        QuicInitialPacketProtection protection,
        IEnumerable<QuicConnectionSendDatagramEffect> datagrams)
    {
        List<CryptoFrameSnapshot> frames = [];

        foreach (QuicConnectionSendDatagramEffect datagram in datagrams)
        {
            Assert.True(packetCoordinator.TryOpenInitialPacket(
                datagram.Datagram.Span,
                protection,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out QuicCryptoFrame cryptoFrame,
                out int encodedLength));

            frames.Add(new CryptoFrameSnapshot(
                cryptoFrame.Offset,
                cryptoFrame.CryptoData.ToArray(),
                encodedLength));
        }

        return frames.ToArray();
    }

    private static ServerHandshakeFlight CreateServerHandshakeFlight(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId,
        ReadOnlySpan<byte> localHandshakePrivateKey,
        QuicConnectionPathIdentity pathIdentity,
        IEnumerable<QuicConnectionSendDatagramEffect> clientInitialDatagrams)
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("server4");
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            parameterName: "serverOptions",
            listenerApplicationProtocols: [SslApplicationProtocol.Http3]);

        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: localHandshakePrivateKey.ToArray(),
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters serverTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        serverTransportParameters.OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();
        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(originalDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId(initialSourceConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));
        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: serverTransportParameters),
            nowTicks: 0).StateChanged);

        byte[]? initialPacket = null;
        byte[]? handshakePacket = null;
        long observedAtTicks = 1;
        foreach (QuicConnectionSendDatagramEffect clientInitialDatagram in clientInitialDatagrams)
        {
            QuicConnectionTransitionResult serverResult = serverRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: observedAtTicks,
                    pathIdentity,
                    clientInitialDatagram.Datagram),
                nowTicks: observedAtTicks);

            initialPacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Initial);
            handshakePacket ??= TryExtractFirstPacketBySpace(serverResult.Effects, QuicPacketNumberSpace.Handshake);
            if (initialPacket is not null && handshakePacket is not null)
            {
                break;
            }

            observedAtTicks++;
        }

        Assert.NotNull(initialPacket);
        Assert.NotNull(handshakePacket);
        return new ServerHandshakeFlight(initialPacket!, handshakePacket!);
    }

    private static byte[]? TryExtractFirstPacketBySpace(
        IEnumerable<QuicConnectionEffect> effects,
        QuicPacketNumberSpace packetNumberSpace)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            int packetOffset = 0;
            while (packetOffset < sendEffect.Datagram.Length)
            {
                ReadOnlyMemory<byte> remainingDatagram = sendEffect.Datagram[packetOffset..];
                Assert.True(QuicPacketParser.TryGetPacketLength(remainingDatagram.Span, out int packetLength));
                ReadOnlyMemory<byte> packet = remainingDatagram[..packetLength];
                if (QuicPacketParser.TryGetPacketNumberSpace(packet.Span, out QuicPacketNumberSpace observedPacketNumberSpace)
                    && observedPacketNumberSpace == packetNumberSpace)
                {
                    return packet.ToArray();
                }

                packetOffset += packetLength;
            }
        }

        return null;
    }

    private static byte[] CreateScalar(byte lastByte)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = lastByte;
        return scalar;
    }

    private static string DescribeHandshakeState(QuicConnectionRuntime runtime, QuicConnectionTransitionResult result)
    {
        return string.Join(
            " | ",
            [
                $"stateChanged={result.StateChanged}",
                $"phase={runtime.Phase}",
                $"handshakeOpenMaterial={runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _)}",
                $"peerTransportParametersCommitted={runtime.TlsState.PeerTransportParametersCommitted}",
                $"peerHandshakeTranscriptCompleted={runtime.PeerHandshakeTranscriptCompleted}",
                $"handshakeConfirmed={runtime.HandshakeConfirmed}",
                $"effects={result.Effects.Count()}",
                $"effectTypes={string.Join(",", result.Effects.Select(effect => effect.GetType().Name))}",
            ]);
    }

    private readonly record struct CryptoFrameSnapshot(
        ulong Offset,
        byte[] CryptoData,
        int EncodedLength);

    private readonly record struct ServerHandshakeFlight(
        byte[] InitialPacket,
        byte[] HandshakePacket);
}
