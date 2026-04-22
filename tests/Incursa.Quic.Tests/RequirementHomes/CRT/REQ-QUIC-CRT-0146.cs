using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0146")]
public sealed class REQ_QUIC_CRT_0146
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplacementInitialCryptoFromANewPeerAttemptResetsTheClientHandshakeAttempt()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] initialSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] firstServerSourceConnectionId = [0x31, 0x32, 0x33, 0x34];
        byte[] replacementServerSourceConnectionId = [0x41, 0x42, 0x43, 0x44];
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
            CreateScalar(0x21),
            pathIdentity,
            clientInitialDatagrams);
        ServerHandshakeFlight replacementFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            replacementServerSourceConnectionId,
            CreateScalar(0x22),
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
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(firstServerSourceConnectionId),
            DescribeState(clientRuntime, firstInitialResult));

        QuicConnectionTransitionResult replacementInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                replacementFlight.InitialPacket),
            nowTicks: 2);
        Assert.True(replacementInitialResult.StateChanged, DescribeState(clientRuntime, replacementInitialResult));
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial replacementHandshakeOpenMaterial));
        Assert.False(firstHandshakeOpenMaterial.Matches(replacementHandshakeOpenMaterial));
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(replacementServerSourceConnectionId),
            DescribeState(clientRuntime, replacementInitialResult));

        QuicConnectionTransitionResult replacementHandshakeResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                replacementFlight.HandshakePacket),
            nowTicks: 3);

        Assert.True(replacementHandshakeResult.StateChanged, DescribeState(clientRuntime, replacementHandshakeResult));
        Assert.True(clientRuntime.Phase == QuicConnectionPhase.Active, DescribeState(clientRuntime, replacementHandshakeResult));
        Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted, DescribeState(clientRuntime, replacementHandshakeResult));
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable, DescribeState(clientRuntime, replacementHandshakeResult));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DifferentPeerInitialSourceConnectionIdsDoNotResetWhenTheInitialCryptoPrefixIsTheSame()
    {
        byte[] originalDestinationConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] initialSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] firstServerSourceConnectionId = [0x71, 0x72, 0x73, 0x74];
        byte[] replayedServerSourceConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] sharedServerScalar = CreateScalar(0x33);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.11", "198.51.100.21", 443, 12346);

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
        ServerHandshakeFlight sameCryptoDifferentSourceFlight = CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            initialSourceConnectionId,
            replayedServerSourceConnectionId,
            sharedServerScalar,
            pathIdentity,
            clientInitialDatagrams);

        Assert.Equal(
            Convert.ToHexString(firstFlight.InitialCryptoPayload),
            Convert.ToHexString(sameCryptoDifferentSourceFlight.InitialCryptoPayload));

        QuicConnectionTransitionResult firstInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                firstFlight.InitialPacket),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged);
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstHandshakeOpenMaterial));

        QuicConnectionTransitionResult replayedInitialResult = clientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                sameCryptoDifferentSourceFlight.InitialPacket),
            nowTicks: 2);
        Assert.True(replayedInitialResult.StateChanged, DescribeState(clientRuntime, replayedInitialResult));
        Assert.True(
            clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial replayedHandshakeOpenMaterial));
        Assert.True(firstHandshakeOpenMaterial.Matches(replayedHandshakeOpenMaterial));
        Assert.True(
            clientRuntime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(firstServerSourceConnectionId),
            DescribeState(clientRuntime, replayedInitialResult));
    }

    private static QuicConnectionRuntime CreateClientRuntime(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            remoteCertificateValidationCallback: static (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            clientAuthenticationOptions: new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                TargetHost = "server4",
            },
            tlsRole: QuicTlsRole.Client);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(new QuicConnectionPathIdentity("203.0.113.1", "198.51.100.1", 443, 12345)));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId));
        return runtime;
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
        byte[]? initialCryptoPayload = null;
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
            if (initialPacket is not null && initialCryptoPayload is null)
            {
                initialCryptoPayload = TryExtractFirstCryptoFramePayloadFromInitial(
                    originalDestinationConnectionId,
                    initialPacket);
            }

            if (initialPacket is not null && handshakePacket is not null && initialCryptoPayload is not null)
            {
                break;
            }

            observedAtTicks++;
        }

        Assert.NotNull(initialPacket);
        Assert.NotNull(handshakePacket);
        Assert.NotNull(initialCryptoPayload);
        return new ServerHandshakeFlight(initialPacket!, handshakePacket!, initialCryptoPayload!);
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

    private static byte[] TryExtractFirstCryptoFramePayloadFromInitial(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> initialPacket)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            initialPacket,
            protection,
            requireZeroTokenLength: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);

        int frameOffset = 0;
        while (frameOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[frameOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                frameOffset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                frameOffset += ackBytesConsumed;
                continue;
            }

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out _));
            return cryptoFrame.CryptoData.ToArray();
        }

        Assert.Fail("The server Initial did not contain a CRYPTO frame.");
        return [];
    }

    private static byte[] CreateScalar(byte lastByte)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = lastByte;
        return scalar;
    }

    private static string DescribeState(QuicConnectionRuntime runtime, QuicConnectionTransitionResult result)
    {
        return string.Join(
            " | ",
            [
                $"stateChanged={result.StateChanged}",
                $"phase={runtime.Phase}",
                $"peerDestinationConnectionId={Convert.ToHexString(runtime.CurrentPeerDestinationConnectionId.ToArray())}",
                $"handshakeOpenMaterial={runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _)}",
                $"peerTransportParametersCommitted={runtime.TlsState.PeerTransportParametersCommitted}",
                $"peerHandshakeTranscriptCompleted={runtime.PeerHandshakeTranscriptCompleted}",
                $"oneRttKeys={runtime.TlsState.OneRttKeysAvailable}",
                $"fatalAlertCode={runtime.TlsState.FatalAlertCode}",
                $"fatalAlertDescription={runtime.TlsState.FatalAlertDescription ?? "<null>"}",
                $"effects={result.Effects.Count()}",
                $"effectTypes={string.Join(",", result.Effects.Select(effect => effect.GetType().Name))}",
            ]);
    }

    private readonly record struct ServerHandshakeFlight(
        byte[] InitialPacket,
        byte[] HandshakePacket,
        byte[] InitialCryptoPayload);
}
