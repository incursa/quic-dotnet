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

        Assert.True(packetCoordinator.TryOpenInitialPacket(
            replayDatagrams[0].Datagram.Span,
            serverProtection,
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
            serverProtection,
            replayDatagrams);

        Assert.Equal(bootstrapFrames.Length, replayFrames.Length);
        for (int index = 0; index < bootstrapFrames.Length; index++)
        {
            Assert.Equal(bootstrapFrames[index].Offset, replayFrames[index].Offset);
            Assert.Equal(bootstrapFrames[index].EncodedLength, replayFrames[index].EncodedLength);
            Assert.Equal(bootstrapFrames[index].CryptoData, replayFrames[index].CryptoData);
        }

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

    private readonly record struct CryptoFrameSnapshot(
        ulong Offset,
        byte[] CryptoData,
        int EncodedLength);
}
