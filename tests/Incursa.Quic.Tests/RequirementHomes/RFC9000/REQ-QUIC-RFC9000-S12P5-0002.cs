namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0002")]
public sealed class REQ_QUIC_RFC9000_S12P5_0002
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly byte[] PacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", RemotePort: 443);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParsePaddingFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildPaddingFrame();

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParsePingFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildPingFrame();

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryHandleApplicationPacketReceived_AllowsPingBeforeStreamFramesInApplicationData()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);

        byte[] applicationPayload =
        [
            .. QuicFrameTestData.BuildPingFrame(),
            .. QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0xAA], offset: 0),
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PacketPathIdentity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryHandleApplicationPacketReceived_AllowsCapturedTransferControlFramesAroundOneRttCryptoAndStreamData()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 200_000,
            localBidirectionalSendLimit: 200_000,
            localBidirectionalReceiveLimit: 200_000);
        QuicHandshakeFlowCoordinator coordinator = new(PacketSourceConnectionId, PacketConnectionId);

        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260420-232634306-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\sim\trace_node_right.pcap
        // Packet 83 was opened with SERVER_TRAFFIC_SECRET_0 from the sibling keys.log and carried:
        // NEW_TOKEN, CRYPTO, STREAM_DATA_BLOCKED, HANDSHAKE_DONE, and stream 0 data at offset 82693.
        byte[] applicationPayload = QuicCapturedInteropTransferEvidence.OpenServerApplicationPayload(
            QuicCapturedInteropTransferEvidence.QuicGoTransferPacket83Protected);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(0UL, streamId.Value);
        Assert.Equal(default, blockedFrame);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(325UL, snapshot.UniqueBytesReceived);
        Assert.Equal(325UL, snapshot.AccountedBytesReceived);
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(325, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryHandleApplicationPacketReceived_AcceptsDuplicateOneRttCryptoWhenSiblingStreamDataArrivesLater()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 200_000,
            localBidirectionalSendLimit: 200_000,
            localBidirectionalReceiveLimit: 200_000);
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0xDE, 0xAD, 0xBE, 0xEF],
            [0x01, 0x02]);
        byte[] duplicateCryptoFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, ticketMessage));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            duplicateCryptoFrame,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] firstProtectedPacket));

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                firstProtectedPacket),
            nowTicks: 10);
        Assert.True(firstResult.StateChanged);
        Assert.True(runtime.TlsState.HasPostHandshakeTicket);

        byte[] secondApplicationPayload =
        [
            .. duplicateCryptoFrame,
            .. QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0xCC, 0xDD], offset: 0),
        ];
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            secondApplicationPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] secondProtectedPacket));

        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                runtime.ActivePath!.Value.Identity,
                secondProtectedPacket),
            nowTicks: 11);

        Assert.True(secondResult.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot retransmittedSnapshot));
        Assert.Equal(2UL, retransmittedSnapshot.UniqueBytesReceived);
        Assert.Equal(2, retransmittedSnapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame initialFrame, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);
        Assert.Equal(0UL, initialFrame.Offset);
        Assert.True(initialFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame handshakeFrame, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);
        Assert.Equal(0UL, handshakeFrame.Offset);
        Assert.True(handshakeFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame applicationFrame, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
        Assert.Equal(0UL, applicationFrame.Offset);
        Assert.True(applicationFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePaddingPingAndCryptoFrames_RejectsTruncatedPayloads()
    {
        byte[] crypto = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));

        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParseCryptoFrame(crypto[..^1], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatCryptoFrame_AllowsTheZeroLengthCryptoPayloadEdge()
    {
        QuicCryptoFrame frame = new(0, []);
        Span<byte> destination = stackalloc byte[8];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(destination[..bytesWritten], out QuicCryptoFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(0UL, parsedFrame.Offset);
        Assert.True(parsedFrame.CryptoData.IsEmpty);
    }

    private static byte[] BuildProtectedInitialPacket(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            payload,
            cryptoPayloadOffset: 0,
            protection,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
