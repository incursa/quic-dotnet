namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P1-0001">A packet MUST NOT be acknowledged until packet protection has been successfully removed and all frames contained in the packet have been processed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P1-0001")]
public sealed class REQ_QUIC_RFC9000_S13P1_0001
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly byte[] PacketSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_AcknowledgesThePacketOnlyAfterItsFramesAreProcessed()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreateApplicationCoordinator();
        byte[] applicationPayload =
        [
            .. QuicS12P3TestSupport.CreatePingPayload(),
            .. QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);

        ReadOnlySpan<byte> streamPayload = payload[pingBytesConsumed..];
        Assert.True(QuicStreamParser.TryParseStreamFrame(streamPayload, out QuicStreamFrame streamFrame));

        ReadOnlySpan<byte> trailingPayload = streamPayload[streamFrame.ConsumedLength..];
        while (!trailingPayload.IsEmpty)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(trailingPayload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            trailingPayload = trailingPayload[paddingBytesConsumed..];
        }

        QuicConnectionStreamState streamState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);
        Assert.True(streamState.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(streamState.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(2, snapshot.BufferedReadableBytes);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

        QuicSenderFlowController tracker = new();
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));
        Assert.Equal(packetNumber, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsTamperingBeforeAnyReceiptIsRecorded()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreateApplicationCoordinator();
        byte[] applicationPayload =
        [
            .. QuicFrameTestData.BuildPaddingFrame(),
            .. QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            out byte[] protectedPacket));

        protectedPacket[^1] ^= 0x01;

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _,
            out _));

        QuicSenderFlowController tracker = new();
        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenProtectedApplicationDataPacket_ProcessesTrailingPaddingBeforeRecordingAckEligibility()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreateApplicationCoordinator();
        byte[] applicationPayload =
        [
            .. QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            .. QuicFrameTestData.BuildPaddingFrame(),
        ];

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out _));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame streamFrame));
        Assert.Equal(2, streamFrame.StreamDataLength);

        ReadOnlySpan<byte> trailingPayload = payload[streamFrame.ConsumedLength..];
        while (!trailingPayload.IsEmpty)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(trailingPayload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            trailingPayload = trailingPayload[paddingBytesConsumed..];
        }

        QuicConnectionStreamState streamState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);
        Assert.True(streamState.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        QuicSenderFlowController tracker = new();
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros: 2_000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_200,
            out QuicAckFrame frame));
        Assert.Equal(packetNumber, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    private static QuicHandshakeFlowCoordinator CreateApplicationCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId, PacketSourceConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(PacketConnectionId));
        return coordinator;
    }
}
