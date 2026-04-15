namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0021">Like MAX_DATA, an updated value MUST be sent when a packet containing the most recent MAX_STREAMS for a stream type frame is declared lost or when the limit is updated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0021")]
public sealed class REQ_QUIC_RFC9000_S13P3_0021
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0021")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryPeekPeerStreamCapacityRelease_KeepsTheSameUnidirectionalStreamLimitAvailableUntilCommitted()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame firstReleaseFrame));
        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame secondReleaseFrame));
        Assert.Equal(firstReleaseFrame, secondReleaseFrame);
        Assert.Equal(2UL, firstReleaseFrame.MaximumStreams);

        Assert.True(state.TryCommitPeerStreamCapacityRelease(3, firstReleaseFrame));
        Assert.False(state.TryPeekPeerStreamCapacityRelease(3, out _));
        Assert.Equal(2UL, state.IncomingUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0021")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_QueuesTheMostRecentMaxStreamsPacketForRepairUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(false, 2));
        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(packet, out QuicMaxStreamsFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.False(frame.IsBidirectional);
        Assert.Equal(2UL, frame.MaximumStreams);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 13,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 300,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            13,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(13UL, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }
}
