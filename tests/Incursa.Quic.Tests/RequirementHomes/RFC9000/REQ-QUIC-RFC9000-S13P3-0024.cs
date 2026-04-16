namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0024">A new frame MUST be sent if a packet containing the most recent frame for a scope is lost, but only while the endpoint is blocked on the corresponding limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0024")]
public sealed class REQ_QUIC_RFC9000_S13P3_0024
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_RetainsBlockedPacketsAndAllowsAReplacementWhileStillBlocked()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);

        byte[] blockedPacket = QuicFrameTestData.BuildDataBlockedFrame(dataBlockedFrame);
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)blockedPacket.Length,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: blockedPacket));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(blockedPacket.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame repeatedDataBlockedFrame,
            out QuicStreamDataBlockedFrame repeatedStreamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, repeatedDataBlockedFrame.MaximumData);
        Assert.Equal(default, repeatedStreamDataBlockedFrame);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(2)));
        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
    }
}
