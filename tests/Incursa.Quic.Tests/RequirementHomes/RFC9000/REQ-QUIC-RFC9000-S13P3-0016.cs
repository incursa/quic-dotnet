namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0016">An updated value MUST be sent in a MAX_DATA frame if the packet containing the most recently sent MAX_DATA frame is declared lost or when the endpoint decides to update the limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
public sealed class REQ_QUIC_RFC9000_S13P3_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_UpdatesTheCurrentConnectionMaximumDataWhenAdditionalBytesAreRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[3];
        Assert.True(state.TryReadStreamData(
            1,
            destination[..2],
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame firstMaxDataFrame,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(18UL, firstMaxDataFrame.MaximumData);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 5, [0x33, 0x44, 0x55], offset: 0),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReadStreamData(
            5,
            destination,
            out bytesWritten,
            out completed,
            out QuicMaxDataFrame secondMaxDataFrame,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.False(completed);
        Assert.Equal(21UL, secondMaxDataFrame.MaximumData);
        Assert.Equal(21UL, state.ConnectionReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_SendsTheUpdatedConnectionMaximumDataWhenTheResetReleasesBufferedBytes()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(18UL, state.ConnectionReceiveLimit);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(5UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_LeavesTheConnectionMaximumDataUnchangedWhenNoBufferedBytesAreReleased()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame readMaxDataFrame,
            out QuicMaxStreamDataFrame readMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(18UL, readMaxDataFrame.MaximumData);
        Assert.Equal(10UL, readMaxStreamDataFrame.MaximumStreamData);
        Assert.Equal(18UL, state.ConnectionReceiveLimit);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0, snapshot.BufferedReadableBytes);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 2),
            out QuicMaxDataFrame resetMaxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, resetMaxDataFrame);
        Assert.Equal(18UL, state.ConnectionReceiveLimit);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_QueuesTheMostRecentMaxDataPacketForRepairUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(18));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(packet, out QuicMaxDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(18UL, frame.MaximumData);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_DoesNotRetainTheMostRecentMaxDataFrameForRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(18));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(packet, out QuicMaxDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(18UL, frame.MaximumData);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 125,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }
}
