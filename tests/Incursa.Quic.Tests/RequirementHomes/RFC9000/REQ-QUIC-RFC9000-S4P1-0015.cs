namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0015">A sender that is flow control limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it has no ack-eliciting packets in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
public sealed class REQ_QUIC_RFC9000_S4P1_0015
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_ReemitsBlockedFramesWhileTheLimitRemainsClosed()
    {
        QuicConnectionStreamState connectionBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(connectionBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId connectionBlockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame firstDataBlockedFrame,
            out QuicStreamDataBlockedFrame firstStreamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, firstDataBlockedFrame.MaximumData);
        Assert.Equal(default, firstStreamDataBlockedFrame);

        Assert.False(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame repeatedDataBlockedFrame,
            out QuicStreamDataBlockedFrame repeatedStreamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, repeatedDataBlockedFrame.MaximumData);
        Assert.Equal(default, repeatedStreamDataBlockedFrame);

        Assert.True(connectionBlockedState.TryApplyMaxDataFrame(new QuicMaxDataFrame(2)));
        Assert.True(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out firstDataBlockedFrame,
            out firstStreamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, firstDataBlockedFrame);
        Assert.Equal(default, firstStreamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        QuicConnectionStreamState streamBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalStreamLimit: 1);

        Assert.True(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamBlockedStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame firstStreamsBlockedFrame));
        Assert.True(firstStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, firstStreamsBlockedFrame.MaximumStreams);

        Assert.False(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame repeatedStreamsBlockedFrame));
        Assert.True(repeatedStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, repeatedStreamsBlockedFrame.MaximumStreams);

        Assert.True(streamBlockedState.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.True(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId reopenedStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.NotEqual(streamBlockedStreamId, reopenedStreamId);
    }
}
