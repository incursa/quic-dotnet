namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0167">A receiver MAY advertise a larger limit for a stream by sending a MAX_STREAM_DATA frame with the corresponding stream ID.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0167")]
public sealed class REQ_QUIC_RFC9000_0167
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_AdvertisesLargerLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 12), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(12UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamDataFrame_OnlyChangesTheCorrespondingStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 4,
            peerUnidirectionalStreamLimit: 4);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId secondStreamId, out QuicStreamsBlockedFrame secondBlockedFrame));
        Assert.Equal(default, secondBlockedFrame);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshotBefore));
        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshotBefore));
        Assert.Equal(8UL, firstSnapshotBefore.SendLimit);
        Assert.Equal(8UL, secondSnapshotBefore.SendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(firstStreamId.Value, 12), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshotAfter));
        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshotAfter));
        Assert.Equal(12UL, firstSnapshotAfter.SendLimit);
        Assert.Equal(firstSnapshotBefore.ReceiveState, firstSnapshotAfter.ReceiveState);
        Assert.Equal(8UL, secondSnapshotAfter.SendLimit);
        Assert.Equal(secondSnapshotBefore.ReceiveState, secondSnapshotAfter.ReceiveState);
    }
}
