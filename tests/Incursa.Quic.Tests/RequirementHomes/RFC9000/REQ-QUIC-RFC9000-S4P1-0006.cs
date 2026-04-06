namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0006">Endpoints MUST advertise larger flow-control limits using MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS frames when the peer is permitted to send more data.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
public sealed class REQ_QUIC_RFC9000_S4P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxFrames_AdvertisesIncreasingLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
        Assert.Equal(10UL, streamSnapshot.SendLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}
