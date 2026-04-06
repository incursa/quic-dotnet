namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0013">An endpoint MUST ignore a MAX_STREAMS frame with a value that is not greater than the previously received value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0013")]
public sealed class REQ_QUIC_RFC9000_S4P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxFrames_IgnoresNonIncreasingLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(11)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 3)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}
