namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0010">Once a receiver advertises a stream limit using the MAX_STREAMS frame, advertising a smaller limit MUST have no effect.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
public sealed class REQ_QUIC_RFC9000_S4P6_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamsFrame_IgnoresSmallerBidirectionalLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);
    }
}
