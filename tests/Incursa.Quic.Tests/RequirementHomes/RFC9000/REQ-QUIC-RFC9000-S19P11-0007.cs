namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0007">Loss or reordering MAY cause an endpoint to receive a MAX_STREAMS frame with a lower stream limit than was previously received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P11-0007")]
public sealed class REQ_QUIC_RFC9000_S19P11_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamsFrame_IgnoresALowerLimitAfterAHigherLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(4UL, state.PeerBidirectionalStreamLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamsFrame_LeavesAStaleLowerLimitUnchanged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 3)));
        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 3)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }
}
