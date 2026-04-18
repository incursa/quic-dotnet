namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0008">MAX_STREAMS frames that do not increase the stream limit MUST be ignored.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P11-0008")]
public sealed class REQ_QUIC_RFC9000_S19P11_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamsFrame_IgnoresAnEqualLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);
    }
}
