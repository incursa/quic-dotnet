namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P2-0001">While otherwise identical to the closing state, an endpoint in the draining state MUST NOT send any packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P2-0001")]
public sealed class REQ_QUIC_RFC9000_S10P2P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryEnterDrainingState_DisablesSendingPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
        Assert.False(state.TryEnterClosingState());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryEnterDrainingState_ReturnsFalseWhenAlreadyDraining()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.TryEnterDrainingState());
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }
}
