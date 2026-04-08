namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P2-0003">An endpoint MUST NOT send further packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P2-0003")]
public sealed class REQ_QUIC_RFC9000_S10P2P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryEnterClosingState_DisablesFurtherPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryEnterClosingState_ReturnsFalseAfterDraining()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.TryEnterClosingState());
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }
}
