namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P1-0008">An endpoint MUST enter the closing state after initiating an immediate close.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P1-0008")]
public sealed class REQ_QUIC_RFC9000_S10P2P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryEnterClosingState_EntersClosingStateAfterImmediateClose()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryEnterClosingState_ReturnsFalseWhenAlreadyClosingOrDraining()
    {
        QuicConnectionLifecycleState closingState = new();

        Assert.True(closingState.TryEnterClosingState());
        Assert.False(closingState.TryEnterClosingState());
        Assert.True(closingState.IsClosing);

        QuicConnectionLifecycleState drainingState = new();

        Assert.True(drainingState.TryEnterDrainingState());
        Assert.False(drainingState.TryEnterClosingState());
        Assert.True(drainingState.IsDraining);
    }
}
