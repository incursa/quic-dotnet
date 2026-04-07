namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P2P2-0004")]
public sealed class REQ_QUIC_RFC9000_S10P2P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryEnterClosingState_ThenTryEnterDrainingState_ReplacesClosingWithDrainingAndStopsSendingPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.IsDraining);

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.IsClosing);
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }
}
