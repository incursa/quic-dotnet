namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P2P2-0001")]
public sealed class REQ_QUIC_RFC9000_S10P2P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryEnterDrainingState_DisablesSendingPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
        Assert.False(state.TryEnterClosingState());
    }
}
