namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSend_ReturnsFalseBeforeAnyClientDatagramsAreReceived()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
        Assert.False(budget.TryConsumeSendBudget(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterReceivedDatagramPayloadBytes_OpensTheBudgetAfterClientTrafficArrives()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresUnattributedDatagrams()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
    }
}
