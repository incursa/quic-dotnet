namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1-0003")]
public sealed class REQ_QUIC_RFC9000_S8P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresDatagramsThatAreNotUniquelyAttributed()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(50, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }
}
