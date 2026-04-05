namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2P1-0002">When the server receives a datagram from the client, the amplification limit increases and the server MUST reset the PTO timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterReceivedDatagramPayloadBytes_RestoresTheSendBudgetAfterTheServerHasExhaustedIt()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(0UL, budget.RemainingSendBudget);

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1, uniquelyAttributedToSingleConnection: true));

        Assert.Equal(101UL, budget.ReceivedPayloadBytes);
        Assert.Equal(3UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(3));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterReceivedDatagramPayloadBytes_DoesNotRestoreTheSendBudgetForUnattributedDatagrams()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(0UL, budget.RemainingSendBudget);

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryRegisterReceivedDatagramPayloadBytes_LeavesTheSendBudgetExhaustedForZeroLengthDatagrams()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(0UL, budget.RemainingSendBudget);

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(0, uniquelyAttributedToSingleConnection: true));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
    }
}
