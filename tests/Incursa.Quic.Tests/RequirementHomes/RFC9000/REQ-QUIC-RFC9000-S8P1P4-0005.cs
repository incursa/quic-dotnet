namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0005">If the client IP address has changed, the server MUST adhere to the anti-amplification limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0005")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanConsumeSendBudget_TracksTheThreeToOneAntiAmplificationLimit()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(budget.CanSend(1));
        Assert.False(budget.TryConsumeSendBudget(1));

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);

        Assert.True(budget.CanSend(300));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.False(budget.CanSend(1));
    }
}
