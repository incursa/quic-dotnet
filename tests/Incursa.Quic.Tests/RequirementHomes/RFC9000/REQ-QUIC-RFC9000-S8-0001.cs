namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8-0001">After receiving packets from an address that is not yet validated, an endpoint MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from that address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8-0001")]
public sealed class REQ_QUIC_RFC9000_S8_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_TracksTheThreeTimesAmplificationCapUntilValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
        Assert.False(budget.CanSend(301));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(budget.TryRegisterReceivedDatagramPayloadBytes(-1, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.False(budget.CanSend(-1));
        Assert.False(budget.TryConsumeSendBudget(-1));
    }
}
