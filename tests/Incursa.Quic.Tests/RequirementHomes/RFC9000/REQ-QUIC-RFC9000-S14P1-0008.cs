namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0008">The server MUST also limit the number of bytes it sends before validating the address of the client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0008")]
public sealed class REQ_QUIC_RFC9000_S14P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryConsumeSendBudget_RejectsPayloadsThatExceedTheRemainingBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(300UL, budget.RemainingSendBudget);

        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.SentPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }
}
