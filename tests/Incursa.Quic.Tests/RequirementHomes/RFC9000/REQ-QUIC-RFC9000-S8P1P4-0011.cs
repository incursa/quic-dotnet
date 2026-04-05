namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0011">If the client IP address has changed, the server MUST adhere to the anti-amplification limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0011")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresUnattributedDatagrams()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: false));
        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
    }
}
