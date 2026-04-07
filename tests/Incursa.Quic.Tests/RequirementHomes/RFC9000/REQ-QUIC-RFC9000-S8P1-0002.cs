namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0002">Prior to validating the client address, servers MUST NOT send more than three times as many bytes as the number of bytes they have received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1-0002")]
public sealed class REQ_QUIC_RFC9000_S8P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSend_RejectsDataBeyondThePreValidationBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
    }
}
