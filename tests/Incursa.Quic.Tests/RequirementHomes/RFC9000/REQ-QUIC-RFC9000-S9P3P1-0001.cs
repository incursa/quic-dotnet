namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
public sealed class REQ_QUIC_RFC9000_S9P3P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_AllowsUnlimitedSendingAfterAddressValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        budget.MarkAddressValidated();

        Assert.True(budget.IsAddressValidated);
        Assert.True(budget.CanSend(int.MaxValue));
        Assert.True(budget.TryConsumeSendBudget(int.MaxValue));
        Assert.Equal((ulong)int.MaxValue, budget.SentPayloadBytes);
        Assert.Equal(ulong.MaxValue, budget.RemainingSendBudget);
    }
}
