namespace Incursa.Quic.Tests;

public sealed class QuicAntiAmplificationBudgetTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P1P1P1-0002">Endpoints MUST NOT send data toward an unvalidated address in excess of three times the data received from that address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0008">The server MUST also limit the number of bytes it sends before validating the address of the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8-0001">After receiving packets from an address that is not yet validated, an endpoint MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from that address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0002">Prior to validating the client address, servers MUST NOT send more than three times as many bytes as the number of bytes they have received.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S21P1P1P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S14P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSend_TracksTheThreeTimesAmplificationCapUntilValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
        Assert.False(budget.CanSend(301));

        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(300UL, budget.SentPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
        Assert.False(budget.TryConsumeSendBudget(1));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8-0001">After receiving packets from an address that is not yet validated, an endpoint MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(budget.TryRegisterReceivedDatagramPayloadBytes(-1, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.False(budget.CanSend(-1));
        Assert.False(budget.TryConsumeSendBudget(-1));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0003">For the purposes of avoiding amplification prior to address validation, servers MUST count all of the payload bytes received in datagrams that are uniquely attributed to a single connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresDatagramsThatAreNotUniquelyAttributed()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(50, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P1P1P1-0002">Endpoints MUST NOT send data toward an unvalidated address in excess of three times the data received from that address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0008">The server MUST also limit the number of bytes it sends before validating the address of the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8-0001">After receiving packets from an address that is not yet validated, an endpoint MUST limit the amount of data it sends to the unvalidated address to three times the amount of data received from that address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S21P1P1P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S14P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
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
