namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P1-0003")]
public sealed class REQ_QUIC_RFC9000_S6P1_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0003">A server MAY limit the number of Version Negotiation packets it sends.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_CanLimitRepeatedResponses()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: true));
    }
}
