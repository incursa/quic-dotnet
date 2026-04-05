namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0020">A server MUST NOT send more than one Version Negotiation packet in response to a single UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0020")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0020">A server MUST NOT send more than one Version Negotiation packet in response to a single UDP datagram.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0020")]
    public void ShouldSendVersionNegotiation_ReturnsTrueBeforeTheServerHasAlreadySentOne()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0020">A server MUST NOT send more than one Version Negotiation packet in response to a single UDP datagram.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0020")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForASupportedClientVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0020">A server MUST NOT send more than one Version Negotiation packet in response to a single UDP datagram.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0020")]
    public void ShouldSendVersionNegotiation_ReturnsFalseAfterTheServerHasAlreadySentOne()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: true));
    }
}
