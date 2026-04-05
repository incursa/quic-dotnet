namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsTrueForAnUnsupportedClientVersion()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForASupportedClientVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForTheReservedVersionNegotiationVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));
    }
}
