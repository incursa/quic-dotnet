namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0016">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0016")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0016">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0016")]
    public void ShouldSendVersionNegotiation_ReturnsTrueForAnUnsupportedClientVersionWithEnoughDatagramSpace()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0016">Version-specific rules for the connection ID therefore MUST NOT influence a decision about whether to send a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0016")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForASupportedClientVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));
    }
}
