namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-6223")]
public sealed class REQ_QUIC_RFC9000_6223
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0001">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet unless it has received and successfully processed any other packet or the Version Negotiation packet lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-6222">A client MUST discard any Version Negotiation packet if it has received and successfully processed any other packet, including an earlier Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-6223">A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P12-0001">Version Negotiation packets MUST NOT contain any mechanism to prevent version downgrade attacks.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-21120001">Future versions of QUIC that use Version Negotiation packets MUST define a mechanism that is robust against version downgrade attacks.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-6222")]
    [Requirement("REQ-QUIC-RFC9000-6223")]
    [Requirement("REQ-QUIC-RFC9000-S21P12-0001")]
    [Requirement("REQ-QUIC-RFC9000-21120001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDiscardVersionNegotiation_RespectsPreviouslyProcessedPacketsAndSelectedVersions()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344,
            0xAABBCCDD);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.True(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0x11223344, true));
        Assert.True(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0x11223344, false));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0xDEADBEEF, false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-6222">A client MUST discard any Version Negotiation packet if it has received and successfully processed any other packet, including an earlier Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-6223">A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P12-0001">Version Negotiation packets MUST NOT contain any mechanism to prevent version downgrade attacks.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-21120001">Future versions of QUIC that use Version Negotiation packets MUST define a mechanism that is robust against version downgrade attacks.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-6222")]
    [Requirement("REQ-QUIC-RFC9000-6223")]
    [Requirement("REQ-QUIC-RFC9000-S21P12-0001")]
    [Requirement("REQ-QUIC-RFC9000-21120001")]
    public void ShouldKeepVersionNegotiationWhenNoEarlierPacketWasProcessedAndTheSelectedVersionIsNotListed()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344,
            0xAABBCCDD);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0xDEADBEEF, false));
    }
}
