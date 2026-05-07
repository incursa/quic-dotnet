namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0004
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseVersionNegotiation_PreservesTheSevenUnusedControlBits()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x7F,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal((byte)0x7F, header.HeaderControlBits);
    }
}
