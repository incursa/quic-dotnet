namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0003">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsNonVersionNegotiationPacketsWithZeroFixedBit()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x12,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21, 0x22],
            versionSpecificData: [0x33, 0x34]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
