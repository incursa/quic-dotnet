namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0014">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0014
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0014">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsInitialPacketNumberLengthsWithinTheRange()
    {
        byte[] packetNumber = [0x01, 0x02, 0x03, 0x04];
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xAA],
            packetNumber,
            protectedPayload: [0xBB]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x43,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
