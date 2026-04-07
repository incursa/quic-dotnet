namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0001">A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0012">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0014">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0015">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0016">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AcceptsVersion1ZeroRttPacketsWithValidStructuralFields()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0, 0xB1, 0xB2]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x51,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21, 0x22],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
