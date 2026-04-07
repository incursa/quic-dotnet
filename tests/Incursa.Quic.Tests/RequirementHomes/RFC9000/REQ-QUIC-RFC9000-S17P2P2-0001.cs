namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0001">An Initial packet MUST use long headers with a type value of 0x00.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0012">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0013">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0014">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0015">The Initial packet MUST contain a long header as well as the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0017">The Token Length field MUST be variable-length integer specifying the length of the Token field, in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AcceptsVersion1InitialPacketsWithValidStructuralFields()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA0, 0xA1],
            packetNumber: [0x01, 0x02, 0x03],
            protectedPayload: [0xB0, 0xB1]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11, 0x12],
            sourceConnectionId: [0x20, 0x21],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0001">QUIC transmissions MUST be sent with a packet-level header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0003">The packet-level header MUST include a packet sequence number.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0002">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0003">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0004">The Long Packet Type field MUST be 2 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0005">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0006">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0007">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0016">The first byte MUST contain the Reserved and Packet Number Length bits; see also Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0001">During the handshake, packets with the long header MUST be used to establish the connection IDs used by both endpoints.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0008">Packets with long headers MUST include Source Connection ID and Destination Connection ID fields.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9002-S3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S7P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_RoundTripsLengthEncodedConnectionIdsAndPayload()
    {
        byte[] destinationConnectionId = [0x10, 0x11, 0x12];
        byte[] sourceConnectionId = [0x20, 0x21];
        byte[] versionSpecificData = [0x30, 0x31, 0x32, 0x33];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x4A, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
        Assert.Equal((byte)0x02, header.ReservedBits);
        Assert.Equal((uint)0x11223344, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
