namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
public sealed class REQ_QUIC_RFC8999_S5P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    public void TryParseLongHeader_PreservesTheSevenVersionSpecificBits()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            versionSpecificData: [0x31, 0x32]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x4A, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
        Assert.Equal((byte)0x02, header.ReservedBits);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    public void TryParseLongHeader_RejectsShortHeadersEvenWhenTheOtherSevenBitsMatch()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x4A,
            remainder: [0xAA, 0xBB]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    public void TryParseLongHeader_PreservesAnAllZeroVersionSpecificBitField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x11223344,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x21],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x40, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x00, header.PacketNumberLengthBits);
        Assert.Equal((byte)0x00, header.TypeSpecificBits);
        Assert.Equal((byte)0x00, header.ReservedBits);
    }
}
