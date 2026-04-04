namespace Incursa.Quic.Tests;

public sealed class QuicPacketParserTests
{
    public static TheoryData<byte[], QuicHeaderForm> HeaderFormCases => new()
    {
        { QuicHeaderTestData.BuildLongHeader(0x12, 0x01020304, [0x11], [0x22], [0x33]), QuicHeaderForm.Long },
        { QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]), QuicHeaderForm.Short },
    };

    [Theory]
    [MemberData(nameof(HeaderFormCases))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0002">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0005">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2-0001">Incoming packets MUST be classified on receipt.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0003">The Header Form field MUST be 1 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0012">The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit(byte[] packet, QuicHeaderForm expectedForm)
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm actualForm));
        Assert.Equal(expectedForm, actualForm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryClassifyHeaderForm_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryClassifyHeaderForm([], out _));
    }

    public static TheoryData<byte[], byte, bool> HeaderControlBitCases => new()
    {
        { QuicHeaderTestData.BuildLongHeader(0x55, 0x01020304, [0x11, 0x12], [0x21], [0x31, 0x32]), 0x55, true },
        { QuicHeaderTestData.BuildShortHeader(0x27, [0x41, 0x42, 0x43]), 0x67, false },
    };

    [Theory]
    [MemberData(nameof(HeaderControlBitCases))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0002">The Key Phase bit MUST indicate which packet protection keys are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0005">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0006">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0016">The first byte MUST contain the Reserved and Packet Number Length bits; see also Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0008">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0009">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0002">The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0004">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0005">The Spin Bit field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0006">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0007">The Key Phase field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0016">The value included prior to protection MUST be set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0017">An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0013">The next bit (0x40) of byte 0 MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0015">The next two bits (those with a mask of 0x18) of byte 0 MUST be reserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0019">The next bit (0x04) of byte 0 MUST indicate the key phase, which allows a recipient of a packet to identify the packet protection keys that are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0020">The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S6-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseHeader_PreservesTheSevenControlBits(byte[] packet, byte expectedControlBits, bool isLongHeader)
    {
        if (isLongHeader)
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader));
            Assert.Equal(expectedControlBits, longHeader.HeaderControlBits);
            Assert.Equal((byte)(expectedControlBits & 0x03), longHeader.PacketNumberLengthBits);
            return;
        }

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket shortHeader));
        Assert.Equal(expectedControlBits, shortHeader.HeaderControlBits);
        Assert.True(shortHeader.FixedBit);
        Assert.Equal((expectedControlBits & 0x20) != 0, shortHeader.SpinBit);
        Assert.Equal((byte)((expectedControlBits & 0x18) >> 3), shortHeader.ReservedBits);
        Assert.Equal((expectedControlBits & 0x04) != 0, shortHeader.KeyPhase);
        Assert.Equal((byte)(expectedControlBits & 0x03), shortHeader.PacketNumberLengthBits);
    }

    public static TheoryData<byte[], QuicPacketNumberSpace> PacketNumberSpaceCases => new()
    {
        {
            QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]),
            QuicPacketNumberSpace.ApplicationData
        },
        {
            QuicHeaderTestData.BuildLongHeader(
                0x40,
                1,
                [0x11],
                [0x22],
                QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], [0x01], [0xBB])),
            QuicPacketNumberSpace.Initial
        },
        {
            QuicHeaderTestData.BuildLongHeader(
                0x51,
                1,
                [0x11],
                [0x22],
                QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x01], [0xBB])),
            QuicPacketNumberSpace.ApplicationData
        },
        {
            QuicHeaderTestData.BuildLongHeader(
                0x60,
                1,
                [0x11],
                [0x22],
                QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x01], [0xBB])),
            QuicPacketNumberSpace.Handshake
        },
    };

    [Theory]
    [MemberData(nameof(PacketNumberSpaceCases))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0002">The packet-level header MUST indicate the encryption level.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetPacketNumberSpace_MapsSupportedHeaderFormsToSpaces(
        byte[] packet,
        QuicPacketNumberSpace expectedPacketNumberSpace)
    {
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(expectedPacketNumberSpace, packetNumberSpace);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0002">The packet-level header MUST indicate the encryption level.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationAndRetryPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            supportedVersions: [1, 2]);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }
}
