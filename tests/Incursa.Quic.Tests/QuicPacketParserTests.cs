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
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Trait("Category", "Positive")]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit(byte[] packet, QuicHeaderForm expectedForm)
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm actualForm));
        Assert.Equal(expectedForm, actualForm);
    }

    [Fact]
    [Trait("Category", "Negative")]
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
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9002-S3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_MapsSupportedHeaderFormsToSpaces(
        byte[] packet,
        QuicPacketNumberSpace expectedPacketNumberSpace)
    {
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(expectedPacketNumberSpace, packetNumberSpace);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [Trait("Category", "Negative")]
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
