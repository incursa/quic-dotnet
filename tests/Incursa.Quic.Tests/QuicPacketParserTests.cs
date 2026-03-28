namespace Incursa.Quic.Tests;

public sealed class QuicPacketParserTests
{
    public static TheoryData<byte[], QuicHeaderForm> HeaderFormCases => new()
    {
        { QuicHeaderTestData.BuildLongHeader(0x12, 0x01020304, [0x11], [0x22], [0x33]), QuicHeaderForm.Long },
        { QuicHeaderTestData.BuildShortHeader(0x34, [0xAA, 0xBB, 0xCC]), QuicHeaderForm.Short },
    };

    [Theory]
    [MemberData(nameof(HeaderFormCases))]
    [Trait("Requirement", "REQ-QUIC-HDR-0001")]
    [Trait("Category", "Positive")]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit(byte[] packet, QuicHeaderForm expectedForm)
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm actualForm));
        Assert.Equal(expectedForm, actualForm);
    }

    public static TheoryData<byte[], byte, bool> HeaderControlBitCases => new()
    {
        { QuicHeaderTestData.BuildLongHeader(0x55, 0x01020304, [0x11, 0x12], [0x21], [0x31, 0x32]), 0x55, true },
        { QuicHeaderTestData.BuildShortHeader(0x66, [0x41, 0x42, 0x43]), 0x66, false },
    };

    [Theory]
    [MemberData(nameof(HeaderControlBitCases))]
    [Trait("Requirement", "REQ-QUIC-HDR-0002")]
    [Trait("Category", "Positive")]
    public void TryParseHeader_PreservesTheSevenControlBits(byte[] packet, byte expectedControlBits, bool isLongHeader)
    {
        if (isLongHeader)
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader));
            Assert.Equal(expectedControlBits, longHeader.HeaderControlBits);
            return;
        }

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket shortHeader));
        Assert.Equal(expectedControlBits, shortHeader.HeaderControlBits);
    }
}
