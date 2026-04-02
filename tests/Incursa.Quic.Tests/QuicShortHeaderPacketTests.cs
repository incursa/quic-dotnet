namespace Incursa.Quic.Tests;

public sealed class QuicShortHeaderPacketTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0020")]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesOpaqueRemainder()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x65,
            remainder: [0xA1, 0xA2, 0xA3, 0xA4]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x65, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.True(header.SpinBit);
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.True(header.KeyPhase);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0014")]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsFixedBitZero()
    {
        byte[] packet = [0x3D, 0xA1, 0xA2, 0xA3];

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsReservedBitsNonZero()
    {
        byte[] packet = [0x5D, 0xA1, 0xA2, 0xA3];

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsLongHeaderForm()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x01,
            version: 0x01020304,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }
}
