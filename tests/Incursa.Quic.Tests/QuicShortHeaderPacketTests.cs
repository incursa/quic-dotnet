namespace Incursa.Quic.Tests;

public sealed class QuicShortHeaderPacketTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0007")]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesOpaqueRemainder()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x3D,
            remainder: [0xA1, 0xA2, 0xA3, 0xA4]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x3D, header.HeaderControlBits);
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0007")]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0007")]
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
