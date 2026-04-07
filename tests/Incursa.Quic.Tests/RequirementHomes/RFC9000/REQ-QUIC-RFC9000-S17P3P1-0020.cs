namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0020">The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0020")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_EncodesThePacketNumberLengthAsOneLessThanTheFieldLength()
    {
        byte[] remainder = [0xA1, 0xB2, 0xC3];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x02, remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
        Assert.Equal(remainder.Length, header.Remainder.Length);
    }
}
