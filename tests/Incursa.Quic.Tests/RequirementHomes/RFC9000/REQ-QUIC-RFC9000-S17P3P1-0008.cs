namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0008
{
    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x01)]
    [InlineData((byte)0x02)]
    [InlineData((byte)0x03)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ReportsThePacketNumberLengthBits(byte packetNumberLengthBits)
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(packetNumberLengthBits, [0xA1, 0xB2, 0xC3, 0xD4]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(packetNumberLengthBits, header.PacketNumberLengthBits);
    }
}
