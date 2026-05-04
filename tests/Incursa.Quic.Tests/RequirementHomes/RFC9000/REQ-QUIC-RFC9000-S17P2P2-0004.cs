namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesTheInitialLongPacketTypeValue()
    {
        byte[] packet = QuicS17P2P2TestSupport.BuildInitialPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicLongPacketTypeBits.Initial, header.LongPacketTypeBits);
        Assert.Equal(0, (header.HeaderControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift);
    }
}
