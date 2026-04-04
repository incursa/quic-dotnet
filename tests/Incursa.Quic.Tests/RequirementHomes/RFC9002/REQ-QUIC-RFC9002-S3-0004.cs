namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0004")]
public sealed class REQ_QUIC_RFC9002_S3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    public void TryGetPacketNumberSpace_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = [0x40];

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }
}
