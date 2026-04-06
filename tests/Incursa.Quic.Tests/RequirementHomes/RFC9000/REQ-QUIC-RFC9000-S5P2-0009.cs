namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0009")]
public sealed class REQ_QUIC_RFC9000_S5P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_AcceptsVersion1Packets()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0x01], [0x02], [0xAA]));

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsDifferentProtocolVersions()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 2,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0xAA]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }
}
