namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S15-0001")]
public sealed class REQ_QUIC_RFC9000_S15_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseVersionNegotiation_PreservesSupportedVersionsAsUnsigned32BitValues()
    {
        uint firstVersion = 0x00000001;
        uint highBitVersion = 0xF0E1D2C3;
        uint secondVersion = 0xAABBCCDD;

        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersion,
            highBitVersion,
            secondVersion);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(3, header.SupportedVersionCount);
        Assert.Equal(firstVersion, header.GetSupportedVersion(0));
        Assert.Equal(highBitVersion, header.GetSupportedVersion(1));
        Assert.Equal(secondVersion, header.GetSupportedVersion(2));
        Assert.True(header.ContainsSupportedVersion(highBitVersion));
    }
}
