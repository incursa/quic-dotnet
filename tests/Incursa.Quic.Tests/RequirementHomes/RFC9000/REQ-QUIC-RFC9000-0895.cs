namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0895")]
public sealed class REQ_QUIC_RFC9000_0895
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsSupportedVersionListsThatAreNotWholeUInt32Values()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x00000001]);

        byte[] nonWholeVersionList = [.. packet, 0xFF];

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(nonWholeVersionList, out _));
    }
}
