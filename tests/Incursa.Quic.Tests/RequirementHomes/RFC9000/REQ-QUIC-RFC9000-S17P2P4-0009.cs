namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0009")]
    public void TryParseLongHeader_ReportsTheVersionField()
    {
        byte[] packet = BuildVersionPacket(0x01020304);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0x01020304u, header.Version);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0009")]
    public void TryParseLongHeader_RejectsPacketsMissingTheVersionField()
    {
        byte[] packet = BuildVersionPacket(0x01020304);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..4], out _));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(0xFFFFFFFFu)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P4-0009")]
    public void TryParseLongHeader_PreservesBoundaryVersionValues(uint version)
    {
        byte[] packet = BuildVersionPacket(version);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(version, header.Version);
    }

    private static byte[] BuildVersionPacket(uint version)
    {
        return version == 0
            ? QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: 0x00,
                destinationConnectionId: [0x10],
                sourceConnectionId: [0x20],
                supportedVersions: [1u])
            : QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version,
                destinationConnectionId: [0x10],
                sourceConnectionId: [0x20],
                versionSpecificData: [0xAA]);
    }
}
