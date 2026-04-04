namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P2-0013")]
public sealed class REQ_QUIC_RFC9000_S12P2_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_TreatsRetryPacketsAsOpaqueTrailingDataSoTheyCannotBeFollowedByAnotherPacket()
    {
        byte[] retryVersionSpecificData = [0x30, 0x31, 0x32, 0x33];
        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x73,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            retryVersionSpecificData);
        byte[] trailingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0x40, 0x41, 0x42]);
        byte[] datagram = [.. retryPacket, .. trailingPacket];

        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
        Assert.Equal(retryVersionSpecificData.Length + trailingPacket.Length, header.VersionSpecificData.Length);
        Assert.True(trailingPacket.AsSpan().SequenceEqual(header.VersionSpecificData.Slice(retryVersionSpecificData.Length)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_TreatsSubsequentPacketsAsPartOfTheSupportedVersionList()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0x55667788]);
        byte[] trailingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0x60, 0x61, 0x62]);
        byte[] datagram = [.. versionNegotiationPacket, .. trailingPacket];

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(datagram, out QuicVersionNegotiationPacket header));
        Assert.Equal(3, header.SupportedVersionCount);
        Assert.Equal(12, header.SupportedVersionBytes.Length);
        Assert.True(trailingPacket.AsSpan().SequenceEqual(header.SupportedVersionBytes.Slice(8)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsStandaloneRetryAndVersionNegotiationPackets()
    {
        byte[] retryVersionSpecificData = [0x30, 0x31, 0x32, 0x33];
        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x73,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            retryVersionSpecificData);
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0x55667788]);

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.True(retryVersionSpecificData.AsSpan().SequenceEqual(retryHeader.VersionSpecificData));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out QuicVersionNegotiationPacket versionNegotiationHeader));
        Assert.Equal(2, versionNegotiationHeader.SupportedVersionCount);
        Assert.Equal(8, versionNegotiationHeader.SupportedVersionBytes.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AllowsTheSmallestRetryAndVersionNegotiationDatagrams()
    {
        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x73,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            [0x30]);
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344]);

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.Equal(1, retryHeader.VersionSpecificData.Length);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out QuicVersionNegotiationPacket versionNegotiationHeader));
        Assert.Equal(1, versionNegotiationHeader.SupportedVersionCount);
        Assert.Equal(4, versionNegotiationHeader.SupportedVersionBytes.Length);
    }
}
