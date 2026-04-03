namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
public sealed class REQ_QUIC_RFC8999_S5P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    public void TryParseLongHeader_AcceptsMaximumLengthDestinationConnectionId()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, byte.MaxValue).ToArray();
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId: [0x5C],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(byte.MaxValue, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    public void TryParseLongHeader_RejectsTruncatedDestinationConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId: [0xDA, 0xDB, 0xDC],
            sourceConnectionId: [0x5C],
            versionSpecificData: []);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..8], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    public void TryParseLongHeader_AllowsZeroLengthDestinationConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId: [],
            sourceConnectionId: [0x5C],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.True(header.DestinationConnectionId.IsEmpty);
    }
}
