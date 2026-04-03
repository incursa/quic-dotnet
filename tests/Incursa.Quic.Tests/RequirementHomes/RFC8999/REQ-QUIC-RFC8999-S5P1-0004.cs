namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
public sealed class REQ_QUIC_RFC8999_S5P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    public void TryParseLongHeader_ParsesTheDestinationConnectionIdLengthByte()
    {
        byte[] destinationConnectionId = [0x11, 0x12, 0x13];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId: [0x21],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    public void TryParseLongHeader_RejectsPacketsMissingTheDestinationConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11, 0x12, 0x13],
            sourceConnectionId: [0x21],
            versionSpecificData: []);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..5], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    public void TryParseLongHeader_AllowsZeroLengthDestinationConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [],
            sourceConnectionId: [0x21],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.True(header.DestinationConnectionId.IsEmpty);
    }
}
