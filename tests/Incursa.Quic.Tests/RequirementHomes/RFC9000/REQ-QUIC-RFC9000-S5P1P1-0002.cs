namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0002")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0002")]
    public void TryParseLongHeader_ExposesTheHandshakeSourceConnectionId()
    {
        byte[] destinationConnectionId = [0x10, 0x11, 0x12];
        byte[] initialSourceConnectionId = [0x20, 0x21];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: initialSourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(initialSourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(initialSourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0002")]
    public void TryParseLongHeader_RejectsHandshakePacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..^1], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0002")]
    public void TryParseLongHeader_AllowsAZeroLengthHandshakeSourceConnectionId()
    {
        byte[] destinationConnectionId = [0x10];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }
}
