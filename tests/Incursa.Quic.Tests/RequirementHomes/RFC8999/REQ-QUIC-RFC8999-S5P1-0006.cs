namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
public sealed class REQ_QUIC_RFC8999_S5P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    public void TryParseLongHeader_ParsesTheSourceConnectionIdLengthByte()
    {
        byte[] sourceConnectionId = [0x21, 0x22, 0x23];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId,
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    public void TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            versionSpecificData: []);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..8], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    public void TryParseLongHeader_AllowsZeroLengthSourceConnectionId()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [],
            versionSpecificData: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
    }
}
