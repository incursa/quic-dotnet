namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC8999_S5P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    public void TryParseLongHeader_AcceptsMaximumLengthConnectionIds()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, byte.MaxValue).ToArray();
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, byte.MaxValue).ToArray();
        byte[] versionSpecificData = [0x10, 0x20, 0x30];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(byte.MaxValue, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(byte.MaxValue, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
