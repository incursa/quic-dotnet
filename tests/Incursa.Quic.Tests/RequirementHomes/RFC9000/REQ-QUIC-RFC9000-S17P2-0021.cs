namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0021")]
public sealed class REQ_QUIC_RFC9000_S17P2_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsVersion1DestinationConnectionIdAt20Bytes()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, 20).ToArray();
        byte[] sourceConnectionId = [0x5C];
        byte[] versionSpecificData = BuildValidVersion1VersionSpecificData(0x41);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(20, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    private static byte[] BuildValidVersion1VersionSpecificData(byte headerControlBits)
    {
        int packetNumberLength = (headerControlBits & 0x03) + 1;
        byte[] packetNumber = Enumerable.Range(0, packetNumberLength).Select(index => (byte)(index + 1)).ToArray();
        byte[] protectedPayload = [0xFA];
        return (headerControlBits & 0x30) == 0x10
            ? QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload)
            : QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], packetNumber, protectedPayload);
    }
}
