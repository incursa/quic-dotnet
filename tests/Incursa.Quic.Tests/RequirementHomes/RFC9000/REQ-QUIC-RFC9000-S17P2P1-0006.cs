namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0006
{
    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    public void TryParseVersionNegotiation_PreservesDestinationConnectionIdLengthByte(int destinationConnectionIdLength)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x6E,
            destinationConnectionId: new byte[destinationConnectionIdLength],
            sourceConnectionId: [0x21],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionIdLength);
        Assert.Equal(destinationConnectionIdLength, header.DestinationConnectionId.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    public void TryParseVersionNegotiation_RejectsTruncatedDestinationConnectionIdLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x6E,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x21],
            supportedVersions: 0x01020304);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet[..6], out _));
    }
}
