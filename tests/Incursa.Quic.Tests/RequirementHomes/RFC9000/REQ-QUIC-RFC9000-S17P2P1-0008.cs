namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0008
{
    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    public void TryParseVersionNegotiation_PreservesSourceConnectionIdLengthByte(int sourceConnectionIdLength)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: new byte[sourceConnectionIdLength],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionIdLength);
        Assert.Equal(sourceConnectionIdLength, header.SourceConnectionId.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    public void TryParseVersionNegotiation_RejectsTruncatedSourceConnectionIdLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet[..8], out _));
    }
}
