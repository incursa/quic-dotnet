namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0008")]
    public void TryParseVersionNegotiation_PreservesARepresentativeSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.Equal(1, header.SourceConnectionId.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0008")]
    public void TryParseVersionNegotiation_PreservesBoundarySourceConnectionIdLengthBytes(int sourceConnectionIdLength)
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
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0008")]
    public void TryParseVersionNegotiation_RejectsPacketsMissingTheSourceConnectionIdLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet[..7], out _));
    }
}
