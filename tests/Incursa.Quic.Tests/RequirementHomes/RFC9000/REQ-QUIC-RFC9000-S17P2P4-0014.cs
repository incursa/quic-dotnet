namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P4-0014")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsInitialPacketsWhoseLengthFieldFitsInOneVarintByte()
    {
        byte[] packet = BuildInitialPacket(protectedPayloadLength: 0);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsWhoseLengthFieldIsTruncatedMidVarint()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x00, 0x40]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_AcceptsInitialPacketsWhoseLengthFieldRequiresTwoVarintBytes()
    {
        byte[] packet = BuildInitialPacket(protectedPayloadLength: 64);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    private static byte[] BuildInitialPacket(int protectedPayloadLength)
    {
        byte[] protectedPayload = new byte[protectedPayloadLength];

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], protectedPayload));
    }
}
