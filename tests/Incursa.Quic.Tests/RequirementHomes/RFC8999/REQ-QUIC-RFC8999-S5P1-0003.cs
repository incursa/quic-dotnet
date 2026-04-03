namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
public sealed class REQ_QUIC_RFC8999_S5P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    public void TryParseLongHeader_ParsesTheEncodedVersionField()
    {
        uint version = 0x11223344;
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x21],
            versionSpecificData: [0x31]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(version, header.Version);
        Assert.False(header.IsVersionNegotiation);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    public void TryParseLongHeader_RejectsPacketsMissingTheVersionField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x21],
            versionSpecificData: [0x31]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..4], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    public void TryParseLongHeader_PreservesTheMaximumVersionValue()
    {
        uint version = uint.MaxValue;
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x21],
            versionSpecificData: [0x31]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(version, header.Version);
        Assert.False(header.IsVersionNegotiation);
    }
}
