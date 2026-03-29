namespace Incursa.Quic.Tests;

public sealed class QuicVersionNegotiationPacketTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0007")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0013")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0019")]
    [Trait("Category", "Positive")]
    public void TryParseVersionNegotiation_ExposesSupportedVersions()
    {
        byte[] destinationConnectionId = [0x01, 0x02];
        byte[] sourceConnectionId = [0x03, 0x04, 0x05];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x6E,
            destinationConnectionId,
            sourceConnectionId,
            0x00000001,
            0x11223344,
            0xAABBCCDD);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x6E, header.HeaderControlBits);
        Assert.Equal((uint)0, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(3, header.SupportedVersionCount);
        Assert.Equal((uint)0x00000001, header.GetSupportedVersion(0));
        Assert.Equal((uint)0x11223344, header.GetSupportedVersion(1));
        Assert.Equal((uint)0xAABBCCDD, header.GetSupportedVersion(2));
        int supportedVersionOffset = 1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length;
        Assert.True(packet.AsSpan(supportedVersionOffset).SequenceEqual(header.SupportedVersionBytes));

        bool threw = false;
        try
        {
            _ = header.GetSupportedVersion(3);
        }
        catch (ArgumentOutOfRangeException)
        {
            threw = true;
        }

        Assert.True(threw);
    }

    [Fact]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsNegativeSupportedVersionIndex()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x5A,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: 0x01020304);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));

        bool threw = false;
        try
        {
            _ = header.GetSupportedVersion(-1);
        }
        catch (ArgumentOutOfRangeException)
        {
            threw = true;
        }

        Assert.True(threw);
    }

    [Fact]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseVersionNegotiation([], out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsShortHeaderForm()
    {
        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x00,
            remainder: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(shortHeader, out _));
    }

    [Fact]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsPacketsWithoutSupportedVersions()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x01,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            supportedVersions: []);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsTruncatedSupportedVersions(int truncateBy)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x7F,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            supportedVersions: 0x01020304);

        byte[] truncatedPacket = packet[..^truncateBy];

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsOrdinaryLongHeaders()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x21,
            version: 0x01020304,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33, 0x44, 0x55, 0x66]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }
}
