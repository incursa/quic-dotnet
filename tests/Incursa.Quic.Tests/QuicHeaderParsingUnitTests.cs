namespace Incursa.Quic.Tests;

public sealed class QuicHeaderParsingUnitTests
{
    [Fact]
    public void TryClassifyHeaderForm_RecognizesLongAndShortPackets()
    {
        byte[] shortPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB]);
        byte[] longPacket = BuildZeroRttLongHeaderPacket(
            [0x10, 0x11],
            [0x20],
            QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]));

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(shortPacket, out QuicHeaderForm shortHeaderForm));
        Assert.Equal(QuicHeaderForm.Short, shortHeaderForm);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(longPacket, out QuicHeaderForm longHeaderForm));
        Assert.Equal(QuicHeaderForm.Long, longHeaderForm);
    }

    [Fact]
    public void TryClassifyHeaderForm_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryClassifyHeaderForm([], out _));
    }

    [Fact]
    public void TryParseLongHeader_ParsesAValidVersion1Packet()
    {
        byte[] destinationConnectionId = [0x10, 0x11];
        byte[] sourceConnectionId = [0x20];
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] packet = BuildZeroRttLongHeaderPacket(destinationConnectionId, sourceConnectionId, versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x50, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal(1u, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(2, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    public void TryParseLongHeader_RejectsTruncatedBuffers()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] packet = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: versionSpecificData,
            truncateBy: 1);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    public void TryParseLongHeader_RejectsVersion1ConnectionIdsLongerThan20Bytes()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData([0x30], [0x40, 0x41]);
        byte[] destinationTooLongPacket = BuildZeroRttLongHeaderPacket(new byte[21], [0x20], versionSpecificData);
        byte[] sourceTooLongPacket = BuildZeroRttLongHeaderPacket([0x10, 0x11], new byte[21], versionSpecificData);

        Assert.False(QuicPacketParser.TryParseLongHeader(destinationTooLongPacket, out _));
        Assert.False(QuicPacketParser.TryParseLongHeader(sourceTooLongPacket, out _));
    }

    [Fact]
    public void TryParseShortHeader_ParsesAValidShortHeaderPacket()
    {
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x64, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.True(header.SpinBit);
        Assert.True(header.KeyPhase);
        Assert.Equal((byte)0x00, header.PacketNumberLengthBits);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    public void TryParseVersionNegotiation_ParsesAValidVersionNegotiationPacket()
    {
        byte[] expectedDestinationConnectionId = [0x10, 0x11];
        byte[] expectedSourceConnectionId = [0x20];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0xAABBCCDD]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x4C, header.HeaderControlBits);
        Assert.Equal(0u, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal(2, header.DestinationConnectionIdLength);
        Assert.True(expectedDestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(1, header.SourceConnectionIdLength);
        Assert.True(expectedSourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(2, header.SupportedVersionCount);
        Assert.Equal((uint)0x11223344, header.GetSupportedVersion(0));
        Assert.Equal((uint)0xAABBCCDD, header.GetSupportedVersion(1));
    }

    [Fact]
    public void TryParseVersionNegotiation_RejectsTruncatedAndMalformedLayouts()
    {
        byte[] truncatedPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344])[..^1];

        byte[] emptyVersionListPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20]);

        byte[] misalignedVersionListPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: 0,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x11, 0x22, 0x33]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(emptyVersionListPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(misalignedVersionListPacket, out _));
    }

    private static byte[] BuildZeroRttLongHeaderPacket(
        byte[] destinationConnectionId,
        byte[] sourceConnectionId,
        byte[] versionSpecificData)
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: sourceConnectionId,
            versionSpecificData: versionSpecificData);
    }
}
