namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9369-S3-0001")]
public sealed class REQ_QUIC_RFC9369_S3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetLongHeaderPacketType_MapsVersion2PacketTypeBits()
    {
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x01,
            out QuicLongPacketType initialPacketType));
        Assert.Equal(QuicLongPacketType.Initial, initialPacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x02,
            out QuicLongPacketType zeroRttPacketType));
        Assert.Equal(QuicLongPacketType.ZeroRtt, zeroRttPacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x03,
            out QuicLongPacketType handshakePacketType));
        Assert.Equal(QuicLongPacketType.Handshake, handshakePacketType);

        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            QuicVersionNegotiation.Version2,
            0x00,
            out QuicLongPacketType retryPacketType));
        Assert.Equal(QuicLongPacketType.Retry, retryPacketType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsVersion2InitialAndHandshakePackets()
    {
        byte[] initialPacket = BuildVersion2InitialPacket();
        byte[] handshakePacket = BuildVersion2HandshakePacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket, out QuicLongHeaderPacket initialHeader));
        Assert.Equal(QuicVersionNegotiation.Version2, initialHeader.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            initialHeader.Version,
            initialHeader.LongPacketTypeBits,
            out QuicLongPacketType initialPacketType));
        Assert.Equal(QuicLongPacketType.Initial, initialPacketType);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket, out QuicLongHeaderPacket handshakeHeader));
        Assert.Equal(QuicVersionNegotiation.Version2, handshakeHeader.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            handshakeHeader.Version,
            handshakeHeader.LongPacketTypeBits,
            out QuicLongPacketType handshakePacketType));
        Assert.Equal(QuicLongPacketType.Handshake, handshakePacketType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsVersion2RetryPackets()
    {
        byte[] retryPacket = BuildVersion2RetryPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
        Assert.Equal(QuicVersionNegotiation.Version2, header.Version);
        Assert.True(QuicVersionNegotiation.TryGetLongHeaderPacketType(
            header.Version,
            header.LongPacketTypeBits,
            out QuicLongPacketType packetType));
        Assert.Equal(QuicLongPacketType.Retry, packetType);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGetPacketNumberSpace_MapsVersion2InitialAndHandshakePackets()
    {
        byte[] initialPacket = BuildVersion2InitialPacket();
        byte[] handshakePacket = BuildVersion2HandshakePacket();

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryParseLongHeader_AcceptsRepresentativeVersion2PacketShapes()
    {
        Random random = new(unchecked((int)0x9369_0001));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            byte[] packet = BuildRepresentativeVersion2Packet(random, iteration);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(QuicVersionNegotiation.Version2, header.Version);
            Assert.True(QuicVersionNegotiation.IsSupportedTransportVersion(header.Version));
        }
    }

    private static byte[] BuildVersion2InitialPacket()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (0x01 << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                [0x01],
                [0x02],
                [0xAA]));
    }

    private static byte[] BuildVersion2ZeroRttPacket()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (0x02 << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                | 0x00),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                [0x01],
                [0xAA, 0xBB]));
    }

    private static byte[] BuildVersion2HandshakePacket()
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (0x03 << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                | 0x02),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                [0x01, 0x02],
                [0xAA, 0xBB]));
    }

    private static byte[] BuildVersion2RetryPacket()
    {
        return QuicRetryPacketRequirementTestData.BuildRetryPacket(
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            retryToken: [0x74, 0x6F, 0x6B, 0x65, 0x6E]);
    }

    private static byte[] BuildRepresentativeVersion2Packet(Random random, int iteration)
    {
        byte[] destinationConnectionId = RandomBytes(random, 1 + (iteration % 4));
        byte[] sourceConnectionId = RandomBytes(random, 1 + ((iteration + 1) % 4));

        return (iteration % 4) switch
        {
            0 => QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                    | (0x01 << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
                version: QuicVersionNegotiation.Version2,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                    RandomBytes(random, 1 + (iteration % 3)),
                    RandomBytes(random, 1 + (iteration % 2)),
                    RandomBytes(random, 8 + (iteration % 4)))),
            1 => QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                    | (0x02 << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
                version: QuicVersionNegotiation.Version2,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    RandomBytes(random, 1 + (iteration % 3)),
                    RandomBytes(random, 8 + (iteration % 4)))),
            2 => QuicHeaderTestData.BuildLongHeader(
                headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                    | (0x03 << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                    | (iteration & QuicPacketHeaderBits.LongReservedBitsMask)),
                version: QuicVersionNegotiation.Version2,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    RandomBytes(random, 1 + (iteration % 3)),
                    RandomBytes(random, 8 + (iteration % 4)))),
            _ => QuicRetryPacketRequirementTestData.BuildRetryPacket(
                destinationConnectionId: destinationConnectionId,
                sourceConnectionId: sourceConnectionId,
                retryToken: RandomBytes(random, 4 + (iteration % 5)),
                version: QuicVersionNegotiation.Version2),
        };
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
