namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0001")]
public sealed class REQ_QUIC_RFC9000_S12P5_0001
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_MapsTheSupportedPacketFormsToTheExpectedSpaces()
    {
        byte[] initialPayload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));
        byte[] initialPacket = BuildProtectedInitialPacket(initialPayload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(initialPayload, out QuicCryptoFrame initialCryptoFrame, out int initialCryptoBytesConsumed));
        Assert.Equal(initialPayload.Length, initialCryptoBytesConsumed);
        Assert.Equal(0UL, initialCryptoFrame.Offset);
        Assert.True(initialCryptoFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));

        byte[] handshakePayload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xBB]));
        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: handshakePayload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - handshakePayload.Length, handshakePayload.Length).SequenceEqual(handshakePayload));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(handshakePayload, out QuicCryptoFrame handshakeCryptoFrame, out int handshakeCryptoBytesConsumed));
        Assert.Equal(handshakePayload.Length, handshakeCryptoBytesConsumed);
        Assert.Equal(0UL, handshakeCryptoFrame.Offset);
        Assert.True(handshakeCryptoFrame.CryptoData.SequenceEqual(new byte[] { 0xBB }));

        byte[] applicationPayload = QuicFrameTestData.BuildPingFrame();
        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, applicationPayload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - applicationPayload.Length, applicationPayload.Length).SequenceEqual(applicationPayload));
        Assert.True(QuicFrameCodec.TryParsePingFrame(applicationPayload, out int applicationPingBytesConsumed));
        Assert.Equal(applicationPayload.Length, applicationPingBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationAndRetryPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [1, 2]);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryGetPacketNumberSpace_AcceptsTheShortestValidShortHeader()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, []);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
    }

    private static byte[] BuildProtectedInitialPacket(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            payload,
            cryptoPayloadOffset: 0,
            protection,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
