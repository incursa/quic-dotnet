namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0002")]
public sealed class REQ_QUIC_RFC9000_S12P5_0002
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
    public void TryParsePaddingFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildPaddingFrame();

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParsePingFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildPingFrame();

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_CarriesTheFrameBytesAcrossEveryPacketNumberSpace()
    {
        byte[] payload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame initialFrame, out int initialBytesConsumed));
        Assert.Equal(payload.Length, initialBytesConsumed);
        Assert.Equal(0UL, initialFrame.Offset);
        Assert.True(initialFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame handshakeFrame, out int handshakeBytesConsumed));
        Assert.Equal(payload.Length, handshakeBytesConsumed);
        Assert.Equal(0UL, handshakeFrame.Offset);
        Assert.True(handshakeFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(payload, out QuicCryptoFrame applicationFrame, out int applicationBytesConsumed));
        Assert.Equal(payload.Length, applicationBytesConsumed);
        Assert.Equal(0UL, applicationFrame.Offset);
        Assert.True(applicationFrame.CryptoData.SequenceEqual(new byte[] { 0xAA }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePaddingPingAndCryptoFrames_RejectsTruncatedPayloads()
    {
        byte[] crypto = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA]));

        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParseCryptoFrame(crypto[..^1], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatCryptoFrame_AllowsTheZeroLengthCryptoPayloadEdge()
    {
        QuicCryptoFrame frame = new(0, []);
        Span<byte> destination = stackalloc byte[8];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(destination[..bytesWritten], out QuicCryptoFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(0UL, parsedFrame.Offset);
        Assert.True(parsedFrame.CryptoData.IsEmpty);
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
