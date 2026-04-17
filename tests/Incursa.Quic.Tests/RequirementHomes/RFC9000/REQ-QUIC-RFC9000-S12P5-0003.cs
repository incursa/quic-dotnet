namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0003")]
public sealed class REQ_QUIC_RFC9000_S12P5_0003
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
    public void TryParseConnectionCloseFrame_CarriesTransportCloseAcrossEveryPacketNumberSpace()
    {
        QuicConnectionCloseFrame transportFrame = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x02,
            reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        byte[] initialPacket = BuildProtectedInitialPacket(payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame initialParsedFrame, out int initialBytesConsumed));
        Assert.False(initialParsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, initialParsedFrame.FrameType);
        Assert.Equal(payload.Length, initialBytesConsumed);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
        Assert.True(handshakePacket.AsSpan(handshakePacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame handshakeParsedFrame, out int handshakeBytesConsumed));
        Assert.False(handshakeParsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, handshakeParsedFrame.FrameType);
        Assert.Equal(payload.Length, handshakeBytesConsumed);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        Assert.True(applicationPacket.AsSpan(applicationPacket.Length - payload.Length, payload.Length).SequenceEqual(payload));
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame applicationParsedFrame, out int applicationBytesConsumed));
        Assert.False(applicationParsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, applicationParsedFrame.FrameType);
        Assert.Equal(payload.Length, applicationBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTruncatedTransportClosePayloads()
    {
        QuicConnectionCloseFrame transportFrame = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x02,
            reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(payload[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1C], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_AllowsTransportCloseWithoutAReasonPhrase()
    {
        QuicConnectionCloseFrame transportFrame = new(
            QuicTransportErrorCode.NoError,
            triggeringFrameType: 0x02,
            reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1C, parsedFrame.FrameType);
        Assert.Equal(payload.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));
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
