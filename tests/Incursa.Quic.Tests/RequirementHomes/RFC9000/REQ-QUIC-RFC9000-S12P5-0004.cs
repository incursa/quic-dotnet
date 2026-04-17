namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0004")]
public sealed class REQ_QUIC_RFC9000_S12P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_CarriesApplicationCloseInApplicationDataPackets()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.True(packet.AsSpan(packet.Length - payload.Length, payload.Length).SequenceEqual(payload));

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.Equal(payload.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTruncatedApplicationClosePayloads()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: [0x6F, 0x6B]);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(payload[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1D], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_AllowsApplicationCloseWithoutAReasonPhrase()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal((byte)0x1D, parsedFrame.FrameType);
        Assert.Equal(payload.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(payload.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
