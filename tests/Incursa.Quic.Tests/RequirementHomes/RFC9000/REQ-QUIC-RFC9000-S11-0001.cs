namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S11-0001")]
public sealed class REQ_QUIC_RFC9000_S11_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_ParsesTransportAndApplicationVariants()
    {
        byte[] reasonPhrase = [0x6F, 0x6B];

        QuicConnectionCloseFrame transportFrame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, reasonPhrase);
        byte[] transportEncoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(transportEncoded, out QuicConnectionCloseFrame parsedTransport, out int transportBytesConsumed));
        Assert.False(parsedTransport.IsApplicationError);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsedTransport.ErrorCode);
        Assert.True(parsedTransport.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsedTransport.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedTransport.ReasonPhrase));
        Assert.Equal(transportEncoded.Length, transportBytesConsumed);

        Span<byte> transportDestination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedTransport, transportDestination, out int transportBytesWritten));
        Assert.Equal(transportEncoded.Length, transportBytesWritten);
        Assert.True(transportEncoded.AsSpan().SequenceEqual(transportDestination[..transportBytesWritten]));

        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase);
        byte[] applicationEncoded = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(applicationEncoded, out QuicConnectionCloseFrame parsedApplication, out int applicationBytesConsumed));
        Assert.True(parsedApplication.IsApplicationError);
        Assert.Equal(0x1234UL, parsedApplication.ErrorCode);
        Assert.False(parsedApplication.HasTriggeringFrameType);
        Assert.Equal((byte)0x1D, parsedApplication.FrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsedApplication.ReasonPhrase));
        Assert.Equal(applicationEncoded.Length, applicationBytesConsumed);

        Span<byte> applicationDestination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedApplication, applicationDestination, out int applicationBytesWritten));
        Assert.Equal(applicationEncoded.Length, applicationBytesWritten);
        Assert.True(applicationEncoded.AsSpan().SequenceEqual(applicationDestination[..applicationBytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTruncatedOrUnknownTypes()
    {
        QuicConnectionCloseFrame transportFrame = new(QuicTransportErrorCode.ProtocolViolation, 0x02, [0x6F, 0x6B]);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(encoded[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1B], out _, out _));
    }
}
