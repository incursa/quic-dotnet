namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecErrorHandlingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0014")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseConnectionCloseFrame_ParsesAndFormatsTransportAndApplicationVariants(bool isApplicationError)
    {
        byte[] reasonPhrase = [0x6F, 0x6B];
        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(0x1234, reasonPhrase)
            : new QuicConnectionCloseFrame(0x1234, 0x02, reasonPhrase);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsApplicationError, parsed.IsApplicationError);
        Assert.Equal(frame.ErrorCode, parsed.ErrorCode);
        Assert.Equal(frame.HasTriggeringFrameType, parsed.HasTriggeringFrameType);
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.True(frame.ReasonPhrase.SequenceEqual(parsed.ReasonPhrase));

        if (!frame.IsApplicationError)
        {
            Assert.Equal(frame.TriggeringFrameType, parsed.TriggeringFrameType);
        }

        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0016")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseConnectionCloseFrame_AllowsEmptyReasonPhrases(bool isApplicationError)
    {
        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(0x1234, [])
            : new QuicConnectionCloseFrame(0x1234, 0x02, []);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(0, parsed.ReasonPhrase.Length);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P19-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatConnectionCloseFrame_RejectsTooSmallDestinationBuffers()
    {
        QuicConnectionCloseFrame frame = new(0x1234, 0x02, [0x6F, 0x6B]);

        Assert.False(QuicFrameCodec.TryFormatConnectionCloseFrame(frame, stackalloc byte[0], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseConnectionCloseFrame_RejectsTruncatedOrUnknownTypes()
    {
        QuicConnectionCloseFrame transportFrame = new(0x1234, 0x02, [0x6F, 0x6B]);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(encoded[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1B], out _, out _));
    }
}
