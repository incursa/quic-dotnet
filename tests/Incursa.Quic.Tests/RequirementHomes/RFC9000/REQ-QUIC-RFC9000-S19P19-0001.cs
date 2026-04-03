namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0001")]
public sealed class REQ_QUIC_RFC9000_S19P19_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseConnectionCloseFrame_UsesTheTransportCloseFrameType()
    {
        QuicConnectionCloseFrame frame = new(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, [0x6F, 0x6B]);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.NoError, parsed.ErrorCode);
        Assert.Equal(frame.TriggeringFrameType, parsed.TriggeringFrameType);
        Assert.True(frame.ReasonPhrase.SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
