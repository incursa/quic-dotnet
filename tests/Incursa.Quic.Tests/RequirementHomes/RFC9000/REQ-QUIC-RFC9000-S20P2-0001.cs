namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
public sealed class REQ_QUIC_RFC9000_S20P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetStreamFrame_UsesApplicationProtocolErrorCodes()
    {
        QuicResetStreamFrame frame = new(streamId: 0x1234, applicationProtocolErrorCode: 0x5678, finalSize: 0x9A);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StopSendingFrame_UsesApplicationProtocolErrorCodes()
    {
        QuicStopSendingFrame frame = new(streamId: 0x1234, applicationProtocolErrorCode: 0x5678);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionCloseFrame_UsesApplicationProtocolErrorCodes()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionCloseFrame_DoesNotUseTransportErrorCodesForApplicationClose()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: 0x1234,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
