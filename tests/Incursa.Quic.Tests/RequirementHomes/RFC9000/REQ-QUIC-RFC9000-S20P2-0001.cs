namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
public sealed class REQ_QUIC_RFC9000_S20P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_UsesApplicationProtocolErrorCode()
    {
        QuicResetStreamFrame frame = new(streamId: 0x44, applicationProtocolErrorCode: 0x66, finalSize: 0x88);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStopSendingFrame_UsesApplicationProtocolErrorCode()
    {
        QuicStopSendingFrame frame = new(streamId: 0x55, applicationProtocolErrorCode: 0x77);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_UsesApplicationProtocolErrorCodeOnApplicationCloseFrames()
    {
        const ulong applicationProtocolErrorCode = 0x1234;
        byte[] reasonPhrase = [0x61, 0x70, 0x70];
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(
            errorCode: applicationProtocolErrorCode,
            reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(applicationProtocolErrorCode, parsed.ErrorCode);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal(0UL, parsed.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_DoesNotClassifyTransportCloseAsApplicationClose()
    {
        byte[] reasonPhrase = [0x6F, 0x6B];
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x02,
            reasonPhrase: reasonPhrase);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, parsed.ErrorCode);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsed.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
