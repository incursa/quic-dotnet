namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1237")]
public sealed class REQ_QUIC_RFC9000_1237
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    public void TryAddFrame_ReportsCryptoBufferExceededForFramesBeyondTheStreamLimit()
    {
        QuicCryptoBuffer buffer = new();

        Assert.False(buffer.TryAddFrame(
            new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]),
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, result);
        Assert.Equal(0x0DUL, (ulong)QuicTransportErrorCode.CryptoBufferExceeded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(encoded, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue, [0xAA]);

        Assert.False(QuicFrameCodec.TryFormatCryptoFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAddFrame_AcceptsFramesThatEndExactlyAtTheStreamLimit()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(
            new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue - 1, [0xAA]),
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
    }
}
