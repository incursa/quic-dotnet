namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
public sealed class REQ_QUIC_RFC9000_S19P4_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_DecodesVariableLengthFinalSizeField()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeMinimal(0x55),
            QuicVarintTestData.EncodeWithLength(0x1234, 2));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x1234UL, parsed.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsTruncatedFinalSizeField()
    {
        byte[] finalSize = QuicVarintTestData.EncodeWithLength(0x1234, 2);
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeMinimal(0x55),
            finalSize[..1]);

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_RoundTripsMaximumFinalSizeField()
    {
        QuicResetStreamFrame frame = new(
            streamId: 0x40,
            applicationProtocolErrorCode: 0x55,
            finalSize: QuicVariableLengthInteger.MaxValue);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.FinalSize);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
