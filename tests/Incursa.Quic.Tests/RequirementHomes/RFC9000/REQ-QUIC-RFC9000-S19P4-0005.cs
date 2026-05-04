namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
public sealed class REQ_QUIC_RFC9000_S19P4_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_DecodesVariableLengthStreamIdField()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeWithLength(0x1234, 2),
            QuicVarintTestData.EncodeMinimal(0x55),
            QuicVarintTestData.EncodeMinimal(0x66));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x1234UL, parsed.StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsTruncatedStreamIdField()
    {
        byte[] streamId = QuicVarintTestData.EncodeWithLength(0x1234, 2);
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            streamId[..1],
            QuicVarintTestData.EncodeMinimal(0x55),
            QuicVarintTestData.EncodeMinimal(0x66));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_RoundTripsMaximumStreamIdField()
    {
        QuicResetStreamFrame frame = new(
            QuicVariableLengthInteger.MaxValue,
            applicationProtocolErrorCode: 0x55,
            finalSize: 0x66);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.StreamId);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
