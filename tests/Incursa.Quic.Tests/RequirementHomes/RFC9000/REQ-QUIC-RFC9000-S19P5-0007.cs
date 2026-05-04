namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
public sealed class REQ_QUIC_RFC9000_S19P5_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStopSendingFrame_DecodesVariableLengthApplicationErrorField()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildStopSendingPayload(
            QuicVarintTestData.EncodeMinimal(0x05),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeWithLength(0x1234, 2));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x1234UL, parsed.ApplicationProtocolErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStopSendingFrame_RejectsTruncatedApplicationErrorField()
    {
        byte[] applicationErrorCode = QuicVarintTestData.EncodeWithLength(0x1234, 2);
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildStopSendingPayload(
            QuicVarintTestData.EncodeMinimal(0x05),
            QuicVarintTestData.EncodeMinimal(0x40),
            applicationErrorCode[..1]);

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStopSendingFrame_RoundTripsMaximumApplicationErrorField()
    {
        QuicStopSendingFrame frame = new(
            streamId: 0x40,
            applicationProtocolErrorCode: QuicVariableLengthInteger.MaxValue);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.ApplicationProtocolErrorCode);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
