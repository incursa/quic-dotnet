namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
public sealed class REQ_QUIC_RFC9000_S19P5_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatStopSendingFrame_EncodesTypeAs05()
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(
            new QuicStopSendingFrame(streamId: 0x40, applicationProtocolErrorCode: 0x41),
            destination,
            out int bytesWritten));

        Assert.True(bytesWritten > 0);
        Assert.Equal(0x05, destination[0]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStopSendingFrame_RejectsNonStopSendingType()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildStopSendingPayload(
            QuicVarintTestData.EncodeMinimal(0x04),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeMinimal(0x41));

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStopSendingFrame_AcceptsType05WithZeroFields()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(
            new QuicStopSendingFrame(streamId: 0, applicationProtocolErrorCode: 0));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0UL, parsed.StreamId);
        Assert.Equal(0UL, parsed.ApplicationProtocolErrorCode);
    }
}
