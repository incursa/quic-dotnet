namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4-0004")]
public sealed class REQ_QUIC_RFC9000_S4_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAndParseCryptoFrame_AllowsOffsetsThatDoNotFollowStreamFlowControl()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue - 1, [0xAA]);
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(destination[..bytesWritten], out QuicCryptoFrame parsedFrame, out int bytesConsumed));

        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.Offset, parsedFrame.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsedFrame.CryptoData));
    }
}
