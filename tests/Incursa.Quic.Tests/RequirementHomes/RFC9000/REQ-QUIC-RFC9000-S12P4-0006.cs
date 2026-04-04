namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P4-0006")]
public sealed class REQ_QUIC_RFC9000_S12P4_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatSelectedFrames_PrefixesTheFrameTypeBeforeTypeDependentFields()
    {
        Span<byte> pingDestination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingDestination, out int pingBytesWritten));
        Assert.Equal(1, pingBytesWritten);
        Assert.Equal(0x01, pingDestination[0]);

        Span<byte> maxDataDestination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(new QuicMaxDataFrame(0x1234), maxDataDestination, out int maxDataBytesWritten));
        Assert.True(maxDataBytesWritten > 1);
        Assert.Equal(0x10, maxDataDestination[0]);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(maxDataDestination[..maxDataBytesWritten], out QuicMaxDataFrame parsedMaxData, out int maxDataBytesConsumed));
        Assert.Equal(0x1234UL, parsedMaxData.MaximumData);
        Assert.Equal(maxDataBytesWritten, maxDataBytesConsumed);
    }
}
