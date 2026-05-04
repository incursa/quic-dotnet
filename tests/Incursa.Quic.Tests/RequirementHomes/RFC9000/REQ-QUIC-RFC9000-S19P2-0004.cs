namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P2-0004")]
public sealed class REQ_QUIC_RFC9000_S19P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProducesAckElicitingKeepAliveProbe()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal((byte)0x01, destination[0]);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(destination[0]));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination[..bytesWritten], out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
    }
}
