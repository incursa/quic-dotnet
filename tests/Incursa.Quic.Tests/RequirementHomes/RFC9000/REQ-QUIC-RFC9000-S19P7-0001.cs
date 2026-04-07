namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
public sealed class REQ_QUIC_RFC9000_S19P7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_WritesTheFrameTypeField()
    {
        QuicNewTokenFrame frame = new([0x10, 0x20, 0x30, 0x40]);
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(frame, destination, out int bytesWritten));
        Assert.Equal(6, bytesWritten);
        Assert.Equal(0x07, destination[0]);
    }
}
