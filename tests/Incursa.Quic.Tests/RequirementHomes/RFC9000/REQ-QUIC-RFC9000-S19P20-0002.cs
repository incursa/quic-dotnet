namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
public sealed class REQ_QUIC_RFC9000_S19P20_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatHandshakeDoneFrame_WritesOnlyTheTypeByte()
    {
        byte[] encoded = QuicFrameTestData.BuildHandshakeDoneFrame();

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encoded, out QuicHandshakeDoneFrame parsed, out _));

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal(0x1E, destination[0]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicHandshakeDoneFrame_ExposesTheWireFrameType()
    {
        QuicHandshakeDoneFrame frame = default;

        Assert.Equal((byte)0x1E, frame.FrameType);
    }
}
