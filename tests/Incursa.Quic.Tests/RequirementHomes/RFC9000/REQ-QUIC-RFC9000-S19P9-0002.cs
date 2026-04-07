namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P9-0002")]
public sealed class REQ_QUIC_RFC9000_S19P9_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxDataFrame_ParsesAndFormatsTheMaximumDataField()
    {
        QuicMaxDataFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
