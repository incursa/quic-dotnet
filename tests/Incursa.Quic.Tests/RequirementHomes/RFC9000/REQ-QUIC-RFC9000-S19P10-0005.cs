namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
public sealed class REQ_QUIC_RFC9000_S19P10_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_ParsesAndFormatsTheFrameFields()
    {
        QuicMaxStreamDataFrame frame = new(0x06, 0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out QuicMaxStreamDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
