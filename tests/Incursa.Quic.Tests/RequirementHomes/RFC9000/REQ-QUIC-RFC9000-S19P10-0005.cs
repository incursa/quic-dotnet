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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzMaxStreamDataFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzMaxStreamDataFrame();
    }
}
