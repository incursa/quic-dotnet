namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0002">The Type field MUST be encoded as a variable-length integer with value 0x10.</workbench-requirement>
/// </workbench-requirements>
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsFramesWithADifferentType()
    {
        byte[] dataBlockedFrameBytes = QuicFrameTestData.BuildDataBlockedFrame(new QuicDataBlockedFrame(maximumData: 1));

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(dataBlockedFrameBytes, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxDataFrame_RejectsNonMinimalEncodingOfTheFixedType()
    {
        byte[] encoded = [0x40, 0x10, 0x01];

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzMaxDataFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzMaxDataFrame();
    }
}
