namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0003">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P9-0003")]
public sealed class REQ_QUIC_RFC9000_S19P9_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxDataFrame_PreservesVariableLengthMaximumDataField()
    {
        QuicMaxDataFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        AssertMaxDataFrameRoundTrips(parsed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsTruncatedMaximumDataField()
    {
        byte[] truncatedMaximumDataField = [0x10, 0x40];

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(truncatedMaximumDataField, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxDataFrame_AcceptsMaximumRepresentableMaximumDataField()
    {
        QuicMaxDataFrame frame = new(QuicVariableLengthInteger.MaxValue);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.MaximumData);
        AssertMaxDataFrameRoundTrips(parsed);
    }

    private static void AssertMaxDataFrameRoundTrips(QuicMaxDataFrame frame)
    {
        Span<byte> buffer = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(frame, buffer, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(buffer[..bytesWritten], out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame, parsed);
    }
}
