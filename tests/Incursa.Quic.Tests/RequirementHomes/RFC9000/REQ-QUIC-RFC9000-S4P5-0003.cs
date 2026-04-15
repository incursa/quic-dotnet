namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0003">The Final Size field of a RESET_STREAM frame MUST carry the final size value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
public sealed class REQ_QUIC_RFC9000_S4P5_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_ParsesAndFormatsTheFinalSizeField()
    {
        QuicResetStreamFrame frame = new(0x1234, 0x55, 0x200);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x1234, 0x55, 0x200));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([0x05], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_RoundTripsTheMaximumFinalSizeValue()
    {
        QuicResetStreamFrame frame = new(0x1234, 0x55, QuicVariableLengthInteger.MaxValue);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
