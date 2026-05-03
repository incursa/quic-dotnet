namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0005">Sending a RETIRE_CONNECTION_ID frame MUST indicate that the connection ID will not be used again and request that the peer replace it with a new connection ID using a NEW_CONNECTION_ID frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseRetireConnectionIdFrame_ParsesAndFormatsTheRetiredSequenceNumber()
    {
        QuicRetireConnectionIdFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(
            encoded,
            out QuicRetireConnectionIdFrame parsed,
            out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(
            parsed,
            destination,
            out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseRetireConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        QuicRetireConnectionIdFrame frame = new(0x01);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(
            encoded[..Math.Max(0, encoded.Length - truncateBy)],
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseRetireConnectionIdFrame_AllowsSequenceNumberZero()
    {
        QuicRetireConnectionIdFrame frame = new(0);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(
            encoded,
            out QuicRetireConnectionIdFrame parsed,
            out int bytesConsumed));
        Assert.Equal(0UL, parsed.SequenceNumber);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
