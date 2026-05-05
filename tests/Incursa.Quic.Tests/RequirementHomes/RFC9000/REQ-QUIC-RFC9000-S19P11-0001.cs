namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P11-0001")]
public sealed class REQ_QUIC_RFC9000_S19P11_0001
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamsFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicMaxStreamsFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamsFrame_RejectsFramesOutsideTheMaxStreamsTypeRange()
    {
        byte[] encodedDataBlockedFrame = [0x14, 0x01];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encodedDataBlockedFrame, out _, out _));
    }

    [Theory]
    [InlineData(0x12)]
    [InlineData(0x13)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamsFrame_RejectsNonFixedTypeEncodings(byte maxStreamsFrameType)
    {
        byte[] encodedWithTwoByteType = [0x40, maxStreamsFrameType, 0x00];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encodedWithTwoByteType, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzMaxStreamsFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzMaxStreamsFrame();
    }
}
