namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_RoundsTripAcknowledgedRangesAndAckDelay()
    {
        QuicAckFrame frame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 5,
            AckDelay = 300,
            FirstAckRange = 1,
            AdditionalRanges =
            [
                new QuicAckRange(0, 1, 1, 2),
            ],
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Single(parsed.AdditionalRanges);
        Assert.Equal(frame.AdditionalRanges[0].Gap, parsed.AdditionalRanges[0].Gap);
        Assert.Equal(frame.AdditionalRanges[0].AckRangeLength, parsed.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[0].SmallestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
