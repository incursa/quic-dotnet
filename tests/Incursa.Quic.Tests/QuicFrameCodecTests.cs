namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [Requirement("REQ-QUIC-RFC9002-S3-0008")]
    [Trait("Category", "Positive")]
    public void TryParsePaddingFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] frameBytes = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(frameBytes, out int bytesConsumed));
        Assert.Equal(frameBytes.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(destination, out int bytesWritten));
        Assert.Equal(frameBytes.Length, bytesWritten);
        Assert.True(frameBytes.AsSpan().SequenceEqual(destination[..bytesWritten]));

        byte[] packetWithFollowingFrame = [0x00, 0x01];
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetWithFollowingFrame, out int consumedBeforePing));
        Assert.Equal(1, consumedBeforePing);
        Assert.True(QuicFrameCodec.TryParsePingFrame(packetWithFollowingFrame[consumedBeforePing..], out int pingConsumed));
        Assert.Equal(1, pingConsumed);
    }

    [Theory]
    [InlineData(0x00UL, false)]
    [InlineData(0x01UL, true)]
    [InlineData(0x02UL, false)]
    [InlineData(0x03UL, false)]
    [InlineData(0x06UL, true)]
    [InlineData(0x07UL, true)]
    [InlineData(0x10UL, true)]
    [InlineData(0x1AUL, true)]
    [InlineData(0x1CUL, false)]
    [Requirement("REQ-QUIC-RFC9002-S2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0017")]
    [Trait("Category", "Positive")]
    public void IsAckElicitingFrameType_ClassifiesKnownFrameTypes(ulong frameType, bool expectedAckEliciting)
    {
        Assert.Equal(expectedAckEliciting, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
    [Trait("Category", "Negative")]
    public void TryParsePaddingAndPingFrame_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x01], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
    [Trait("Category", "Positive")]
    public void TryParsePingFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] frameBytes = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(frameBytes, out int bytesConsumed));
        Assert.Equal(frameBytes.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(frameBytes.Length, bytesWritten);
        Assert.True(frameBytes.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0007")]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_RoundTripsRangesAndEcnCounts()
    {
        ulong largestAcknowledged = 0x1234;
        ulong firstAckRange = 0x04;
        ulong firstSmallest = largestAcknowledged - firstAckRange;
        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(firstSmallest, 0x01, 0x02);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(firstAdditionalRange.SmallestAcknowledged, 0x00, 0x00);

        QuicAckFrame frame = new()
        {
            FrameType = 0x03,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0x25,
            FirstAckRange = firstAckRange,
            AdditionalRanges =
            [
                firstAdditionalRange,
                secondAdditionalRange,
            ],
            EcnCounts = new QuicEcnCounts(0x11, 0x12, 0x13),
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        Assert.Equal(frame.AdditionalRanges[0].Gap, parsed.AdditionalRanges[0].Gap);
        Assert.Equal(frame.AdditionalRanges[0].AckRangeLength, parsed.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[0].SmallestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[1].Gap, parsed.AdditionalRanges[1].Gap);
        Assert.Equal(frame.AdditionalRanges[1].AckRangeLength, parsed.AdditionalRanges[1].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[1].SmallestAcknowledged, parsed.AdditionalRanges[1].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[1].LargestAcknowledged, parsed.AdditionalRanges[1].LargestAcknowledged);
        Assert.Equal(frame.EcnCounts!.Value.Ect0Count, parsed.EcnCounts!.Value.Ect0Count);
        Assert.Equal(frame.EcnCounts!.Value.Ect1Count, parsed.EcnCounts!.Value.Ect1Count);
        Assert.Equal(frame.EcnCounts!.Value.EcnCeCount, parsed.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0007")]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedAndInvalidRangeLayouts()
    {
        ulong largestAcknowledged = 0x10;
        QuicAckFrame validFrame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0x01,
            FirstAckRange = 0x00,
            AdditionalRanges =
            [
                new QuicAckRange(0x00, 0x00, 0x0D, 0x0D),
            ],
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(validFrame);
        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded[..(encoded.Length - 1)], out _, out _));

        QuicAckFrame invalidFirstRange = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x03,
            AckDelay = 0x01,
            FirstAckRange = 0x04,
        };

        Assert.False(QuicFrameCodec.TryParseAckFrame(QuicFrameTestData.BuildAckFrame(invalidFirstRange), out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [Trait("Category", "Positive")]
    public void TryParseResetStreamFrame_ParsesAndFormatsAllFields()
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
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x1234, 0x55, 0x200));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([0x05], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Trait("Category", "Positive")]
    public void TryParseStopSendingFrame_ParsesAndFormatsAllFields()
    {
        QuicStopSendingFrame frame = new(0x44, 0x66);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Trait("Category", "Negative")]
    public void TryParseStopSendingFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x44, 0x66));

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([0x04], out _, out _));
    }
}
