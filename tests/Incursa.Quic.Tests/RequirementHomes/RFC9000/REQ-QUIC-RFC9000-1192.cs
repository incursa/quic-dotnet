// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1192")]
public sealed class REQ_QUIC_RFC9000_1192
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1192")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_AdditionalRangesDescendByAlternatingGapAndLength()
    {
        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 1);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(firstAdditionalRange.SmallestAcknowledged, gap: 1, ackRangeLength: 0);

        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
                    largestAcknowledged: 20,
                    firstAckRange: 0,
                    firstAdditionalRange,
                    secondAdditionalRange)));

        Assert.True(parsed.AdditionalRanges[0].LargestAcknowledged < 20);
        Assert.True(parsed.AdditionalRanges[1].LargestAcknowledged < parsed.AdditionalRanges[0].SmallestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1192")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatAckFrame_RejectsAdditionalRangeThatDoesNotMatchDescendingComputation()
    {
        QuicAckFrame invalid = QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
            largestAcknowledged: 20,
            firstAckRange: 0,
            new QuicAckRange(gap: 0, ackRangeLength: 0, smallestAcknowledged: 19, largestAcknowledged: 19));

        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicFrameCodec.TryFormatAckFrame(invalid, destination, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1192")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_ZeroGapAndZeroLengthStillDescendByOneSkippedPacket()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 10,
                    firstAckRange: 0,
                    gap: 0,
                    ackRangeLength: 0)));

        Assert.Equal(8UL, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(8UL, parsed.AdditionalRanges[0].SmallestAcknowledged);
    }
}
