// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
public sealed class REQ_QUIC_RFC9000_S19P3_0018
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_AckRangeCountSpecifiesAdditionalRangeFieldCount()
    {
        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 0);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(firstAdditionalRange.SmallestAcknowledged, gap: 0, ackRangeLength: 0);
        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.AckFrameFromRanges(
            largestAcknowledged: 20,
            firstAckRange: 0,
            firstAdditionalRange,
            secondAdditionalRange);

        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(frame));

        Assert.Equal(2UL, parsed.AckRangeCount);
        Assert.Equal(2, parsed.AdditionalRanges.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsWhenDeclaredAckRangeCountIsNotPresent()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(2),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsDeclaredAckRangeCountLargerThanRemainingPayload()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(10_000),
                QuicS19P3AckFrameTestSupport.Varint(0)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AckRangeCountZeroCarriesNoAdditionalRanges()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 10));

        Assert.Equal(0UL, parsed.AckRangeCount);
        Assert.Empty(parsed.AdditionalRanges);
    }
}
