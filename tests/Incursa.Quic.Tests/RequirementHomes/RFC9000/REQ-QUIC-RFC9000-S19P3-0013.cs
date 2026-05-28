// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
public sealed class REQ_QUIC_RFC9000_S19P3_0013
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesFirstAckRangeAsVariableLengthInteger()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 10, firstAckRange: 2));

        Assert.Equal(2UL, parsed.FirstAckRange);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedFirstAckRangeVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AcceptsTwoByteFirstAckRangeAtLargestAcknowledgedBoundary()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 0x40, firstAckRange: 0x40));

        Assert.Equal(0x40UL, parsed.LargestAcknowledged);
        Assert.Equal(0x40UL, parsed.FirstAckRange);
    }
}
