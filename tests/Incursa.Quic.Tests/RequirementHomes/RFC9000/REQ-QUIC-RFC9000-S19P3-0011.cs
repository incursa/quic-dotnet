// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
public sealed class REQ_QUIC_RFC9000_S19P3_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesAckDelayAsVariableLengthInteger()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 4, ackDelay: 0x40));

        Assert.Equal(0x40UL, parsed.AckDelay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedAckDelayVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(4),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_PreservesMaximumAckDelayVarintValue()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(
                largestAcknowledged: 4,
                ackDelay: QuicVariableLengthInteger.MaxValue));

        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.AckDelay);
    }
}
