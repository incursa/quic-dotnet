// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_RejectsRangeWhenComputedPacketNumberWouldBeNegative()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_AcceptsSameRangeLayoutWhenComputedNumbersStayNonNegative()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(2),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));

        Assert.Equal(0UL, parsed.AdditionalRanges[0].LargestAcknowledged);
    }
}
