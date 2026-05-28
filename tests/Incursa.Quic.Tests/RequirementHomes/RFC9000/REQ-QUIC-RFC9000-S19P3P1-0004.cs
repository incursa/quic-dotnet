// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesAckRangeLengthAsVariableLengthInteger()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 100,
                    firstAckRange: 0,
                    gap: 0,
                    ackRangeLength: 0x40)));

        Assert.Equal(0x40UL, parsed.AdditionalRanges[0].AckRangeLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedAckRangeLengthVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AcceptsTwoByteAckRangeLengthVarintAtBoundary()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(100),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.VarintWithLength(0x40, encodedLength: 2)));

        Assert.Equal(0x40UL, parsed.AdditionalRanges[0].AckRangeLength);
    }
}
