// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
public sealed class REQ_QUIC_RFC9000_S19P3_0012
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesAckRangeCountAsVariableLengthInteger()
    {
        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);

        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(frame));

        Assert.Equal(1UL, parsed.AckRangeCount);
        Assert.Single(parsed.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedAckRangeCountVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AcceptsTwoByteAckRangeCountVarint()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.VarintWithLength(1, encodedLength: 2),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));

        Assert.Equal(1UL, parsed.AckRangeCount);
    }
}
