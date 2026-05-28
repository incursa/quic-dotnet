// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
public sealed class REQ_QUIC_RFC9000_S19P3_0014
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_ExposesAllRequiredAckFields()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(
                largestAcknowledged: 12,
                ackDelay: 3,
                firstAckRange: 2));

        Assert.Equal(0x02, parsed.FrameType);
        Assert.Equal(12UL, parsed.LargestAcknowledged);
        Assert.Equal(3UL, parsed.AckDelay);
        Assert.Equal(0UL, parsed.AckRangeCount);
        Assert.Equal(2UL, parsed.FirstAckRange);
    }
}
