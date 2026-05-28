// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
public sealed class REQ_QUIC_RFC9000_S19P3_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EmitsFullLargestAcknowledgedVarint()
    {
        byte[] encoded = QuicS19P3AckFrameTestSupport.FormatAckFrame(
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(0x1_0000));

        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(encoded);

        Assert.Equal(0x1_0000UL, parsed.LargestAcknowledged);
        Assert.Equal(0x80, encoded[1] & 0xC0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedLargestAcknowledgedInsteadOfGuessingPacketNumber()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                [0x80, 0x00, 0x01]));
    }
}
