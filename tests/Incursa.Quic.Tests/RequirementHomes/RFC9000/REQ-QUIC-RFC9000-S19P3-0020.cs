// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
public sealed class REQ_QUIC_RFC9000_S19P3_0020
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_AdditionalRangeAcknowledgesPacketsAfterGap()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 5,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 1,
            ackRangeLength: 2);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            frame,
            ackReceivedAtMicros: 11_000));

        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            sentAtMicros: 12_000));
        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsAdditionalRangeThatComputesBelowZero()
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
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AdditionalRangeCanRepresentOnePacketAfterOnePacketGap()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 10,
                    firstAckRange: 0,
                    gap: 0,
                    ackRangeLength: 0)));

        Assert.Single(parsed.AdditionalRanges);
        Assert.Equal(8UL, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(8UL, parsed.AdditionalRanges[0].SmallestAcknowledged);
    }
}
