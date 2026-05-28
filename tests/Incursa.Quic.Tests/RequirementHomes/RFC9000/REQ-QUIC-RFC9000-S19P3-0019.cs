// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
public sealed class REQ_QUIC_RFC9000_S19P3_0019
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_FirstAckRangeAcknowledgesContiguousPacketsBeforeLargest()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 7,
            last: 10);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged: 10, firstAckRange: 3),
            ackReceivedAtMicros: 11_000));

        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsFirstAckRangeThatPrecedesPacketNumberZero()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 2, firstAckRange: 3));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_FirstAckRangeZeroAcknowledgesOnlyLargestPacket()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 9,
            last: 10);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateContiguousAckFrame(largestAcknowledged: 10, firstAckRange: 0),
            ackReceivedAtMicros: 11_000));

        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            sentAtMicros: 12_000));
    }
}
