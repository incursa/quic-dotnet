// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-3-P2-S1-R01")]
public sealed class RFC9000_S19_3_P2_S1_R01
{
    [Fact]
    [Requirement("RFC9000-S19-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_DoesNotRequirePreviouslyAcknowledgedPacketInLaterAckFrames()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 1,
            last: 2);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(1),
            ackReceivedAtMicros: 3_000));

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(2),
            ackReceivedAtMicros: 4_000));

        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 5_000));
        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [Requirement("RFC9000-S19-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotTreatOmittedUnacknowledgedPacketAsAcknowledged()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 1,
            last: 2);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(2),
            ackReceivedAtMicros: 3_000));

        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentAtMicros: 4_000));
    }

    [Fact]
    [Requirement("RFC9000-S19-3-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_DuplicateAcknowledgmentDoesNotReprocessAlreadyAcknowledgedPacket()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(1),
            ackReceivedAtMicros: 2_000));
        ulong bytesInFlightAfterFirstAck = sender.CongestionControlState.BytesInFlightBytes;

        Assert.False(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(1),
            ackReceivedAtMicros: 3_000));
        Assert.Equal(bytesInFlightAfterFirstAck, sender.CongestionControlState.BytesInFlightBytes);
    }
}
