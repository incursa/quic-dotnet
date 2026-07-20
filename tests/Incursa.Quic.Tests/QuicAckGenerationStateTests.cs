// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicAckGenerationStateTests
{
    [Fact]
    public void RecordProcessedPacketClassifiesImmediateAckTriggerWithoutChangingAckState()
    {
        QuicAckGenerationState state = new(minimumAckElicitingPacketsBeforeDelayedAck: 16);

        Assert.Equal(
            QuicImmediateAckTrigger.None,
            state.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber: 10,
                ackEliciting: true,
                receivedAtMicros: 1_000));
        Assert.Equal(
            QuicImmediateAckTrigger.AckElicitingPacketGap,
            state.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber: 12,
                ackEliciting: true,
                receivedAtMicros: 1_100));

        Assert.True(state.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    public void EcnCountsFollowTheLatestCumulativeSnapshotAcrossOutOfOrderPacketNumbers()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(4, 2, 1));
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            ackEliciting: true,
            receivedAtMicros: 1_100,
            ecnCounts: new QuicEcnCounts(5, 3, 2));

        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        AssertEcnCounts(frame, 5, 3, 2);
        frame.Dispose();
    }

    [Fact]
    public void EcnCountsRemainCumulativeAfterAcknowledgedRangesRetire()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));
        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            out QuicAckFrame firstFrame));
        state.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 20,
            firstFrame,
            sentAtMicros: 1_100,
            ackOnlyPacket: false);
        firstFrame.Dispose();

        QuicAckFrame peerAck = new()
        {
            LargestAcknowledged = 20,
            FirstAckRange = 0,
        };
        Assert.True(state.TryRetireAcknowledgedAckRanges(QuicPacketNumberSpace.ApplicationData, peerAck));

        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_200);
        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame secondFrame));

        Assert.Equal((byte)0x03, secondFrame.FrameType);
        AssertEcnCounts(secondFrame, 1, 0, 0);
        secondFrame.Dispose();
    }

    [Fact]
    public void DiscardingPacketNumberSpaceClearsItsCumulativeEcnCounts()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));

        Assert.True(state.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        state.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_100);
        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_200,
            out QuicAckFrame frame));

        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Null(frame.EcnCounts);
        frame.Dispose();
    }

    [Fact]
    public void DuplicatePacketWithoutEcnMetadataDoesNotEraseCumulativeCounts()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(3, 2, 1));
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        AssertEcnCounts(frame, 3, 2, 1);
        frame.Dispose();
    }

    [Fact]
    public void RetiringLargestAckElicitingPacketRefreshesGapDetectionState()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        using QuicAckFrame largestOnly = new()
        {
            LargestAcknowledged = 3,
            FirstAckRange = 0,
        };
        state.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 20,
            largestOnly,
            sentAtMicros: 1_200,
            ackOnlyPacket: false);
        Assert.True(state.TryRetireAcknowledgedAckRanges(
            QuicPacketNumberSpace.ApplicationData,
            ackedPacketNumber: 20));

        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_300);

        Assert.False(state.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }

    private static void AssertEcnCounts(QuicAckFrame frame, ulong ect0, ulong ect1, ulong ecnCe)
    {
        Assert.True(frame.EcnCounts.HasValue);
        Assert.Equal(ect0, frame.EcnCounts.Value.Ect0Count);
        Assert.Equal(ect1, frame.EcnCounts.Value.Ect1Count);
        Assert.Equal(ecnCe, frame.EcnCounts.Value.EcnCeCount);
    }
}
