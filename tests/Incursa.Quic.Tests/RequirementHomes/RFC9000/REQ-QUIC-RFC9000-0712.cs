// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0712">A receiver MUST discard a newly unprotected packet unless it is certain that it has not processed another packet with the same packet number from the same packet number space.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P10-0001">If duplicate packets are discarded by a receiver, an attacker will MUST race the duplicate packet against the original to be successful in this attack.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0712")]
public sealed class REQ_QUIC_RFC9000_0712
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P10-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_MergesDuplicatePacketNumbersIntoASingleAckRange()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P10-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordIncomingPacket_KeepsMatchingPacketNumbersSeparatedByPacketNumberSpace()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_200,
            out QuicAckFrame initialFrame));
        Assert.Equal(7UL, initialFrame.LargestAcknowledged);
        Assert.Equal(0UL, initialFrame.FirstAckRange);
        Assert.Empty(initialFrame.AdditionalRanges);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_200,
            out QuicAckFrame applicationFrame));
        Assert.Equal(7UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.FirstAckRange);
        Assert.Empty(applicationFrame.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P10-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordIncomingPacket_HandlesTheLargestPacketNumberWithoutSplittingTheRange()
    {
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: ulong.MaxValue,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: ulong.MaxValue,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(ulong.MaxValue, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }
}
