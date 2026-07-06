// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1-0001">A QUIC sender MUST track every ack-eliciting packet until the packet is acknowledged or lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1-0001")]
public sealed class REQ_QUIC_RFC9002_SAP1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordProcessedPacket_KeepsAckElicitingPacketsTrackedUntilTheAckOnlyFrameIsSent()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));
        Assert.Equal(7UL, frame.LargestAcknowledged);

        tracker.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        Assert.False(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordProcessedPacket_DoesNotTreatNonAckElicitingPacketsAsAckTriggers()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordProcessedPacket_RequestsImmediateAckForInitialAndHandshakePackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderFlowController_UsesAckGenerationStateForImmediateAndScheduledAckFrames()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1000);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1100);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(sender.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, maxAckDelayMicros: 1000));

        Assert.True(sender.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, out QuicAckFrame ackFrame));
        Assert.Equal(3UL, ackFrame.LargestAcknowledged);
        Assert.Equal(0UL, ackFrame.FirstAckRange);

        sender.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1300, ackOnlyPacket: true);
        Assert.False(sender.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1400, maxAckDelayMicros: 1000));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 3400, maxAckDelayMicros: 1000));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 3400);
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 3400, maxAckDelayMicros: 1000));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 4400, maxAckDelayMicros: 1000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrackSentAckElicitingPacketsUntilAcknowledgedOrLost()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong packetNumber, ulong payloadBytes, bool resolveByAck) in new[]
        {
            (QuicPacketNumberSpace.Initial, 1UL, 1_200UL, true),
            (QuicPacketNumberSpace.Handshake, 2UL, 1_350UL, false),
            (QuicPacketNumberSpace.ApplicationData, 3UL, 9_000UL, true),
            (QuicPacketNumberSpace.ApplicationData, 4UL, 1UL, false),
        })
        {
            QuicConnectionSendRuntime runtime = new();
            QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);

            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                packetNumberSpace,
                packetNumber,
                payloadBytes,
                SentAtMicros: packetNumber * 1_000,
                AckEliciting: true,
                Retransmittable: false));

            Assert.True(runtime.SentPackets.ContainsKey(key));
            Assert.True(runtime.HasAckElicitingPacketsInFlight);

            bool resolved = resolveByAck
                ? runtime.TryAcknowledgePacket(packetNumberSpace, packetNumber, handshakeConfirmed: true)
                : runtime.TryRegisterLoss(packetNumberSpace, packetNumber, handshakeConfirmed: true, scheduleRetransmission: false);

            Assert.True(resolved);
            Assert.False(runtime.SentPackets.ContainsKey(key));
            Assert.False(runtime.HasAckElicitingPacketsInFlight);
        }
    }
}
