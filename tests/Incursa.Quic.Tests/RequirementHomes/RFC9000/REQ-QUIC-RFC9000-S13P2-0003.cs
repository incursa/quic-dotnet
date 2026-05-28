// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0003">Packets that are not ack-eliciting MUST only be acknowledged when an ACK frame is sent for other reasons.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2-0003")]
public sealed class REQ_QUIC_RFC9000_S13P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_IncludesNonAckElicitingGapOnlyAfterAckElicitingReason()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 30_000,
            maxAckDelayMicros: 25_000));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 30_000,
            maxAckDelayMicros: 25_000));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 26_100,
            maxAckDelayMicros: 25_000));
        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 26_100,
            out QuicAckFrame ackFrame));

        Assert.Equal(6UL, ackFrame.LargestAcknowledged);
        Assert.Equal(0UL, ackFrame.FirstAckRange);
        QuicAckRange additionalRange = Assert.Single(ackFrame.AdditionalRanges ?? Array.Empty<QuicAckRange>());
        Assert.Equal(4UL, additionalRange.SmallestAcknowledged);
        Assert.Equal(4UL, additionalRange.LargestAcknowledged);
    }
}
