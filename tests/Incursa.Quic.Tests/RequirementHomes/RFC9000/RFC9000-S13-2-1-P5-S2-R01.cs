// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S13-2-1-P5-S2-R01">When only non-ack-eliciting packets need to be acknowledged, an endpoint MAY choose not to send an ACK frame with outgoing frames until an ack-eliciting packet has been received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S13-2-1-P5-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0764
{
    [Fact]
    [Requirement("RFC9000-S13-2-1-P5-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_AllowsAckAfterAckElicitingPacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_000,
            maxAckDelayMicros: 25_000));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 101_100);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_200,
            maxAckDelayMicros: 25_000));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 126_100,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_RemainsFalseWhenOnlyNonAckElicitingPacketsArePending()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            maxAckDelayMicros: 25_000));
        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_StillDelaysNonAckElicitingOnlyPacketsAfterMaxAckDelay()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: false,
            receivedAtMicros: 1_100);

        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_100,
            maxAckDelayMicros: 25_000));
        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_100,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShouldIncludeAckFrameWithOutgoingPacket_DelaysNonAckElicitingOnlyPacketSets()
    {
        for (ulong firstPacketNumber = 1; firstPacketNumber <= 24; firstPacketNumber++)
        {
            QuicSenderFlowController sender = new();

            for (ulong offset = 0; offset < 4; offset++)
            {
                sender.RecordIncomingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    firstPacketNumber + (offset * 2),
                    ackEliciting: false,
                    receivedAtMicros: 1_000 + offset);
            }

            Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
            Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 250_000,
                maxAckDelayMicros: 25_000));
            Assert.False(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 250_000,
                maxAckDelayMicros: 25_000));
        }
    }
}
