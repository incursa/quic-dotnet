// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S13-2-1-P3-R01">Since packets containing only ACK frames are not congestion controlled, an endpoint MUST NOT send more than one such packet in response to receiving an ack-eliciting packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S13-2-1-P3-R01")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSendAckOnlyPacket_AllowsTheFirstAckOnlyPacketForAnAckElicitingApplicationDataPacket()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSendAckOnlyPacket_RejectsASecondAckOnlyPacketForTheSameAckElicitingApplicationDataPacket()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSendAckOnlyPacket_RearmsAfterTheNextAckElicitingApplicationDataPacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            ackEliciting: true,
            receivedAtMicros: 1_600);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_700,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CanSendAckOnlyPacket_FuzzAllowsOnlyOneAckOnlyPacketPerAckElicitingTrigger()
    {
        foreach ((ulong PacketNumber, ulong ReceivedAtMicros, ulong SentAtMicros, ulong NextPacketNumber) testCase in new[]
        {
            (1UL, 1_000UL, 1_250UL, 2UL),
            (7UL, 2_000UL, 2_500UL, 8UL),
            (63UL, 4_000UL, 4_125UL, 64UL),
        })
        {
            QuicSenderFlowController sender = new();
            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                testCase.PacketNumber,
                ackEliciting: true,
                testCase.ReceivedAtMicros);

            Assert.True(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: testCase.SentAtMicros,
                maxAckDelayMicros: 1_000));

            sender.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                testCase.SentAtMicros,
                ackOnlyPacket: true);

            Assert.False(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: testCase.SentAtMicros + 1,
                maxAckDelayMicros: 1_000));

            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                testCase.NextPacketNumber,
                ackEliciting: true,
                testCase.SentAtMicros + 2);

            Assert.True(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: testCase.SentAtMicros + 3,
                maxAckDelayMicros: 1_000));
        }
    }
}
