// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0006")]
public sealed class REQ_QUIC_RFC9000_S19P3_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckGeneration_AllowsSameNumericPacketNumberInDifferentSpaces()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(QuicPacketNumberSpace.Initial, packetNumber: 7, ackEliciting: true, receivedAtMicros: 1_000);
        state.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, packetNumber: 7, ackEliciting: true, receivedAtMicros: 2_000);

        Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1_100, out QuicAckFrame initialAck));
        Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 2_100, out QuicAckFrame handshakeAck));
        Assert.Equal(7UL, initialAck.LargestAcknowledged);
        Assert.Equal(7UL, handshakeAck.LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotAcknowledgeSamePacketNumberInOtherSpaces()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(QuicPacketNumberSpace.Initial, packetNumber: 7, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);
        sender.RecordPacketSent(QuicPacketNumberSpace.Handshake, packetNumber: 7, sentBytes: 1_200, sentAtMicros: 2_000, ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(7),
            ackReceivedAtMicros: 3_000));

        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 7,
            sentAtMicros: 4_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void AckGeneration_DiscardingOneSpaceLeavesSameNumberInAnotherSpace()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(QuicPacketNumberSpace.Initial, packetNumber: 0, ackEliciting: true, receivedAtMicros: 1_000);
        state.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, packetNumber: 0, ackEliciting: true, receivedAtMicros: 2_000);

        Assert.True(state.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.False(state.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 3_000, out _));
        Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 3_000, out QuicAckFrame handshakeAck));
        Assert.Equal(0UL, handshakeAck.LargestAcknowledged);
    }
}
