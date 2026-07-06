// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1177")]
public sealed class REQ_QUIC_RFC9000_1177
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1177")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_UsesPacketNumberAndPacketNumberSpaceTogether()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(QuicPacketNumberSpace.Handshake, packetNumber: 4, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(4),
            ackReceivedAtMicros: 2_000));

        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 4,
            sentAtMicros: 3_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1177")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_WrongPacketNumberSpaceDoesNotAcknowledgeSameNumber()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(QuicPacketNumberSpace.Handshake, packetNumber: 4, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);

        Assert.False(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(4),
            ackReceivedAtMicros: 2_000));

        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 4,
            sentAtMicros: 3_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1177")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_SameAckNumberCanBeAppliedIndependentlyPerSpace()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(QuicPacketNumberSpace.Initial, packetNumber: 0, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);
        sender.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, packetNumber: 0, sentBytes: 1_200, sentAtMicros: 2_000, ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(0),
            ackReceivedAtMicros: 3_000));
        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(0),
            ackReceivedAtMicros: 4_000));
        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1177")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckProcessingCombinesPacketNumberWithItsPacketNumberSpace()
    {
        QuicPacketNumberSpace[] packetNumberSpaces =
        [
            QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.ApplicationData,
        ];

        foreach (QuicPacketNumberSpace acknowledgedSpace in packetNumberSpaces)
        {
            foreach (ulong packetNumber in new ulong[] { 0, 1, 7, 63, 511 })
            {
                QuicSenderFlowController sender = new();
                foreach (QuicPacketNumberSpace packetNumberSpace in packetNumberSpaces)
                {
                    sender.RecordPacketSent(
                        packetNumberSpace,
                        packetNumber,
                        sentBytes: 1_200,
                        sentAtMicros: 1_000 + packetNumber,
                        ackEliciting: true);
                }

                Assert.True(sender.TryProcessAckFrame(
                    acknowledgedSpace,
                    QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(packetNumber),
                    ackReceivedAtMicros: 10_000 + packetNumber));

                foreach (QuicPacketNumberSpace packetNumberSpace in packetNumberSpaces)
                {
                    bool lossRegistered = sender.TryRegisterLoss(
                        packetNumberSpace,
                        packetNumber,
                        sentAtMicros: 20_000 + packetNumber);

                    Assert.Equal(packetNumberSpace != acknowledgedSpace, lossRegistered);
                }
            }
        }
    }
}
