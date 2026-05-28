// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0004")]
public sealed class REQ_QUIC_RFC9000_S19P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_ValidatedEcnCeFeedbackReducesCongestionWindow()
    {
        QuicSenderFlowController sender = new();
        ulong initialCongestionWindow = sender.CongestionControlState.CongestionWindowBytes;

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        QuicAckFrame ackFrame = QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(1, frameType: 0x03);
        ackFrame.EcnCounts = new QuicEcnCounts(ect0Count: 1, ect1Count: 0, ecnCeCount: 1);

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));

        Assert.True(sender.CongestionControlState.CongestionWindowBytes < initialCongestionWindow);
    }
}
