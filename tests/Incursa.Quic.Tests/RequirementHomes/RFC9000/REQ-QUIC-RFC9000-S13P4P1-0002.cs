// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0002")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_ReportsEcnCountsWhenReceivedEcnFieldsAreAccessible()
    {
        // ACK generation consumes received ECN counts directly; sender-side ECT policy is not part of this path.
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
    }
}
