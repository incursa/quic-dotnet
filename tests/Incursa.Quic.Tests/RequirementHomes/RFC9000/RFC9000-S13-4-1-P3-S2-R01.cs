// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S13-4-1-P3-S2-R01")]
public sealed class RFC9000_S13_4_1_P3_S2_R01
{
    [Fact]
    [Requirement("RFC9000-S13-4-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesEcnCountsInSubsequentAckFrames()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 4000, out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
    }
}
