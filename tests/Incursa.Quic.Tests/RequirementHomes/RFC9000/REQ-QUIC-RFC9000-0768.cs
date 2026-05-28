// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
/// <workbench-requirement requirementId="REQ-QUIC-RFC9000-0768">A receiver MUST retain an ACK Range unless it can ensure that it will not subsequently accept packets with numbers in that range.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0768")]
public sealed class REQ_QUIC_RFC9000_0768
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRetireAcknowledgedAckRanges_RetiresRangesWhenTheCarrierPacketIsAcknowledged()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(3, 1, 2, 5, 6, 9);
        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));

        tracker.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            new QuicAckFrame
            {
                LargestAcknowledged = 9,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges =
                [
                    new QuicAckRange(1, 1, 5, 6),
                    new QuicAckRange(1, 1, 1, 2),
                ],
            },
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        Assert.True(tracker.TryRetireAcknowledgedAckRanges(
            QuicPacketNumberSpace.ApplicationData,
            ackedPacketNumber: 11));
        Assert.False(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 3_100, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRetireAcknowledgedAckRanges_LeavesRangesWhenASeparatePacketNumberSpaceAcknowledgesTheCarrierPacket()
    {
        QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(3, 1, 2, 5, 6, 9);
        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));

        tracker.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            new QuicAckFrame
            {
                LargestAcknowledged = 9,
                AckDelay = 0,
                FirstAckRange = 0,
                AdditionalRanges =
                [
                    new QuicAckRange(1, 1, 5, 6),
                    new QuicAckRange(1, 1, 1, 2),
                ],
            },
            sentAtMicros: 2_100,
            ackOnlyPacket: true);

        Assert.False(tracker.TryRetireAcknowledgedAckRanges(
            QuicPacketNumberSpace.Initial,
            ackedPacketNumber: 11));
        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 9,
            expectedFirstAckRange: 0,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));
    }
}
