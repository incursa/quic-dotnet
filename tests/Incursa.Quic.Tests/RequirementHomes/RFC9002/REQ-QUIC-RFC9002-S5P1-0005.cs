// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0005">An RTT sample MUST NOT be generated on receiving an ACK frame that does not newly acknowledge at least one ack-eliciting packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
public sealed class REQ_QUIC_RFC9002_S5P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_GeneratesSampleForNewAckElicitingProgress()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotGenerateSampleForNewlyAcknowledgedNonAckElicitingPackets()
    {
        QuicRttEstimator estimator = new();

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: false));

        Assert.False(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryUpdateFromAck_PreservesExistingRttSampleWhenAckElicitingProgressIsAbsent()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 4_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: false));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }
}
