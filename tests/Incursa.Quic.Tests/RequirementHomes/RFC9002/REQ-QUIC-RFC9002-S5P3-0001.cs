// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0001">The calculation of smoothed_rtt MUST use RTT samples after adjusting them for acknowledgment delays.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0001")]
public sealed class REQ_QUIC_RFC9002_S5P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_UsesAdjustedRttWhenUpdatingSmoothedRtt()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_100,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 400,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 400));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_600UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_025UL, estimator.SmoothedRttMicros);
        Assert.Equal(425UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotSubtractAckDelayWhenItExceedsTheAvailableSlack()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 700));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryUpdateFromAck_UsesTheAdjustedSampleAtTheAckDelayBoundary()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(375UL, estimator.RttVarMicros);
    }

    private static QuicRttEstimator CreatePrimedEstimator()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        return estimator;
    }
}
