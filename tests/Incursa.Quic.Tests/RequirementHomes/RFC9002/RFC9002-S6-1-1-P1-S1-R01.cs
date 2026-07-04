// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-1-1-P1-S1-R01">The initial value for the packet reordering threshold (kPacketThreshold) is RECOMMENDED to be 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-1-1-P1-S1-R01")]
public sealed class RFC9002_S6_1_1_P1_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDeclarePacketLostByPacketThreshold_DeclaresPacketsOlderThanTheRecommendedThreshold()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 6,
            largestAcknowledgedPacketNumber: 10));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldDeclarePacketLostByPacketThreshold_DoesNotUseAThresholdAboveThreeAtTheBoundary()
    {
        Assert.False(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold + 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheThreePacketBoundary()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold));
    }
}
