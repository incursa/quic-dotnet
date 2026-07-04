// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-1-1-P1-S2-R01">Implementations SHOULD NOT use a packet threshold less than 3.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-1-1-P1-S2-R01")]
public sealed class RFC9002_S6_1_1_P1_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDeclarePacketLostByPacketThreshold_AllowsTheRecommendedThreshold()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 10,
            largestAcknowledgedPacketNumber: 13));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldDeclarePacketLostByPacketThreshold_RejectsThresholdsBelowThree()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packetNumber: 10,
                largestAcknowledgedPacketNumber: 12,
                packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold - 1));

        Assert.Equal("packetThreshold", exception.ParamName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheMinimumRecommendedThreshold()
    {
        Assert.True(QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 0,
            largestAcknowledgedPacketNumber: QuicRecoveryTiming.RecommendedPacketThreshold,
            packetThreshold: QuicRecoveryTiming.RecommendedPacketThreshold));
    }
}
