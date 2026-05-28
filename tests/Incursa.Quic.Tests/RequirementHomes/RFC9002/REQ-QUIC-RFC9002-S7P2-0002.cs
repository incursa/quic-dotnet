// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0002">Endpoints SHOULD use an initial congestion window of ten times the maximum datagram size while limiting the window to the larger of 14,720 bytes or twice the maximum datagram size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
public sealed class REQ_QUIC_RFC9002_S7P2_0002
{
    public static TheoryData<InitialCongestionWindowCase> InitialCongestionWindowCases => new()
    {
        new(1_472, 14_720, 2_944),
        new(7_361, 14_722, 14_722),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ComputeInitialCongestionWindowBytes_UsesTenMaximumDatagramsAtTheDefaultFloor()
    {
        Assert.Equal(12_000UL, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_200));
        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(1_200));
    }

    [Theory]
    [MemberData(nameof(InitialCongestionWindowCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeInitialCongestionWindowBytes_HonorsTheTransitionPoints(InitialCongestionWindowCase scenario)
    {
        Assert.Equal(scenario.ExpectedInitialCongestionWindowBytes, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(scenario.MaxDatagramSizeBytes));
        Assert.Equal(scenario.ExpectedMinimumCongestionWindowBytes, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(scenario.MaxDatagramSizeBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ComputeInitialCongestionWindowBytes_RejectsZeroDatagramSizes()
    {
        ArgumentOutOfRangeException initialException = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(0));
        Assert.Equal("maxDatagramSizeBytes", initialException.ParamName);

        ArgumentOutOfRangeException minimumException = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(0));
        Assert.Equal("maxDatagramSizeBytes", minimumException.ParamName);
    }

    public sealed record InitialCongestionWindowCase(
        ulong MaxDatagramSizeBytes,
        ulong ExpectedInitialCongestionWindowBytes,
        ulong ExpectedMinimumCongestionWindowBytes);
}
