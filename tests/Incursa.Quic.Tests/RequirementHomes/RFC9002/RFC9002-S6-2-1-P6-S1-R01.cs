// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-2-1-P6-S1-R01">When ack-eliciting packets in multiple packet number spaces are in flight, the PTO timer MUST be set to the earlier value of the Initial and Handshake packet number spaces.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-2-1-P6-S1-R01")]
public sealed class RFC9002_S6_2_1_P6_S1_R01
{
    public static TheoryData<SharedDeadlineCase> SharedDeadlineCases => new()
    {
        new(2_500, 2_500, 2_500),
        new(3_000, 3_000, 3_000),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_SelectsTheEarlierDeadline()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 3_000,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsFalseWhenBothTimersAreMissing()
    {
        Assert.False(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            out _));
    }

    [Theory]
    [MemberData(nameof(SharedDeadlineCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesTheSharedDeadlineWhenBothTimersMatch(SharedDeadlineCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: scenario.InitialProbeTimeoutMicros,
            handshakeProbeTimeoutMicros: scenario.HandshakeProbeTimeoutMicros,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(scenario.ExpectedSelectedProbeTimeoutMicros, selectedProbeTimeoutMicros);
    }

    public sealed record SharedDeadlineCase(
        ulong InitialProbeTimeoutMicros,
        ulong HandshakeProbeTimeoutMicros,
        ulong ExpectedSelectedProbeTimeoutMicros);
}
