namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0010">The PTO timer MUST NOT be set if a timer is set for time-threshold loss detection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0010")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0010
{
    public static TheoryData<RecoveryTimerTieCase> RecoveryTimerTieCases => new()
    {
        new(1_800, 1_800, 1_800),
        new(3_500, 3_500, 3_500),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TrySelectRecoveryTimerMicros_ReturnsFalseWhenNoTimersAreAvailable()
    {
        Assert.False(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: null,
            probeTimeoutMicros: null,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectRecoveryTimerMicros_PrefersTheLossDetectionTimerOverPtoTimers()
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: 2_800,
            probeTimeoutMicros: 1_500,
            out ulong selectedTimerMicros));

        Assert.Equal(2_800UL, selectedTimerMicros);
    }

    [Theory]
    [MemberData(nameof(RecoveryTimerTieCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TrySelectRecoveryTimerMicros_PrefersTheLossDetectionTimerWhenTheDeadlinesMatch(RecoveryTimerTieCase scenario)
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: scenario.LossDetectionTimerMicros,
            probeTimeoutMicros: scenario.ProbeTimeoutMicros,
            out ulong selectedTimerMicros));

        Assert.Equal(scenario.ExpectedSelectedTimerMicros, selectedTimerMicros);
    }

    public sealed record RecoveryTimerTieCase(
        ulong LossDetectionTimerMicros,
        ulong ProbeTimeoutMicros,
        ulong ExpectedSelectedTimerMicros);
}
