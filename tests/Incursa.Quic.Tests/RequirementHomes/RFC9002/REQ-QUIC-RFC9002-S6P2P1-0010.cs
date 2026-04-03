namespace Incursa.Quic.Tests;

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
