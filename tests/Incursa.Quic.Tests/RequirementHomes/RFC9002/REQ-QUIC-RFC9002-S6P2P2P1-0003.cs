namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2P1-0003">If the PTO timer is then set to a time in the past, it MUST be executed immediately.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TrySelectRecoveryTimerMicros_ReturnsThePtoDeadlineImmediatelyWhenItIsAlreadyDue()
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: null,
            probeTimeoutMicros: 0,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TrySelectRecoveryTimerMicros_ReturnsFalseWhenNoRecoveryTimersAreAvailable()
    {
        Assert.False(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: null,
            probeTimeoutMicros: null,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TrySelectRecoveryTimerMicros_PreservesAOneMicrosecondPtoDeadline()
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: null,
            probeTimeoutMicros: 1,
            out ulong selectedTimerMicros));

        Assert.Equal(1UL, selectedTimerMicros);
    }
}
