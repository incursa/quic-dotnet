namespace Incursa.Quic.Tests;

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
