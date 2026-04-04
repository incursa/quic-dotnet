namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_PrefersTheLossDetectionTimerOverPtoTimers()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: 1_500,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(1_500UL, selectedTimerMicros);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimerMicros_CancelsTheTimerWhenRecoveryIsBlocked(
        bool serverAtAntiAmplificationLimit,
        bool noAckElicitingPacketsInFlight,
        bool peerAddressValidationComplete)
    {
        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: serverAtAntiAmplificationLimit,
            noAckElicitingPacketsInFlight: noAckElicitingPacketsInFlight,
            peerAddressValidationComplete: peerAddressValidationComplete,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimerMicros_UsesThePtoTimeoutWhenNoLossTimeIsPending()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }
}
