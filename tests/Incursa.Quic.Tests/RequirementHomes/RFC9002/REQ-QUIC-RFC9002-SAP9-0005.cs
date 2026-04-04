namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP9-0005")]
public sealed class REQ_QUIC_RFC9002_SAP9_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TimeoutHandling_DoublesThePtoBackoffAndRefreshesTheTimer()
    {
        ulong refreshedProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: 2_500,
            ptoCount: 1);

        Assert.Equal(5_000UL, refreshedProbeTimeoutMicros);

        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: refreshedProbeTimeoutMicros,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(5_000UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TimeoutHandling_LeavesTheBasePtoInPlaceBeforeAnyBackoffIncrement()
    {
        ulong refreshedProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: 2_500,
            ptoCount: 0);

        Assert.Equal(2_500UL, refreshedProbeTimeoutMicros);

        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: refreshedProbeTimeoutMicros,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(2_500UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimeoutHandling_SaturatesTheBackoffBeforeRefreshingTheTimer()
    {
        ulong refreshedProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: (ulong.MaxValue / 2) + 1,
            ptoCount: 1);

        Assert.Equal(ulong.MaxValue, refreshedProbeTimeoutMicros);

        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: refreshedProbeTimeoutMicros,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(ulong.MaxValue, selectedTimerMicros);
    }
}
