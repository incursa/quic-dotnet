namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP9-0001")]
public sealed class REQ_QUIC_RFC9002_SAP9_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TimeoutHandling_PrefersTheEarliestLossSpaceBeforePtoWork()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: 4_500,
            handshakeLossTimeMicros: 1_800,
            applicationDataLossTimeMicros: 3_000,
            out ulong selectedLossTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(1_800UL, selectedLossTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);

        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: selectedLossTimeMicros,
            probeTimeoutMicros: 2_500,
            out ulong selectedTimerMicros));

        Assert.Equal(1_800UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TimeoutHandling_FallsBackToPtoWhenNoLossTimeExists()
    {
        Assert.False(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: null,
            handshakeLossTimeMicros: null,
            applicationDataLossTimeMicros: null,
            out _,
            out _));

        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: null,
            probeTimeoutMicros: 2_500,
            out ulong selectedTimerMicros));

        Assert.Equal(2_500UL, selectedTimerMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TimeoutHandling_PrefersAnImmediateLossDeadlineAtTheBoundary()
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: 0,
            probeTimeoutMicros: 1,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }
}
