namespace Incursa.Quic.Tests;

public sealed class QuicRecoveryTimingTests
{
    [Theory]
    [InlineData(false, true, 9, true)]
    [InlineData(true, true, 9, false)]
    [InlineData(false, false, 9, false)]
    [InlineData(false, true, 10, true)]
    [Requirement("REQ-QUIC-RFC9002-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanDeclarePacketLost_RequiresAnUnacknowledgedInFlightPacketSentBeforeAnAcknowledgedPacket(
        bool packetAcknowledged,
        bool packetInFlight,
        ulong packetNumber,
        bool expected)
    {
        Assert.Equal(expected, QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged,
            packetInFlight,
            packetNumber,
            largestAcknowledgedPacketNumber: 11));
    }

    [Theory]
    [InlineData(8UL, 11UL, true)]
    [InlineData(9UL, 11UL, false)]
    [InlineData(6UL, 9UL, true)]
    [Requirement("REQ-QUIC-RFC9002-S6P1P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDeclarePacketLostByPacketThreshold_UsesTheRecommendedThresholdOfThree(
        ulong packetNumber,
        ulong largestAcknowledgedPacketNumber,
        bool expected)
    {
        Assert.Equal(expected, QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber,
            largestAcknowledgedPacketNumber));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1P1-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldDeclarePacketLostByPacketThreshold_RejectsThresholdsBelowThree()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
            packetNumber: 8,
            largestAcknowledgedPacketNumber: 11,
            packetThreshold: 2));
    }

    [Theory]
    [InlineData(800UL, 1_000UL, 1_125UL)]
    [InlineData(1UL, 1UL, 1_000UL)]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ComputeLossDelayMicros_UsesTheRttAndGranularityThresholds(
        ulong latestRttMicros,
        ulong smoothedRttMicros,
        ulong expectedLossDelayMicros)
    {
        Assert.Equal(expectedLossDelayMicros, QuicRecoveryTiming.ComputeLossDelayMicros(latestRttMicros, smoothedRttMicros));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputeRemainingLossDelayMicros_SchedulesTheRemainingTimeBeforeLoss()
    {
        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros: 1_000,
            nowMicros: 2_000,
            latestRttMicros: 800,
            smoothedRttMicros: 1_000,
            out ulong remainingLossDelayMicros));

        Assert.Equal(125UL, remainingLossDelayMicros);

        Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
            packetSentAtMicros: 1_000,
            nowMicros: 3_500,
            latestRttMicros: 800,
            smoothedRttMicros: 1_000,
            out ulong expiredLossDelayMicros));

        Assert.Equal(0UL, expiredLossDelayMicros);
    }

    [Theory]
    [InlineData(QuicPacketNumberSpace.Initial, false, 2_000UL)]
    [InlineData(QuicPacketNumberSpace.Handshake, false, 2_000UL)]
    [InlineData(QuicPacketNumberSpace.ApplicationData, true, 2_500UL)]
    [Requirement("REQ-QUIC-RFC9002-S6P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula(
        QuicPacketNumberSpace packetNumberSpace,
        bool handshakeConfirmed,
        ulong expectedProbeTimeoutMicros)
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            packetNumberSpace,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 500,
            handshakeConfirmed,
            out ulong probeTimeoutMicros));

        Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_RejectsApplicationDataBeforeHandshakeConfirmation()
    {
        Assert.False(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 200,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out _));
    }

    [Theory]
    [InlineData(1_000UL, 1, 2_000UL)]
    [InlineData(1_000UL, 2, 4_000UL)]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ComputeProbeTimeoutWithBackoffMicros_DoublesTheBasePtoOnTimeout(
        ulong probeTimeoutMicros,
        int ptoCount,
        ulong expectedBackedOffProbeTimeoutMicros)
    {
        Assert.Equal(expectedBackedOffProbeTimeoutMicros, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros,
            ptoCount));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesTheEarlierValue()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 3_000,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TrySelectRecoveryTimerMicros_PrefersLossDetectionTimersOverPtoTimers()
    {
        Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
            lossDetectionTimerMicros: 1_800,
            probeTimeoutMicros: 2_500,
            out ulong selectedTimerMicros));

        Assert.Equal(1_800UL, selectedTimerMicros);
    }

    [Theory]
    [InlineData(1_000UL, 2_250UL)]
    [InlineData(2_000UL, 3_250UL)]
    [Requirement("REQ-QUIC-RFC9002-S6P3-0004")]
    [Requirement("REQ-QUIC-RFC9002-S6P3-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryMeasureRetryRoundTripMicros_ComputesTheElapsedTimeAndCanSeedInitialRtt(
        ulong firstInitialPacketSentAtMicros,
        ulong retryReceivedAtMicros)
    {
        Assert.True(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
            firstInitialPacketSentAtMicros,
            retryReceivedAtMicros,
            out ulong retryRoundTripMicros));

        Assert.Equal(retryReceivedAtMicros - firstInitialPacketSentAtMicros, retryRoundTripMicros);

        QuicRttEstimator estimator = new(initialRttMicros: retryRoundTripMicros);
        Assert.Equal(retryRoundTripMicros, estimator.SmoothedRttMicros);
    }
}
