namespace Incursa.Quic.Tests;

public sealed class QuicRecoveryTimingTests
{
    [Theory]
    [InlineData(false, true, 9, true)]
    [InlineData(true, true, 9, false)]
    [InlineData(false, false, 9, false)]
    [InlineData(false, true, 10, true)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1-0001">A packet MUST be unacknowledged, in flight, and sent before an acknowledged packet before it can be declared lost.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P1-0001">The packet reordering threshold SHOULD be 3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P1-0002">Implementations SHOULD NOT use a packet threshold less than 3.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P1-0002">Implementations SHOULD NOT use a packet threshold less than 3.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0002">To avoid declaring packets lost too early, the time threshold MUST be at least the local timer granularity.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0003">The time threshold MUST be max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0005">The RECOMMENDED time threshold multiplier, kTimeThreshold, SHOULD be 9/8.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0006">The RECOMMENDED timer granularity, kGranularity, SHOULD be 1 millisecond.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0001">Once a later packet within the same packet number space has been acknowledged, an endpoint SHOULD declare an earlier packet lost if it was sent a threshold amount of time in the past.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P1P2-0004">If packets sent prior to the largest acknowledged packet cannot yet be declared lost, a timer SHOULD be set for the remaining time.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2-0002">The PTO MUST be computed separately for each packet number space.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0001">When an ack-eliciting packet is transmitted, the sender MUST schedule a PTO timer using PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0002">When the PTO is armed for the Initial or Handshake packet number spaces, the max_ack_delay in the PTO computation MUST be set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0003">The PTO period MUST be at least kGranularity.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0005">An endpoint MUST NOT set its PTO timer for the Application Data packet number space until the handshake is confirmed.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0005">An endpoint MUST NOT set its PTO timer for the Application Data packet number space until the handshake is confirmed.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0007">When a PTO timer expires, the PTO backoff MUST be increased, which doubles the PTO period.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0004">When ack-eliciting packets in multiple packet number spaces are in flight, the PTO timer MUST be set to the earlier value of the Initial and Handshake packet number spaces.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0010">The PTO timer MUST NOT be set if a timer is set for time-threshold loss detection.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0004">The client MAY compute an RTT estimate to the server as the time period from when the first Initial packet was sent to when a Retry or Version Negotiation packet is received.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0005">The client MAY use this value in place of its default for the initial RTT estimate.</workbench-requirement>
    /// </workbench-requirements>
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
