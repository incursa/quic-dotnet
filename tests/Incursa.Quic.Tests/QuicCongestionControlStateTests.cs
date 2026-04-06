namespace Incursa.Quic.Tests;

public sealed class QuicCongestionControlStateTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4-0001">QUIC endpoints MAY use ECN [RFC3168] to detect and respond to network congestion.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2-0001">To ensure connectivity in the presence of such devices, an endpoint MUST validate the ECN counts for each network path and disable the use of ECN on that path if errors are detected.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0005">The congestion controller MUST be per path, so packets sent on other paths do not alter the current path&apos;s congestion controller.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0001">QUIC MUST begin every connection in slow start with the congestion window set to an initial value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0002">Endpoints SHOULD use an initial congestion window of ten times the maximum datagram size while limiting the window to the larger of 14,720 bytes or twice the maximum datagram size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0005">The minimum congestion window SHOULD be 2 * max_datagram_size.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent()
    {
        QuicCongestionControlState firstPath = new();
        QuicCongestionControlState secondPath = new(1_500);

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, firstPath.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, firstPath.CongestionWindowBytes);
        Assert.Equal(2_400UL, firstPath.MinimumCongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, firstPath.SlowStartThresholdBytes);
        Assert.Equal(0UL, firstPath.BytesInFlightBytes);
        Assert.True(firstPath.IsInSlowStart);

        Assert.Equal(1_500UL, secondPath.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, secondPath.CongestionWindowBytes);
        Assert.Equal(3_000UL, secondPath.MinimumCongestionWindowBytes);

        firstPath.RegisterPacketSent(1_200);
        Assert.Equal(1_200UL, firstPath.BytesInFlightBytes);
        Assert.Equal(0UL, secondPath.BytesInFlightBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0003">If the maximum datagram size changes during the connection, the initial congestion window SHOULD be recalculated with the new size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0004">If the maximum datagram size is decreased in order to complete the handshake, the congestion window SHOULD be set to the new initial congestion window.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ComputeInitialWindowAndResetToInitialWindow_FollowTheDatagramSize()
    {
        Assert.Equal(12_000UL, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_200));
        Assert.Equal(14_720UL, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_500));
        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(1_200));

        QuicCongestionControlState state = new(1_200);
        state.RegisterPacketSent(1_200);
        state.UpdateMaxDatagramSize(1_500, resetToInitialWindow: true);

        Assert.Equal(1_500UL, state.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
    }

    [Theory]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0002">Endpoints SHOULD use an initial congestion window of ten times the maximum datagram size while limiting the window to the larger of 14,720 bytes or twice the maximum datagram size.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
    [InlineData(1_472UL, 14_720UL, 2_944UL)]
    [InlineData(7_361UL, 14_722UL, 14_722UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ComputeInitialCongestionWindowBytes_HonorsTheTransitionPoints(
        ulong maxDatagramSizeBytes,
        ulong expectedInitialCongestionWindowBytes,
        ulong expectedMinimumCongestionWindowBytes)
    {
        Assert.Equal(expectedInitialCongestionWindowBytes, QuicCongestionControlState.ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes));
        Assert.Equal(expectedMinimumCongestionWindowBytes, QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P2-0002">Endpoints SHOULD use an initial congestion window of ten times the maximum datagram size while limiting the window to the larger of 14,720 bytes or twice the maximum datagram size.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ComputeInitialCongestionWindowBytes_RejectsZeroDatagramSizes()
    {
        ArgumentOutOfRangeException initialException = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(0));
        Assert.Equal("maxDatagramSizeBytes", initialException.ParamName);

        ArgumentOutOfRangeException minimumException = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(0));
        Assert.Equal("maxDatagramSizeBytes", minimumException.ParamName);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0002">Packets containing only ACK frames MUST NOT count toward bytes in flight.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0003">Packets containing only ACK frames MUST NOT be congestion controlled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0004">QUIC MAY use loss of ACK-only packets to adjust the congestion controller or the rate of ACK-only packets being sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0006">An endpoint MUST NOT send a packet if it would cause bytes_in_flight to be larger than the congestion window, unless the packet is sent on a PTO timer expiration or when entering recovery.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P5-0001">Probe packets MUST NOT be blocked by the congestion controller.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P5-0002">A sender MUST count these packets as being additionally in flight.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7-0006")]
    [Requirement("REQ-QUIC-RFC9002-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.CanSend(1_200, isAckOnlyPacket: true));
        Assert.True(state.CanSend(1_200, isProbePacket: true));

        state.RegisterPacketSent(state.CongestionWindowBytes);
        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
        Assert.True(state.CanSend(1, isProbePacket: true));

        state.RegisterPacketSent(1_200, isProbePacket: true);
        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);
        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0004">QUIC MAY use loss of ACK-only packets to adjust the congestion controller or the rate of ACK-only packets being sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P1-0001">If a path has been validated to support ECN, QUIC MUST treat a CE codepoint in the IP header as a signal of congestion.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P1-0001">A sender MUST enter a recovery period when it detects packet loss or when the ECN-CE count reported by its peer increases.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P1-0002">A NewReno sender MUST be considered in slow start any time the congestion window is below the slow start threshold.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P1-0003">While a sender is in slow start, the congestion window MUST increase by the number of bytes acknowledged when each acknowledgment is processed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0001">A sender that is already in a recovery period MUST stay in that recovery period.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0003">On entering a recovery period, a sender MUST set the slow start threshold to half the congestion window when loss is detected.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0004">The congestion window MUST be set to the reduced value of the slow start threshold before exiting the recovery period.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0005">Implementations MAY reduce the congestion window immediately upon entering a recovery period or use other mechanisms, such as Proportional Rate Reduction, to reduce the congestion window more gradually.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0006">During a recovery period, the congestion window MUST NOT change in response to new losses or increases in the ECN-CE count.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P2-0007">A recovery period MUST end and the sender enter congestion avoidance when a packet sent during the recovery period is acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P3-0001">A NewReno sender MUST be considered in congestion avoidance any time the congestion window is at or above the slow start threshold and not in a recovery period.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P3-0002">A sender in congestion avoidance MUST limit the increase to the congestion window to at most one maximum datagram size for each congestion window that is acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P4-0001">Endpoints MAY ignore the loss of Handshake, 0-RTT, and 1-RTT packets that might have arrived before the peer had packet protection keys to process those packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P4-0002">Endpoints MUST NOT ignore the loss of packets that were sent after the earliest acknowledged packet in a given packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0006")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P2-0007")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P3P3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P4-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P4-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals()
    {
        QuicCongestionControlState ackOnlyLossState = new();
        Assert.True(ackOnlyLossState.TryRegisterLoss(
            sentBytes: 0,
            sentAtMicros: 500,
            packetInFlight: false,
            allowAckOnlyLossSignal: true));
        Assert.Equal(500UL, ackOnlyLossState.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, ackOnlyLossState.CongestionWindowBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));
        Assert.Equal(13_200UL, state.CongestionWindowBytes);

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 100,
            packetInFlight: true,
            packetCanBeDecrypted: false,
            keysAvailable: false,
            sentAfterEarliestAcknowledgedPacket: false));
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            packetCanBeDecrypted: true,
            keysAvailable: true,
            sentAfterEarliestAcknowledgedPacket: true));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_600UL, state.CongestionWindowBytes);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_500,
            pathValidated: false));
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);

        Assert.True(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 2,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: true));
        Assert.Equal(3_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(3_300UL, state.CongestionWindowBytes);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_500,
            packetInFlight: true));
        Assert.Equal(3_300UL, state.CongestionWindowBytes);

        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 4_000,
            packetInFlight: true));
        Assert.Equal(3_736UL, state.CongestionWindowBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0001">If a sender uses a different controller than the one specified in this document, the chosen controller MUST conform to the congestion-control guidelines in Section 3.1 of RFC 8085.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0001">A sender SHOULD pace sending of all in-flight packets based on input from the congestion controller.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0002">Senders MUST either use pacing or limit such bursts.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0003">Senders SHOULD limit bursts to the initial congestion window.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0004">A sender with knowledge that the network path can absorb larger bursts MAY use a higher limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0005">Packets containing only ACK frames SHOULD therefore not be paced.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0001">When bytes in flight is smaller than the congestion window and sending is not pacing limited, the congestion window SHOULD NOT be increased in either slow start or congestion avoidance.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0002">A sender SHOULD NOT consider itself application limited if it would have fully utilized the congestion window without pacing delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0003">A sender MAY implement alternative mechanisms to update its congestion window after periods of underutilization, such as those proposed for TCP in RFC 7661.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P8-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: false,
            out ulong pacingIntervalMicros));
        Assert.Equal(100UL, pacingIntervalMicros);

        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: true,
            out ulong ackOnlyIntervalMicros));
        Assert.Equal(0UL, ackOnlyIntervalMicros);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: false,
            out ulong cappedBurstBytes));
        Assert.Equal(12_000UL, cappedBurstBytes);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong expandedBurstBytes,
            largerBurstLimitBytes: 24_000));
        Assert.Equal(24_000UL, expandedBurstBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: false));
        Assert.Equal(12_000UL, state.CongestionWindowBytes);

        state = new QuicCongestionControlState();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P4-0002">Loss of a QUIC packet that is carried in a PMTU probe SHOULD NOT trigger a congestion control reaction.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S14P4-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_IgnoresProbePacketLossForCongestionControl()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isProbePacket: true);
        Assert.Equal(1_200UL, state.BytesInFlightBytes);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            isProbePacket: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P1-0001">The persistent congestion duration MUST be computed as (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P1-0002">Unlike PTO computation, this duration MUST include max_ack_delay irrespective of the packet number spaces in which losses are established.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P1-0003">The RECOMMENDED value for kPersistentCongestionThreshold SHOULD be 3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6-0001">When a sender establishes loss of all packets sent over a long enough duration, the network MUST be considered to be experiencing persistent congestion.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0001">A sender MUST establish persistent congestion after receipt of an acknowledgment if two ack-eliciting packets are declared lost and the conditions in the following list are all met.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0002">Those two packets MUST be ack-eliciting.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0003">Persistent congestion SHOULD NOT start until there is at least one RTT sample.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0004">Persistent congestion SHOULD consider packets sent across packet number spaces.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0005">A sender that does not have state for all packet number spaces or cannot compare send times across packet number spaces MAY use state for just the packet number space that was acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0006">When persistent congestion is declared, the sender&apos;s congestion window MUST be reduced to the minimum congestion window.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow()
    {
        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out ulong durationMicros));
        Assert.Equal(6_000UL, durationMicros);

        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 400,
            maxAckDelayMicros: 500,
            out ulong adjustedDurationMicros));
        Assert.Equal(9_300UL, adjustedDurationMicros);

        Assert.Equal(9_000UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            12_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));

        Assert.Equal(2_400UL, QuicCongestionControlState.ComputeReducedCongestionWindowBytes(
            1_000,
            reductionNumerator: 3,
            reductionDenominator: 4,
            minimumCongestionWindowBytes: 2_400));

        QuicCongestionControlState failingState = new();
        QuicPersistentCongestionPacket[] failingPackets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.Handshake, 5_000, 1_200, true, true, acknowledged: true, lost: false),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(failingState.TryDetectPersistentCongestion(
            failingPackets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool failingPersistentCongestionDetected));
        Assert.False(failingPersistentCongestionDetected);
        Assert.Equal(6_000UL, failingState.CongestionWindowBytes);
        Assert.True(failingState.HasRecoveryStartTime);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        QuicPersistentCongestionPacket[] packets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(state.TryDetectPersistentCongestion(
            packets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0003">Persistent congestion SHOULD NOT start until there is at least one RTT sample.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryDetectPersistentCongestion_StartsOnceAnRttSampleIsAvailable()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        QuicPersistentCongestionPacket[] packets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(state.TryDetectPersistentCongestion(
            packets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P6P2-0003">Persistent congestion SHOULD NOT start until there is at least one RTT sample.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryDetectPersistentCongestion_DoesNotStartBeforeAnyRttSampleExists()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        QuicPersistentCongestionPacket[] packets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.False(state.TryDetectPersistentCongestion(
            packets,
            firstRttSampleMicros: 0,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void SenderFlowController_UsesAckFramesToAcknowledgeAndReduceFlight()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentBytes: 1_200,
            sentAtMicros: 1_100,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            sentBytes: 1_200,
            sentAtMicros: 1_200,
            ackEliciting: true);

        Assert.Equal(3_600UL, sender.CongestionControlState.BytesInFlightBytes);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 3,
            AckDelay = 100,
            FirstAckRange = 2,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pacingLimited: true));

        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(15_600UL, sender.CongestionControlState.CongestionWindowBytes);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            sentBytes: 1_200,
            sentAtMicros: 2_100,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            sentBytes: 1_200,
            sentAtMicros: 2_200,
            ackEliciting: true);

        Assert.Equal(2_400UL, sender.CongestionControlState.BytesInFlightBytes);
        Assert.False(sender.CongestionControlState.HasRecoveryStartTime);
        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            sentAtMicros: 2_500));
        Assert.True(sender.CongestionControlState.HasRecoveryStartTime);
        Assert.Equal(7_800UL, sender.CongestionControlState.SlowStartThresholdBytes);
        Assert.Equal(7_800UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(1_200UL, sender.CongestionControlState.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void SenderFlowController_ProcessesEcnInAckFrames()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentBytes: 1_200,
            sentAtMicros: 1_100,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 2,
            AckDelay = 0,
            FirstAckRange = 1,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
            EcnCounts = new QuicEcnCounts(0, 0, 1),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true,
            pacingLimited: true));

        Assert.True(sender.CongestionControlState.HasRecoveryStartTime);
        Assert.Equal(7_200UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(7_200UL, sender.CongestionControlState.SlowStartThresholdBytes);
    }
}
