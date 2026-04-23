namespace Incursa.Quic;

/// <summary>
/// Provides helper methods for RFC 9002 loss-detection and PTO timing calculations that do not require
/// a full sender state machine.
/// </summary>
internal static class QuicRecoveryTiming
{
    /// <summary>
    /// The recommended packet reordering threshold from RFC 9002.
    /// </summary>
    internal const int RecommendedPacketThreshold = 3;

    /// <summary>
    /// The recommended time-threshold numerator from RFC 9002's loss-delay formula.
    /// </summary>
    internal const ulong RecommendedTimeThresholdNumerator = 9;

    /// <summary>
    /// The recommended time-threshold denominator from RFC 9002's loss-delay formula.
    /// </summary>
    internal const ulong RecommendedTimeThresholdDenominator = 8;

    /// <summary>
    /// The recommended timer granularity, in microseconds.
    /// </summary>
    internal const ulong RecommendedTimerGranularityMicros = 1_000;

    /// <summary>
    /// RFC 9002 computes PTO variance with a multiplier of 4.
    /// </summary>
    private const ulong RttVarianceMultiplier = 4;

    /// <summary>
    /// RFC 9002 backs off PTO by doubling it on each timeout.
    /// </summary>
    private const ulong ProbeTimeoutBackoffMultiplier = 2;

    /// <summary>
    /// Determines whether a packet satisfies the basic RFC 9002 loss-declaration preconditions.
    /// </summary>
    internal static bool CanDeclarePacketLost(
        bool packetAcknowledged,
        bool packetInFlight,
        ulong packetNumber,
        ulong largestAcknowledgedPacketNumber)
    {
        return !packetAcknowledged
            && packetInFlight
            && packetNumber < largestAcknowledgedPacketNumber;
    }

    /// <summary>
    /// Determines whether a packet is old enough to be declared lost by packet-threshold logic.
    /// </summary>
    internal static bool ShouldDeclarePacketLostByPacketThreshold(
        ulong packetNumber,
        ulong largestAcknowledgedPacketNumber,
        int packetThreshold = RecommendedPacketThreshold)
    {
        if (packetThreshold < RecommendedPacketThreshold)
        {
            throw new ArgumentOutOfRangeException(nameof(packetThreshold));
        }

        ulong threshold = (ulong)packetThreshold;
        return largestAcknowledgedPacketNumber >= threshold
            && packetNumber <= largestAcknowledgedPacketNumber - threshold;
    }

    /// <summary>
    /// Computes the loss delay from the larger of the latest RTT and smoothed RTT, bounded by timer granularity.
    /// </summary>
    internal static ulong ComputeLossDelayMicros(
        ulong latestRttMicros,
        ulong smoothedRttMicros,
        ulong timeThresholdNumerator = RecommendedTimeThresholdNumerator,
        ulong timeThresholdDenominator = RecommendedTimeThresholdDenominator,
        ulong timerGranularityMicros = RecommendedTimerGranularityMicros)
    {
        if (timeThresholdDenominator == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeThresholdDenominator));
        }

        if (timeThresholdNumerator == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeThresholdNumerator));
        }

        if (timerGranularityMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timerGranularityMicros));
        }

        ulong referenceRttMicros = Math.Max(latestRttMicros, smoothedRttMicros);
        ulong scaledRttMicros = MultiplyAndDivide(referenceRttMicros, timeThresholdNumerator, timeThresholdDenominator);
        return Math.Max(scaledRttMicros, timerGranularityMicros);
    }

    /// <summary>
    /// Computes the remaining time before a packet can be declared lost.
    /// </summary>
    internal static bool TryComputeRemainingLossDelayMicros(
        ulong packetSentAtMicros,
        ulong nowMicros,
        ulong latestRttMicros,
        ulong smoothedRttMicros,
        out ulong remainingLossDelayMicros,
        ulong timeThresholdNumerator = RecommendedTimeThresholdNumerator,
        ulong timeThresholdDenominator = RecommendedTimeThresholdDenominator,
        ulong timerGranularityMicros = RecommendedTimerGranularityMicros)
    {
        ulong lossDelayMicros = ComputeLossDelayMicros(
            latestRttMicros,
            smoothedRttMicros,
            timeThresholdNumerator,
            timeThresholdDenominator,
            timerGranularityMicros);

        ulong lossDeadlineMicros = SaturatingAdd(packetSentAtMicros, lossDelayMicros);
        remainingLossDelayMicros = nowMicros >= lossDeadlineMicros ? 0 : lossDeadlineMicros - nowMicros;
        return true;
    }

    /// <summary>
    /// Computes the PTO delay for a packet number space using RFC 9002's base formula.
    /// </summary>
    internal static bool TryComputeProbeTimeoutMicros(
        QuicPacketNumberSpace packetNumberSpace,
        ulong smoothedRttMicros,
        ulong rttVarMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed,
        out ulong probeTimeoutMicros,
        ulong timerGranularityMicros = RecommendedTimerGranularityMicros)
    {
        probeTimeoutMicros = default;

        if (packetNumberSpace == QuicPacketNumberSpace.ApplicationData && !handshakeConfirmed)
        {
            return false;
        }

        if (timerGranularityMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timerGranularityMicros));
        }

        ulong effectiveMaxAckDelayMicros = packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
            ? default
            : maxAckDelayMicros;

        ulong rttVarianceComponentMicros = MultiplySaturating(rttVarMicros, RttVarianceMultiplier);
        ulong baseTimeoutMicros = SaturatingAdd(
            smoothedRttMicros,
            Math.Max(rttVarianceComponentMicros, timerGranularityMicros));

        baseTimeoutMicros = SaturatingAdd(baseTimeoutMicros, effectiveMaxAckDelayMicros);
        probeTimeoutMicros = Math.Max(baseTimeoutMicros, timerGranularityMicros);
        return true;
    }

    /// <summary>
    /// Applies PTO backoff by doubling the base PTO once per timeout.
    /// </summary>
    internal static ulong ComputeProbeTimeoutWithBackoffMicros(ulong probeTimeoutMicros, int ptoCount)
    {
        if (ptoCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ptoCount));
        }

        ulong backedOffProbeTimeoutMicros = probeTimeoutMicros;
        for (int index = 0; index < ptoCount; index++)
        {
            backedOffProbeTimeoutMicros = MultiplySaturating(backedOffProbeTimeoutMicros, ProbeTimeoutBackoffMultiplier);
            if (backedOffProbeTimeoutMicros == ulong.MaxValue)
            {
                return backedOffProbeTimeoutMicros;
            }
        }

        return backedOffProbeTimeoutMicros;
    }

    /// <summary>
    /// Resets the PTO backoff counter after an event that restarts PTO.
    /// </summary>
    /// <remarks>
    /// A validated acknowledgment, ack-eliciting send, or Initial/Handshake key discard restarts PTO.
    /// Unvalidated Initial acknowledgments keep the current backoff in place.
    /// </remarks>
    internal static int ResetProbeTimeoutBackoffCount(
        int ptoCount,
        bool ackElicitingPacketSent = false,
        bool acknowledgmentReceived = false,
        QuicPacketNumberSpace acknowledgmentPacketNumberSpace = QuicPacketNumberSpace.ApplicationData,
        bool handshakeConfirmed = false,
        bool initialOrHandshakeKeysDiscarded = false)
    {
        if (ptoCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ptoCount));
        }

        if (ackElicitingPacketSent || initialOrHandshakeKeysDiscarded)
        {
            return 0;
        }

        if (acknowledgmentReceived
            && (acknowledgmentPacketNumberSpace != QuicPacketNumberSpace.Initial || handshakeConfirmed))
        {
            return 0;
        }

        return ptoCount;
    }

    /// <summary>
    /// Chooses the earlier PTO deadline from the Initial and Handshake packet number spaces.
    /// </summary>
    internal static bool TrySelectInitialOrHandshakeProbeTimeoutMicros(
        ulong? initialProbeTimeoutMicros,
        ulong? handshakeProbeTimeoutMicros,
        out ulong selectedProbeTimeoutMicros)
    {
        selectedProbeTimeoutMicros = default;

        if (initialProbeTimeoutMicros is null && handshakeProbeTimeoutMicros is null)
        {
            return false;
        }

        if (initialProbeTimeoutMicros is null)
        {
            selectedProbeTimeoutMicros = handshakeProbeTimeoutMicros!.Value;
            return true;
        }

        if (handshakeProbeTimeoutMicros is null)
        {
            selectedProbeTimeoutMicros = initialProbeTimeoutMicros.Value;
            return true;
        }

        selectedProbeTimeoutMicros = Math.Min(initialProbeTimeoutMicros.Value, handshakeProbeTimeoutMicros.Value);
        return true;
    }

    /// <summary>
    /// Selects the earliest nonzero loss time across the packet number spaces and returns the corresponding space.
    /// </summary>
    internal static bool TrySelectLossTimeAndSpaceMicros(
        ulong? initialLossTimeMicros,
        ulong? handshakeLossTimeMicros,
        ulong? applicationDataLossTimeMicros,
        out ulong selectedLossTimeMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        ulong selectedLossTimeMicrosValue = default;
        QuicPacketNumberSpace selectedPacketNumberSpaceValue = default;
        bool hasSelection = false;

        void Consider(ulong? candidateLossTimeMicros, QuicPacketNumberSpace packetNumberSpace)
        {
            if (candidateLossTimeMicros is not > 0)
            {
                return;
            }

            if (hasSelection && candidateLossTimeMicros.Value >= selectedLossTimeMicrosValue)
            {
                return;
            }

            selectedLossTimeMicrosValue = candidateLossTimeMicros.Value;
            selectedPacketNumberSpaceValue = packetNumberSpace;
            hasSelection = true;
        }

        Consider(initialLossTimeMicros, QuicPacketNumberSpace.Initial);
        Consider(handshakeLossTimeMicros, QuicPacketNumberSpace.Handshake);
        Consider(applicationDataLossTimeMicros, QuicPacketNumberSpace.ApplicationData);
        selectedLossTimeMicros = selectedLossTimeMicrosValue;
        selectedPacketNumberSpace = selectedPacketNumberSpaceValue;
        return hasSelection;
    }

    /// <summary>
    /// Selects the PTO deadline and packet number space when no ack-eliciting packets are in flight.
    /// </summary>
    internal static bool TrySelectPtoTimeAndSpaceMicros(
        ulong nowMicros,
        ulong? initialProbeTimeoutMicros,
        ulong? handshakeProbeTimeoutMicros,
        bool handshakeKeysAvailable,
        out ulong selectedPtoTimeMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        selectedPtoTimeMicros = default;
        selectedPacketNumberSpace = default;

        if (handshakeKeysAvailable && handshakeProbeTimeoutMicros is not null)
        {
            selectedPtoTimeMicros = SaturatingAdd(nowMicros, handshakeProbeTimeoutMicros.Value);
            selectedPacketNumberSpace = QuicPacketNumberSpace.Handshake;
            return true;
        }

        if (initialProbeTimeoutMicros is not null)
        {
            selectedPtoTimeMicros = SaturatingAdd(nowMicros, initialProbeTimeoutMicros.Value);
            selectedPacketNumberSpace = QuicPacketNumberSpace.Initial;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Chooses a timer deadline, preferring time-threshold loss detection over PTO when both exist.
    /// </summary>
    internal static bool TrySelectRecoveryTimerMicros(
        ulong? lossDetectionTimerMicros,
        ulong? probeTimeoutMicros,
        out ulong selectedTimerMicros)
    {
        selectedTimerMicros = default;

        if (lossDetectionTimerMicros is not null)
        {
            selectedTimerMicros = lossDetectionTimerMicros.Value;
            return true;
        }

        if (probeTimeoutMicros is not null)
        {
            selectedTimerMicros = probeTimeoutMicros.Value;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Selects the loss-detection timer according to the presence of loss and PTO deadlines.
    /// </summary>
    internal static bool TrySelectLossDetectionTimerMicros(
        ulong? earliestPendingLossTimeMicros,
        ulong? probeTimeoutMicros,
        bool serverAtAntiAmplificationLimit,
        bool noAckElicitingPacketsInFlight,
        bool peerAddressValidationComplete,
        out ulong selectedTimerMicros)
    {
        selectedTimerMicros = default;

        if (earliestPendingLossTimeMicros is not null)
        {
            selectedTimerMicros = earliestPendingLossTimeMicros.Value;
            return true;
        }

        if (serverAtAntiAmplificationLimit
            || (noAckElicitingPacketsInFlight && peerAddressValidationComplete))
        {
            return false;
        }

        if (probeTimeoutMicros is not null)
        {
            selectedTimerMicros = probeTimeoutMicros.Value;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Measures the elapsed time between sending PATH_CHALLENGE data and receiving PATH_RESPONSE data.
    /// </summary>
    internal static bool TryMeasurePathChallengeRoundTripMicros(
        ulong pathChallengeSentAtMicros,
        ulong pathResponseReceivedAtMicros,
        out ulong roundTripMicros)
    {
        roundTripMicros = default;

        if (pathResponseReceivedAtMicros < pathChallengeSentAtMicros)
        {
            return false;
        }

        roundTripMicros = pathResponseReceivedAtMicros - pathChallengeSentAtMicros;
        return true;
    }

    /// <summary>
    /// Measures the elapsed time between the first Initial packet and a Retry packet.
    /// </summary>
    internal static bool TryMeasureRetryRoundTripMicros(
        ulong firstInitialPacketSentAtMicros,
        ulong retryReceivedAtMicros,
        out ulong roundTripMicros)
    {
        roundTripMicros = default;

        if (retryReceivedAtMicros < firstInitialPacketSentAtMicros)
        {
            return false;
        }

        roundTripMicros = retryReceivedAtMicros - firstInitialPacketSentAtMicros;
        return true;
    }

    private static ulong MultiplyAndDivide(ulong value, ulong numerator, ulong denominator)
    {
        ulong wholeQuotient = value / denominator;
        ulong remainder = value % denominator;
        ulong scaledWhole = MultiplySaturating(wholeQuotient, numerator);
        ulong scaledRemainder = (remainder * numerator) / denominator;
        return SaturatingAdd(scaledWhole, scaledRemainder);
    }

    private static ulong MultiplySaturating(ulong value, ulong multiplier)
    {
        if (value == 0 || multiplier == 0)
        {
            return 0;
        }

        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        if (ulong.MaxValue - left < right)
        {
            return ulong.MaxValue;
        }

        return left + right;
    }
}

/// <summary>
/// Describes a packet considered lost by runtime loss detection.
/// </summary>
internal readonly struct QuicLostPacket
{
    /// <summary>
    /// Initializes a lost packet marker.
    /// </summary>
    internal QuicLostPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber)
    {
        PacketNumberSpace = packetNumberSpace;
        PacketNumber = packetNumber;
    }

    /// <summary>
    /// Gets the packet number space for the lost packet.
    /// </summary>
    internal QuicPacketNumberSpace PacketNumberSpace { get; }

    /// <summary>
    /// Gets the lost packet number.
    /// </summary>
    internal ulong PacketNumber { get; }
}

/// <summary>
/// Captures the recovery facts retained for one ack-eliciting packet.
/// </summary>
internal readonly record struct QuicRecoverySentPacketState(
    ulong SentAtMicros,
    QuicTlsEncryptionLevel? PacketProtectionLevel,
    uint? OneRttKeyPhase = null);

/// <summary>
/// Minimal RFC 9002 runtime for loss and PTO timing decisions on a per-space basis.
/// </summary>
internal sealed class QuicRecoveryController
{
    private readonly Dictionary<QuicPacketNumberSpace, QuicRecoveryPacketNumberSpaceState> states;
    private readonly QuicRttEstimator pathRttEstimator;

    /// <summary>
    /// Initializes a new RFC 9002 recovery controller with one shared path RTT estimator and
    /// separate packet-number-space ledgers.
    /// </summary>
    /// <param name="initialRttMicros">Initial RTT seed used by the path RTT estimator.</param>
    internal QuicRecoveryController(ulong initialRttMicros = QuicRttEstimator.DefaultInitialRttMicros)
    {
        pathRttEstimator = new QuicRttEstimator(initialRttMicros);
        states = new Dictionary<QuicPacketNumberSpace, QuicRecoveryPacketNumberSpaceState>(3);
        states[QuicPacketNumberSpace.Initial] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.Initial);
        states[QuicPacketNumberSpace.Handshake] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.Handshake);
        states[QuicPacketNumberSpace.ApplicationData] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.ApplicationData);
    }

    /// <summary>
    /// Gets the PTO backoff counter used by all packet number spaces.
    /// </summary>
    internal int ProbeTimeoutBackoffCount { get; private set; }

    /// <summary>
    /// Gets the loss estimator for a packet number space.
    /// </summary>
    internal QuicRttEstimator GetRttEstimator(QuicPacketNumberSpace packetNumberSpace) => StateFor(packetNumberSpace).RttEstimator;

    /// <summary>
    /// Gets whether a packet number space currently has ack-eliciting packets in flight.
    /// </summary>
    internal bool HasAckElicitingPacketsInFlight(QuicPacketNumberSpace packetNumberSpace) =>
        StateFor(packetNumberSpace).HasAckElicitingPacketsInFlight;

    /// <summary>
    /// Gets whether any packet number space has ack-eliciting packets in flight.
    /// </summary>
    internal bool HasAnyAckElicitingPacketsInFlight
    {
        get
        {
            foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
            {
                if (state.HasAckElicitingPacketsInFlight)
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Records a sent packet for loss and PTO decisions.
    /// </summary>
    internal void RecordPacketSent(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentAtMicros,
        bool isAckElicitingPacket = true,
        bool isProbePacket = false,
        QuicTlsEncryptionLevel? packetProtectionLevel = null,
        uint? oneRttKeyPhase = null)
    {
        StateFor(packetNumberSpace).RecordPacketSent(
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket,
            packetProtectionLevel,
            oneRttKeyPhase);

        if (isAckElicitingPacket && !isProbePacket)
        {
            ProbeTimeoutBackoffCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ProbeTimeoutBackoffCount,
                ackElicitingPacketSent: true);
        }
    }

    /// <summary>
    /// Records an ACK event and refreshes RTT state when applicable.
    /// </summary>
    internal bool RecordAcknowledgment(
        QuicPacketNumberSpace packetNumberSpace,
        ulong largestAcknowledgedPacketNumber,
        ulong ackReceivedAtMicros,
        ReadOnlySpan<ulong> newlyAcknowledgedAckElicitingPacketNumbers,
        ulong ackDelayMicros = 0,
        bool handshakeConfirmed = false,
        ulong peerMaxAckDelayMicros = 0,
        ulong localProcessingDelayMicros = 0,
        bool isInitialPacket = false,
        bool ignoreAckDelayForInitialPacket = false)
    {
        QuicRecoveryPacketNumberSpaceState state = StateFor(packetNumberSpace);
        bool acknowledgedNewPacket = state.RecordAcknowledgment(
            largestAcknowledgedPacketNumber,
            ackReceivedAtMicros,
            newlyAcknowledgedAckElicitingPacketNumbers,
            ackDelayMicros,
            handshakeConfirmed,
            peerMaxAckDelayMicros,
            localProcessingDelayMicros,
            isInitialPacket,
            ignoreAckDelayForInitialPacket,
            out bool hasNewlyAcknowledgedAckElicitingPacket);

        if (hasNewlyAcknowledgedAckElicitingPacket)
        {
            ProbeTimeoutBackoffCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ProbeTimeoutBackoffCount,
                ackElicitingPacketSent: false,
                acknowledgmentReceived: true,
                acknowledgmentPacketNumberSpace: packetNumberSpace,
                handshakeConfirmed: handshakeConfirmed);
        }

        return acknowledgedNewPacket;
    }

    /// <summary>
    /// Detects lost packets at <paramref name="nowMicros" /> using packet threshold and time threshold
    /// logic for each packet number space.
    /// </summary>
    internal IReadOnlyList<QuicLostPacket> DetectLostPackets(
        ulong nowMicros,
        out ulong? earliestLossDetectionTimeMicros,
        out QuicPacketNumberSpace earliestLossPacketNumberSpace)
    {
        List<QuicLostPacket> lostPackets = new();
        earliestLossDetectionTimeMicros = null;
        earliestLossPacketNumberSpace = default;

        foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
        {
            IReadOnlyList<ulong> spaceLostPacketNumbers = state.DetectLostPackets(nowMicros, out ulong? spaceLossTimeMicros);
            foreach (ulong lostPacketNumber in spaceLostPacketNumbers)
            {
                lostPackets.Add(new QuicLostPacket(state.PacketNumberSpace, lostPacketNumber));
            }

            if (spaceLossTimeMicros is null)
            {
                continue;
            }

            if (earliestLossDetectionTimeMicros is null || spaceLossTimeMicros < earliestLossDetectionTimeMicros)
            {
                earliestLossDetectionTimeMicros = spaceLossTimeMicros;
                earliestLossPacketNumberSpace = state.PacketNumberSpace;
            }
        }

        return lostPackets;
    }

    /// <summary>
    /// Resets the recovery state for every packet number space.
    /// </summary>
    internal void Reset()
    {
        pathRttEstimator.Reset();
        states[QuicPacketNumberSpace.Initial] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.Initial);
        states[QuicPacketNumberSpace.Handshake] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.Handshake);
        states[QuicPacketNumberSpace.ApplicationData] = CreatePacketNumberSpaceState(QuicPacketNumberSpace.ApplicationData);
        ProbeTimeoutBackoffCount = 0;
    }

    /// <summary>
    /// Discards the tracked packet-number-space state and restarts it from the initial RTT seed.
    /// </summary>
    internal bool TryDiscardPacketNumberSpace(
        QuicPacketNumberSpace packetNumberSpace,
        bool resetProbeTimeoutBackoff = false)
    {
        if (!states.ContainsKey(packetNumberSpace))
        {
            return false;
        }

        states[packetNumberSpace] = CreatePacketNumberSpaceState(packetNumberSpace);
        if (resetProbeTimeoutBackoff)
        {
            ProbeTimeoutBackoffCount = 0;
        }

        return true;
    }

    /// <summary>
    /// Discards recovery state for packets that used the specified packet protection level.
    /// </summary>
    internal bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        bool updated = false;
        foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
        {
            updated |= state.TryDiscardPacketProtectionLevel(packetProtectionLevel);
        }

        return updated;
    }

    /// <summary>
    /// Discards in-flight 1-RTT packets that were protected with a specific Key Phase.
    /// </summary>
    internal bool TryDiscardOneRttKeyPhase(uint keyPhase)
    {
        bool updated = false;
        foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
        {
            updated |= state.TryDiscardOneRttKeyPhase(keyPhase);
        }

        return updated;
    }

    /// <summary>
    /// Computes the next PTO timer and packet number space across all packet number spaces.
    /// </summary>
    internal bool TrySelectPtoTimeAndSpace(
        ulong nowMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed,
        bool handshakeKeysAvailable,
        out ulong selectedProbeTimeoutMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        selectedProbeTimeoutMicros = default;
        selectedPacketNumberSpace = default;
        bool hasSelection = false;

        foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
        {
            if (!state.TryComputeProbeTimeout(
                nowMicros,
                maxAckDelayMicros,
                handshakeConfirmed,
                ProbeTimeoutBackoffCount,
                handshakeKeysAvailable,
                out ulong probeTimeoutMicros))
            {
                continue;
            }

            if (!hasSelection || probeTimeoutMicros < selectedProbeTimeoutMicros)
            {
                selectedProbeTimeoutMicros = probeTimeoutMicros;
                selectedPacketNumberSpace = state.PacketNumberSpace;
                hasSelection = true;
            }
        }

        return hasSelection;
    }

    /// <summary>
    /// Computes the next recovery timer considering loss and PTO timers for all packet number spaces.
    /// </summary>
    internal bool TrySelectLossDetectionTimer(
        ulong nowMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed,
        bool serverAtAntiAmplificationLimit,
        bool peerAddressValidationComplete,
        bool handshakeKeysAvailable,
        out ulong selectedRecoveryTimerMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        ulong? lossDetectionTimeMicros = null;
        QuicPacketNumberSpace lossPacketNumberSpace = default;
        foreach (QuicRecoveryPacketNumberSpaceState state in states.Values)
        {
            state.PeekLossDetectionTime(nowMicros, out ulong? spaceLossTimeMicros);
            if (spaceLossTimeMicros is null)
            {
                continue;
            }

            if (lossDetectionTimeMicros is null || spaceLossTimeMicros < lossDetectionTimeMicros)
            {
                lossDetectionTimeMicros = spaceLossTimeMicros;
                lossPacketNumberSpace = state.PacketNumberSpace;
            }
        }

        bool hasPtoTimeout = TrySelectPtoTimeAndSpace(
            nowMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
            handshakeKeysAvailable,
            out ulong selectedPtoTimeMicros,
            out QuicPacketNumberSpace ptoPacketNumberSpace);

        if (!QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            lossDetectionTimeMicros,
            hasPtoTimeout ? selectedPtoTimeMicros : null,
            serverAtAntiAmplificationLimit,
            !HasAnyAckElicitingPacketsInFlight,
            peerAddressValidationComplete,
            out selectedRecoveryTimerMicros))
        {
            selectedPacketNumberSpace = default;
            return false;
        }

        if (lossDetectionTimeMicros is not null)
        {
            selectedPacketNumberSpace = lossPacketNumberSpace;
            return true;
        }

        selectedPacketNumberSpace = ptoPacketNumberSpace;
        return true;
    }

    /// <summary>
    /// Increases the PTO backoff counter after a PTO event.
    /// </summary>
    internal void RecordProbeTimeoutExpired()
    {
        if (ProbeTimeoutBackoffCount < int.MaxValue)
        {
            ProbeTimeoutBackoffCount++;
        }
    }

    private QuicRecoveryPacketNumberSpaceState StateFor(QuicPacketNumberSpace packetNumberSpace) =>
        states[packetNumberSpace];

    private QuicRecoveryPacketNumberSpaceState CreatePacketNumberSpaceState(QuicPacketNumberSpace packetNumberSpace) =>
        new(packetNumberSpace, pathRttEstimator);
}

/// <summary>
/// Tracks per-space state used by <see cref="QuicRecoveryController" />.
/// </summary>
internal sealed class QuicRecoveryPacketNumberSpaceState
{
    private readonly SortedList<ulong, QuicRecoverySentPacketState> ackElicitingPacketsInFlight;

    /// <summary>
    /// Initializes a new per-space recovery state.
    /// </summary>
    internal QuicRecoveryPacketNumberSpaceState(
        QuicPacketNumberSpace packetNumberSpace,
        QuicRttEstimator rttEstimator)
    {
        PacketNumberSpace = packetNumberSpace;
        RttEstimator = rttEstimator ?? throw new ArgumentNullException(nameof(rttEstimator));
        ackElicitingPacketsInFlight = new SortedList<ulong, QuicRecoverySentPacketState>();
        LargestAcknowledgedPacketNumber = 0;
    }

    /// <summary>
    /// Gets the packet number space for this state.
    /// </summary>
    internal QuicPacketNumberSpace PacketNumberSpace { get; }

    /// <summary>
    /// Gets the RTT estimator for this packet number space.
    /// </summary>
    internal QuicRttEstimator RttEstimator { get; }

    /// <summary>
    /// Gets the largest packet number known acknowledged in this space.
    /// </summary>
    internal ulong LargestAcknowledgedPacketNumber { get; private set; }

    /// <summary>
    /// Gets whether this space has ack-eliciting packets still in flight.
    /// </summary>
    internal bool HasAckElicitingPacketsInFlight => ackElicitingPacketsInFlight.Count > 0;

    /// <summary>
    /// Records a sent packet for loss accounting.
    /// </summary>
    internal void RecordPacketSent(
        ulong packetNumber,
        ulong sentAtMicros,
        bool isAckElicitingPacket,
        QuicTlsEncryptionLevel? packetProtectionLevel,
        uint? oneRttKeyPhase)
    {
        if (!isAckElicitingPacket)
        {
            return;
        }

        ackElicitingPacketsInFlight[packetNumber] = new QuicRecoverySentPacketState(
            sentAtMicros,
            packetProtectionLevel,
            oneRttKeyPhase);
    }

    /// <summary>
    /// Records newly acknowledged packets, updates RTT state, and removes acknowledged packets from flight.
    /// </summary>
    internal bool RecordAcknowledgment(
        ulong largestAcknowledgedPacketNumber,
        ulong ackReceivedAtMicros,
        ReadOnlySpan<ulong> newlyAcknowledgedAckElicitingPacketNumbers,
        ulong ackDelayMicros,
        bool handshakeConfirmed,
        ulong peerMaxAckDelayMicros,
        ulong localProcessingDelayMicros,
        bool isInitialPacket,
        bool ignoreAckDelayForInitialPacket,
        out bool hasNewlyAcknowledgedAckElicitingPacket)
    {
        bool largestAcknowledgedPacketNewlyAcknowledged = largestAcknowledgedPacketNumber > LargestAcknowledgedPacketNumber;
        hasNewlyAcknowledgedAckElicitingPacket = false;
        ulong? largestAcknowledgedPacketSentAtMicros = null;

        for (int index = 0; index < newlyAcknowledgedAckElicitingPacketNumbers.Length; index++)
        {
            ulong packetNumber = newlyAcknowledgedAckElicitingPacketNumbers[index];
            if (ackElicitingPacketsInFlight.Remove(packetNumber, out QuicRecoverySentPacketState sentPacket))
            {
                hasNewlyAcknowledgedAckElicitingPacket = true;
                if (packetNumber == largestAcknowledgedPacketNumber && largestAcknowledgedPacketSentAtMicros is null)
                {
                    largestAcknowledgedPacketSentAtMicros = sentPacket.SentAtMicros;
                }
            }
        }

        bool rttSampleUpdated = false;
        if (largestAcknowledgedPacketNewlyAcknowledged && hasNewlyAcknowledgedAckElicitingPacket)
        {
            bool hasLargestTimestamp = largestAcknowledgedPacketSentAtMicros is not null;
            rttSampleUpdated = RttEstimator.TryUpdateFromAck(
                hasLargestTimestamp ? largestAcknowledgedPacketSentAtMicros!.Value : 0,
                ackReceivedAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged,
                hasNewlyAcknowledgedAckElicitingPacket,
                ackDelayMicros,
                handshakeConfirmed,
                peerMaxAckDelayMicros,
                localProcessingDelayMicros,
                isInitialPacket: isInitialPacket,
                ignoreAckDelayForInitialPacket: ignoreAckDelayForInitialPacket);
        }

        if (largestAcknowledgedPacketNewlyAcknowledged)
        {
            LargestAcknowledgedPacketNumber = largestAcknowledgedPacketNumber;
        }

        return rttSampleUpdated;
    }

    /// <summary>
    /// Detects lost packets from this packet number space and returns packet numbers that should be removed from flight.
    /// </summary>
    internal IReadOnlyList<ulong> DetectLostPackets(
        ulong nowMicros,
        out ulong? nextLossDetectionTimeMicros)
    {
        List<ulong> lostPacketNumbers = new();
        ulong? nextLossDelayMicros = null;

        foreach (KeyValuePair<ulong, QuicRecoverySentPacketState> packet in ackElicitingPacketsInFlight)
        {
            if (!QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: false,
                packetInFlight: true,
                packetNumber: packet.Key,
                largestAcknowledgedPacketNumber: LargestAcknowledgedPacketNumber))
            {
                continue;
            }

            bool byPacketThreshold = QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packet.Key,
                LargestAcknowledgedPacketNumber);

            QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                packet.Value.SentAtMicros,
                nowMicros,
                RttEstimator.LatestRttMicros,
                RttEstimator.SmoothedRttMicros,
                out ulong remainingLossDelayMicros);

            if (byPacketThreshold || remainingLossDelayMicros == 0)
            {
                lostPacketNumbers.Add(packet.Key);
                continue;
            }

            if (nextLossDelayMicros is null || remainingLossDelayMicros < nextLossDelayMicros.Value)
            {
                nextLossDelayMicros = remainingLossDelayMicros;
            }
        }

        foreach (ulong lostPacketNumber in lostPacketNumbers)
        {
            ackElicitingPacketsInFlight.Remove(lostPacketNumber);
        }

        if (nextLossDelayMicros is null)
        {
            nextLossDetectionTimeMicros = null;
        }
        else
        {
            nextLossDetectionTimeMicros = SaturatingAdd(nowMicros, nextLossDelayMicros.Value);
        }

        return lostPacketNumbers;
    }

    /// <summary>
    /// Peeks the next loss-detection deadline without discarding packets from flight.
    /// </summary>
    internal void PeekLossDetectionTime(
        ulong nowMicros,
        out ulong? nextLossDetectionTimeMicros)
    {
        bool hasImmediateLoss = false;
        ulong? nextLossDelayMicros = null;

        foreach (KeyValuePair<ulong, QuicRecoverySentPacketState> packet in ackElicitingPacketsInFlight)
        {
            if (!QuicRecoveryTiming.CanDeclarePacketLost(
                packetAcknowledged: false,
                packetInFlight: true,
                packetNumber: packet.Key,
                largestAcknowledgedPacketNumber: LargestAcknowledgedPacketNumber))
            {
                continue;
            }

            bool byPacketThreshold = QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packet.Key,
                LargestAcknowledgedPacketNumber);

            QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                packet.Value.SentAtMicros,
                nowMicros,
                RttEstimator.LatestRttMicros,
                RttEstimator.SmoothedRttMicros,
                out ulong remainingLossDelayMicros);

            if (byPacketThreshold || remainingLossDelayMicros == 0)
            {
                hasImmediateLoss = true;
                break;
            }

            if (nextLossDelayMicros is null || remainingLossDelayMicros < nextLossDelayMicros.Value)
            {
                nextLossDelayMicros = remainingLossDelayMicros;
            }
        }

        if (hasImmediateLoss)
        {
            nextLossDetectionTimeMicros = nowMicros;
            return;
        }

        if (nextLossDelayMicros is null)
        {
            nextLossDetectionTimeMicros = null;
            return;
        }

        nextLossDetectionTimeMicros = SaturatingAdd(nowMicros, nextLossDelayMicros.Value);
    }

    /// <summary>
    /// Removes in-flight packets that used a specific packet protection level.
    /// </summary>
    internal bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        if (ackElicitingPacketsInFlight.Count == 0)
        {
            return false;
        }

        List<ulong>? removedPacketNumbers = null;
        foreach (KeyValuePair<ulong, QuicRecoverySentPacketState> packet in ackElicitingPacketsInFlight)
        {
            if (packet.Value.PacketProtectionLevel != packetProtectionLevel)
            {
                continue;
            }

            (removedPacketNumbers ??= []).Add(packet.Key);
        }

        if (removedPacketNumbers is null)
        {
            return false;
        }

        foreach (ulong packetNumber in removedPacketNumbers)
        {
            ackElicitingPacketsInFlight.Remove(packetNumber);
        }

        return true;
    }

    /// <summary>
    /// Removes in-flight 1-RTT packets that used a specific Key Phase.
    /// </summary>
    internal bool TryDiscardOneRttKeyPhase(uint keyPhase)
    {
        if (ackElicitingPacketsInFlight.Count == 0)
        {
            return false;
        }

        List<ulong>? removedPacketNumbers = null;
        foreach (KeyValuePair<ulong, QuicRecoverySentPacketState> packet in ackElicitingPacketsInFlight)
        {
            if (packet.Value.PacketProtectionLevel != QuicTlsEncryptionLevel.OneRtt
                || packet.Value.OneRttKeyPhase != keyPhase)
            {
                continue;
            }

            (removedPacketNumbers ??= []).Add(packet.Key);
        }

        if (removedPacketNumbers is null)
        {
            return false;
        }

        foreach (ulong packetNumber in removedPacketNumbers)
        {
            ackElicitingPacketsInFlight.Remove(packetNumber);
        }

        return true;
    }

    /// <summary>
    /// Computes the PTO deadline for this space.
    /// </summary>
    internal bool TryComputeProbeTimeout(
        ulong nowMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed,
        int probeTimeoutBackoffCount,
        bool handshakeKeysAvailable,
        out ulong probeTimeoutMicros)
    {
        probeTimeoutMicros = default;

        if (!HasAckElicitingPacketsInFlight)
        {
            return false;
        }

        if (PacketNumberSpace == QuicPacketNumberSpace.Handshake && !handshakeKeysAvailable)
        {
            return false;
        }

        if (!QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            PacketNumberSpace,
            RttEstimator.SmoothedRttMicros,
            RttEstimator.RttVarMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
            out ulong probeTimeoutMicrosValue))
        {
            return false;
        }

        ulong backedOffProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicrosValue,
            probeTimeoutBackoffCount);
        probeTimeoutMicros = SaturatingAdd(nowMicros, backedOffProbeTimeoutMicros);
        return true;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        if (ulong.MaxValue - left < right)
        {
            return ulong.MaxValue;
        }

        return left + right;
    }
}
