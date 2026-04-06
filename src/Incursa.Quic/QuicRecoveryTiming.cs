namespace Incursa.Quic;

/// <summary>
/// Provides helper methods for RFC 9002 loss-detection and PTO timing calculations that do not require
/// a full sender state machine.
/// </summary>
public static class QuicRecoveryTiming
{
    /// <summary>
    /// The recommended packet reordering threshold from RFC 9002.
    /// </summary>
    public const int RecommendedPacketThreshold = 3;

    /// <summary>
    /// The recommended time-threshold numerator from RFC 9002's loss-delay formula.
    /// </summary>
    public const ulong RecommendedTimeThresholdNumerator = 9;

    /// <summary>
    /// The recommended time-threshold denominator from RFC 9002's loss-delay formula.
    /// </summary>
    public const ulong RecommendedTimeThresholdDenominator = 8;

    /// <summary>
    /// The recommended timer granularity, in microseconds.
    /// </summary>
    public const ulong RecommendedTimerGranularityMicros = 1_000;

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
    public static bool CanDeclarePacketLost(
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
    public static bool ShouldDeclarePacketLostByPacketThreshold(
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
    public static ulong ComputeLossDelayMicros(
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
    public static bool TryComputeRemainingLossDelayMicros(
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
    public static bool TryComputeProbeTimeoutMicros(
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
    public static ulong ComputeProbeTimeoutWithBackoffMicros(ulong probeTimeoutMicros, int ptoCount)
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
    public static int ResetProbeTimeoutBackoffCount(
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
    public static bool TrySelectInitialOrHandshakeProbeTimeoutMicros(
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
    public static bool TrySelectLossTimeAndSpaceMicros(
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
    public static bool TrySelectPtoTimeAndSpaceMicros(
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
    public static bool TrySelectRecoveryTimerMicros(
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
    public static bool TrySelectLossDetectionTimerMicros(
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
    public static bool TryMeasurePathChallengeRoundTripMicros(
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
    public static bool TryMeasureRetryRoundTripMicros(
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
