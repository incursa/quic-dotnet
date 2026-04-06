namespace Incursa.Quic;

/// <summary>
/// Tracks RTT estimates for a single QUIC path.
/// </summary>
public sealed class QuicRttEstimator
{
    /// <summary>
    /// The RFC 9002 default initial RTT, in microseconds.
    /// </summary>
    public const ulong DefaultInitialRttMicros = 333_000;

    /// <summary>
    /// RFC 9002 initializes RTTVAR to half of the initial RTT.
    /// </summary>
    private const ulong InitialRttVarianceDivisor = 2;

    /// <summary>
    /// RFC 9002 smooths RTT with a 7/8 weight on the previous sample.
    /// </summary>
    private const ulong SmoothedRttWeightNumerator = 7;

    /// <summary>
    /// RFC 9002 smooths RTT with a denominator of 8.
    /// </summary>
    private const ulong SmoothedRttWeightDenominator = 8;

    /// <summary>
    /// RFC 9002 updates RTTVAR with a 3/4 weight on the previous variance.
    /// </summary>
    private const ulong RttVarianceWeightNumerator = 3;

    /// <summary>
    /// RFC 9002 updates RTTVAR with a denominator of 4.
    /// </summary>
    private const ulong RttVarianceWeightDenominator = 4;

    private readonly ulong initialRttMicros;

    /// <summary>
    /// Initializes a new RTT estimator using the RFC 9002 initial RTT.
    /// </summary>
    /// <param name="initialRttMicros">The initial RTT to use before any path samples are available.</param>
    public QuicRttEstimator(ulong initialRttMicros = DefaultInitialRttMicros)
    {
        if (initialRttMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(initialRttMicros));
        }

        this.initialRttMicros = initialRttMicros;
        Reset();
    }

    /// <summary>
    /// Gets the initial RTT configured for this estimator.
    /// </summary>
    public ulong InitialRttMicros => initialRttMicros;

    /// <summary>
    /// Gets the latest raw RTT sample.
    /// </summary>
    public ulong LatestRttMicros { get; private set; }

    /// <summary>
    /// Gets the current minimum RTT estimate.
    /// </summary>
    public ulong MinRttMicros { get; private set; }

    /// <summary>
    /// Gets the current smoothed RTT estimate.
    /// </summary>
    public ulong SmoothedRttMicros { get; private set; }

    /// <summary>
    /// Gets the current RTT variance estimate.
    /// </summary>
    public ulong RttVarMicros { get; private set; }

    /// <summary>
    /// Gets whether the estimator has processed at least one RTT sample.
    /// </summary>
    public bool HasRttSample { get; private set; }

    /// <summary>
    /// Reinitializes the estimator to the configured initial RTT.
    /// </summary>
    public void Reset()
    {
        LatestRttMicros = 0;
        MinRttMicros = 0;
        SmoothedRttMicros = initialRttMicros;
        RttVarMicros = initialRttMicros / InitialRttVarianceDivisor;
        HasRttSample = false;
    }

    /// <summary>
    /// Reestablishes <see cref="MinRttMicros"/> from the newest RTT sample.
    /// </summary>
    public void RefreshMinRttFromLatestSample(ulong latestRttMicros)
    {
        MinRttMicros = latestRttMicros;
    }

    /// <summary>
    /// Records an RTT sample derived from an ACK for the largest acknowledged packet.
    /// </summary>
    /// <remarks>
    /// The estimator only accepts ACKs that newly acknowledge the largest acknowledged packet and at least
    /// one newly acknowledged ack-eliciting packet.
    /// </remarks>
    /// <returns><see langword="true"/> when the sample was accepted and the estimator state was updated.</returns>
    public bool TryUpdateFromAck(
        ulong largestAcknowledgedPacketSentAtMicros,
        ulong ackReceivedAtMicros,
        bool largestAcknowledgedPacketNewlyAcknowledged,
        bool newlyAcknowledgedAckElicitingPacket,
        ulong ackDelayMicros = 0,
        bool handshakeConfirmed = false,
        ulong peerMaxAckDelayMicros = 0,
        ulong localProcessingDelayMicros = 0,
        bool isInitialPacket = false,
        bool ignoreAckDelayForInitialPacket = false)
    {
        if (!largestAcknowledgedPacketNewlyAcknowledged || !newlyAcknowledgedAckElicitingPacket)
        {
            return false;
        }

        ulong rawLatestRttMicros = GetElapsedMicros(ackReceivedAtMicros, largestAcknowledgedPacketSentAtMicros);
        LatestRttMicros = rawLatestRttMicros;

        ulong sampleRttMicros = rawLatestRttMicros;
        if (!handshakeConfirmed && HasRttSample && localProcessingDelayMicros != 0)
        {
            sampleRttMicros = SubtractWithFloor(sampleRttMicros, localProcessingDelayMicros);
        }

        if (!HasRttSample)
        {
            MinRttMicros = rawLatestRttMicros;
            SmoothedRttMicros = rawLatestRttMicros;
            RttVarMicros = rawLatestRttMicros / InitialRttVarianceDivisor;
            HasRttSample = true;
            return true;
        }

        ulong effectiveAckDelayMicros = 0;
        if (!(ignoreAckDelayForInitialPacket && isInitialPacket))
        {
            effectiveAckDelayMicros = handshakeConfirmed
                ? Math.Min(ackDelayMicros, peerMaxAckDelayMicros)
                : ackDelayMicros;
        }

        ulong adjustedRttMicros = sampleRttMicros;
        if (CanSubtractAckDelay(sampleRttMicros, MinRttMicros, effectiveAckDelayMicros))
        {
            adjustedRttMicros -= effectiveAckDelayMicros;
        }

        ulong previousSmoothedRttMicros = SmoothedRttMicros;
        ulong previousRttVarMicros = RttVarMicros;
        ulong rttDeviationMicros = previousSmoothedRttMicros >= adjustedRttMicros
            ? previousSmoothedRttMicros - adjustedRttMicros
            : adjustedRttMicros - previousSmoothedRttMicros;

        SmoothedRttMicros = (SmoothedRttWeightNumerator * previousSmoothedRttMicros + adjustedRttMicros) / SmoothedRttWeightDenominator;
        RttVarMicros = (RttVarianceWeightNumerator * previousRttVarMicros + rttDeviationMicros) / RttVarianceWeightDenominator;
        MinRttMicros = Math.Min(MinRttMicros, sampleRttMicros);
        return true;
    }

    private static bool CanSubtractAckDelay(ulong latestRttMicros, ulong minRttMicros, ulong ackDelayMicros)
    {
        if (latestRttMicros < minRttMicros)
        {
            return false;
        }

        return latestRttMicros - minRttMicros >= ackDelayMicros;
    }

    private static ulong GetElapsedMicros(ulong laterMicros, ulong earlierMicros)
    {
        return laterMicros >= earlierMicros ? laterMicros - earlierMicros : 0;
    }

    private static ulong SubtractWithFloor(ulong value, ulong amount)
    {
        return value >= amount ? value - amount : 0;
    }
}
