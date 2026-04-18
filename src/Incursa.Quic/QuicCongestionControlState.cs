using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

/// <summary>
/// Tracks the RFC 9002 congestion-control state that can be modeled without a full sender or pacer.
/// </summary>
internal sealed class QuicCongestionControlState
{
    /// <summary>
    /// The recommended persistent congestion threshold from RFC 9002.
    /// </summary>
    internal const int RecommendedPersistentCongestionThreshold = 3;

    /// <summary>
    /// RFC 9002 reduces the congestion window by one-half on loss.
    /// </summary>
    internal const ulong RecommendedLossReductionNumerator = 1;

    /// <summary>
    /// RFC 9002 reduces the congestion window by one-half on loss.
    /// </summary>
    internal const ulong RecommendedLossReductionDenominator = 2;

    /// <summary>
    /// RFC 9002's pacing gain is 5/4.
    /// </summary>
    internal const ulong RecommendedPacingGainNumerator = 5;

    /// <summary>
    /// RFC 9002's pacing gain is 5/4.
    /// </summary>
    internal const ulong RecommendedPacingGainDenominator = 4;

    /// <summary>
    /// QUIC tracks three packet number spaces: Initial, Handshake, and Application Data.
    /// </summary>
    private const int PacketNumberSpaceCount = 3;

    /// <summary>
    /// RFC 9002 recommends an initial congestion window of ten maximum-sized datagrams.
    /// </summary>
    private const ulong InitialCongestionWindowDatagramCount = 10;

    /// <summary>
    /// RFC 9002's minimum initial congestion window floor is 14,720 bytes.
    /// </summary>
    private const ulong MinimumInitialCongestionWindowBytes = 14_720UL;

    /// <summary>
    /// RFC 9002's minimum congestion window is two maximum-sized datagrams.
    /// </summary>
    private const ulong MinimumCongestionWindowMultiplier = 2;

    /// <summary>
    /// Stable array slot for the Initial packet number space.
    /// </summary>
    private const int InitialPacketNumberSpaceIndex = 0;

    /// <summary>
    /// Stable array slot for the Handshake packet number space.
    /// </summary>
    private const int HandshakePacketNumberSpaceIndex = 1;

    /// <summary>
    /// Stable array slot for the Application Data packet number space.
    /// </summary>
    private const int ApplicationDataPacketNumberSpaceIndex = 2;

    private readonly ulong[] ecnCeCounters = new ulong[PacketNumberSpaceCount];

    /// <summary>
    /// Initializes a new congestion-control state using the RFC 9002 default maximum datagram size.
    /// </summary>
    internal QuicCongestionControlState(ulong maxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        MaxDatagramSizeBytes = maxDatagramSizeBytes;
        MinimumCongestionWindowBytes = ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes);
        CongestionWindowBytes = ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes);
        SlowStartThresholdBytes = ulong.MaxValue;
    }

    /// <summary>
    /// Gets the current maximum datagram size used for congestion-window computations.
    /// </summary>
    internal ulong MaxDatagramSizeBytes { get; private set; }

    /// <summary>
    /// Gets the minimum congestion window in bytes.
    /// </summary>
    internal ulong MinimumCongestionWindowBytes { get; }

    /// <summary>
    /// Gets the current congestion window in bytes.
    /// </summary>
    internal ulong CongestionWindowBytes { get; private set; }

    /// <summary>
    /// Gets the slow-start threshold in bytes.
    /// </summary>
    internal ulong SlowStartThresholdBytes { get; private set; }

    /// <summary>
    /// Gets the current number of bytes in flight.
    /// </summary>
    internal ulong BytesInFlightBytes { get; private set; }

    /// <summary>
    /// Gets the start time of the most recent recovery period, if any.
    /// </summary>
    internal ulong? RecoveryStartTimeMicros { get; private set; }

    /// <summary>
    /// Gets whether recovery has started for any packet sent at or before <see cref="RecoveryStartTimeMicros"/>.
    /// </summary>
    internal bool HasRecoveryStartTime => RecoveryStartTimeMicros.HasValue;

    /// <summary>
    /// Gets whether the current controller is in slow start.
    /// </summary>
    internal bool IsInSlowStart => CongestionWindowBytes < SlowStartThresholdBytes;

    /// <summary>
    /// Gets whether the current controller is in congestion avoidance.
    /// </summary>
    internal bool IsInCongestionAvoidance => CongestionWindowBytes >= SlowStartThresholdBytes;

    /// <summary>
    /// Recomputes the initial congestion window for the supplied datagram size.
    /// </summary>
    internal static ulong ComputeInitialCongestionWindowBytes(ulong maxDatagramSizeBytes)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        ulong tenDatagrams = MultiplySaturating(maxDatagramSizeBytes, InitialCongestionWindowDatagramCount);
        ulong twoDatagrams = MultiplySaturating(maxDatagramSizeBytes, MinimumCongestionWindowMultiplier);
        ulong floor = Math.Max(twoDatagrams, MinimumInitialCongestionWindowBytes);
        return Math.Min(tenDatagrams, floor);
    }

    /// <summary>
    /// Computes the RFC 9002 minimum congestion window for the supplied datagram size.
    /// </summary>
    internal static ulong ComputeMinimumCongestionWindowBytes(ulong maxDatagramSizeBytes)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        return MultiplySaturating(maxDatagramSizeBytes, MinimumCongestionWindowMultiplier);
    }

    /// <summary>
    /// Computes the pacing interval from the congestion window, RTT, and packet size.
    /// </summary>
    /// <remarks>
    /// ACK-only packets are intentionally not paced.
    /// </remarks>
    internal static bool TryComputePacingIntervalMicros(
        ulong congestionWindowBytes,
        ulong smoothedRttMicros,
        ulong packetSizeBytes,
        bool ackOnlyPacket,
        out ulong pacingIntervalMicros,
        ulong pacingGainNumerator = RecommendedPacingGainNumerator,
        ulong pacingGainDenominator = RecommendedPacingGainDenominator)
    {
        pacingIntervalMicros = default;

        if (ackOnlyPacket)
        {
            return true;
        }

        if (congestionWindowBytes == 0 || smoothedRttMicros == 0 || packetSizeBytes == 0)
        {
            return false;
        }

        if (pacingGainNumerator == 0 || pacingGainDenominator == 0)
        {
            throw new ArgumentOutOfRangeException(pacingGainNumerator == 0 ? nameof(pacingGainNumerator) : nameof(pacingGainDenominator));
        }

        ulong scaledIntervalMicros = DivideSaturating(MultiplySaturating(smoothedRttMicros, packetSizeBytes), congestionWindowBytes);
        pacingIntervalMicros = MultiplyAndDivide(scaledIntervalMicros, pacingGainDenominator, pacingGainNumerator);
        return true;
    }

    /// <summary>
    /// Computes the burst budget in bytes for paced or burst-limited senders.
    /// </summary>
    internal static bool TryGetBurstLimitBytes(
        ulong initialCongestionWindowBytes,
        bool pathCanAbsorbLargerBursts,
        out ulong burstLimitBytes,
        ulong? largerBurstLimitBytes = null)
    {
        burstLimitBytes = initialCongestionWindowBytes;

        if (initialCongestionWindowBytes == 0)
        {
            return false;
        }

        if (pathCanAbsorbLargerBursts && largerBurstLimitBytes.HasValue)
        {
            burstLimitBytes = largerBurstLimitBytes.Value;
        }

        return true;
    }

    /// <summary>
    /// Resets the controller to a new maximum datagram size while recomputing the initial window.
    /// </summary>
    internal void UpdateMaxDatagramSize(ulong maxDatagramSizeBytes, bool resetToInitialWindow)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        MaxDatagramSizeBytes = maxDatagramSizeBytes;
        if (resetToInitialWindow)
        {
            CongestionWindowBytes = ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes);
            SlowStartThresholdBytes = ulong.MaxValue;
            RecoveryStartTimeMicros = null;
        }
    }

    /// <summary>
    /// Restores the controller to its initial-path state while keeping the negotiated datagram size.
    /// </summary>
    internal void Reset()
    {
        UpdateMaxDatagramSize(MaxDatagramSizeBytes, resetToInitialWindow: true);
        BytesInFlightBytes = 0;
        Array.Clear(ecnCeCounters);
    }

    /// <summary>
    /// Determines whether a packet may be sent without exceeding the congestion window.
    /// </summary>
    internal bool CanSend(ulong sentBytes, bool isAckOnlyPacket = false, bool isProbePacket = false)
    {
        if (isAckOnlyPacket || isProbePacket)
        {
            return true;
        }

        return BytesInFlightBytes <= ulong.MaxValue - sentBytes
            && BytesInFlightBytes + sentBytes <= CongestionWindowBytes;
    }

    /// <summary>
    /// Records a sent packet.
    /// </summary>
    internal void RegisterPacketSent(ulong sentBytes, bool isAckOnlyPacket = false, bool isProbePacket = false)
    {
        if (isAckOnlyPacket)
        {
            return;
        }

        BytesInFlightBytes = SaturatingAdd(BytesInFlightBytes, sentBytes);
    }

    /// <summary>
    /// Records an acknowledged packet and applies the RFC 9002 cwnd growth rules.
    /// </summary>
    internal bool TryRegisterAcknowledgedPacket(
        ulong sentBytes,
        ulong sentAtMicros,
        bool packetInFlight = true,
        bool applicationLimited = false,
        bool flowControlLimited = false,
        bool pacingLimited = false)
    {
        if (!packetInFlight)
        {
            return false;
        }

        BytesInFlightBytes = SubtractSaturating(BytesInFlightBytes, sentBytes);
        bool packetWasSentDuringRecovery = RecoveryStartTimeMicros.HasValue
            && sentAtMicros > RecoveryStartTimeMicros.Value;

        if (RecoveryStartTimeMicros.HasValue && !packetWasSentDuringRecovery)
        {
            return true;
        }

        if (packetWasSentDuringRecovery)
        {
            RecoveryStartTimeMicros = null;
        }

        if (applicationLimited || flowControlLimited)
        {
            return true;
        }

        if (!pacingLimited && BytesInFlightBytes < CongestionWindowBytes)
        {
            return true;
        }

        if (CongestionWindowBytes < SlowStartThresholdBytes)
        {
            CongestionWindowBytes = SaturatingAdd(CongestionWindowBytes, sentBytes);
            return true;
        }

        ulong growthBytes = DivideSaturating(MultiplySaturating(MaxDatagramSizeBytes, sentBytes), CongestionWindowBytes);
        CongestionWindowBytes = SaturatingAdd(CongestionWindowBytes, growthBytes);
        return true;
    }

    /// <summary>
    /// Records a loss signal and enters recovery when the signal is eligible to do so.
    /// </summary>
    internal bool TryRegisterLoss(
        ulong sentBytes,
        ulong sentAtMicros,
        bool packetInFlight,
        bool packetCanBeDecrypted = true,
        bool keysAvailable = true,
        bool sentAfterEarliestAcknowledgedPacket = true,
        bool isProbePacket = false,
        bool allowAckOnlyLossSignal = false)
    {
        if (!packetInFlight && !allowAckOnlyLossSignal)
        {
            return false;
        }

        if (!packetCanBeDecrypted && (!keysAvailable || !sentAfterEarliestAcknowledgedPacket))
        {
            return false;
        }

        if (packetInFlight)
        {
            BytesInFlightBytes = SubtractSaturating(BytesInFlightBytes, sentBytes);
        }

        if (isProbePacket)
        {
            return true;
        }

        EnterRecovery(sentAtMicros);
        return true;
    }

    /// <summary>
    /// Removes a packet from bytes-in-flight accounting without treating it as loss or acknowledgment.
    /// </summary>
    internal bool TryDiscardPacket(ulong sentBytes, bool packetInFlight)
    {
        if (!packetInFlight)
        {
            return false;
        }

        BytesInFlightBytes = SubtractSaturating(BytesInFlightBytes, sentBytes);
        return true;
    }

    /// <summary>
    /// Processes an ECN-CE counter report for the supplied packet number space.
    /// </summary>
    internal bool TryProcessEcn(
        QuicPacketNumberSpace packetNumberSpace,
        ulong reportedEcnCeCount,
        ulong largestAcknowledgedPacketSentAtMicros,
        bool pathValidated)
    {
        int index = GetPacketNumberSpaceIndex(packetNumberSpace);
        if (reportedEcnCeCount <= ecnCeCounters[index])
        {
            return false;
        }

        ecnCeCounters[index] = reportedEcnCeCount;
        if (!pathValidated)
        {
            return false;
        }

        if (IsInRecovery(largestAcknowledgedPacketSentAtMicros))
        {
            return false;
        }

        EnterRecovery(largestAcknowledgedPacketSentAtMicros);
        return true;
    }

    /// <summary>
    /// Computes the RFC 9002 persistent congestion duration.
    /// </summary>
    internal static bool TryComputePersistentCongestionDurationMicros(
        ulong smoothedRttMicros,
        ulong rttVarMicros,
        ulong maxAckDelayMicros,
        out ulong persistentCongestionDurationMicros,
        int persistentCongestionThreshold = RecommendedPersistentCongestionThreshold,
        ulong timerGranularityMicros = QuicRecoveryTiming.RecommendedTimerGranularityMicros)
    {
        persistentCongestionDurationMicros = default;

        if (persistentCongestionThreshold < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(persistentCongestionThreshold));
        }

        if (timerGranularityMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timerGranularityMicros));
        }

        ulong referenceRttMicros = SaturatingAdd(
            smoothedRttMicros,
            Math.Max(MultiplySaturating(rttVarMicros, 4), timerGranularityMicros));

        referenceRttMicros = SaturatingAdd(referenceRttMicros, maxAckDelayMicros);
        persistentCongestionDurationMicros = MultiplySaturating(referenceRttMicros, (ulong)persistentCongestionThreshold);
        return true;
    }

    /// <summary>
    /// Evaluates persistent congestion and optionally applies the cwnd collapse when the test passes.
    /// </summary>
    internal bool TryDetectPersistentCongestion(
        ReadOnlySpan<QuicPersistentCongestionPacket> packets,
        ulong firstRttSampleMicros,
        ulong smoothedRttMicros,
        ulong rttVarMicros,
        ulong maxAckDelayMicros,
        out bool persistentCongestionDetected,
        bool applyReset = true)
    {
        persistentCongestionDetected = false;

        if (firstRttSampleMicros == 0 || packets.IsEmpty)
        {
            return false;
        }

        ulong latestLossSentAtMicros = 0;
        foreach (QuicPersistentCongestionPacket packet in packets)
        {
            if (packet.Lost && packet.InFlight)
            {
                BytesInFlightBytes = SubtractSaturating(BytesInFlightBytes, packet.SentBytes);
                latestLossSentAtMicros = Math.Max(latestLossSentAtMicros, packet.SentAtMicros);
            }
        }

        if (!TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros,
            rttVarMicros,
            maxAckDelayMicros,
            out ulong persistentCongestionDurationMicros))
        {
            return false;
        }

        ulong earliestLostSentAtMicros = ulong.MaxValue;
        ulong latestLostSentAtMicros = 0;
        bool foundAckElicitingLoss = false;
        bool foundAnyPacketAfterRttSample = false;

        foreach (QuicPersistentCongestionPacket packet in packets)
        {
            if (packet.SentAtMicros <= firstRttSampleMicros)
            {
                continue;
            }

            foundAnyPacketAfterRttSample = true;

            if (!packet.Lost)
            {
                continue;
            }

            if (!packet.AckEliciting)
            {
                continue;
            }

            if (!packet.Acknowledged)
            {
                foundAckElicitingLoss = true;
                earliestLostSentAtMicros = Math.Min(earliestLostSentAtMicros, packet.SentAtMicros);
                latestLostSentAtMicros = Math.Max(latestLostSentAtMicros, packet.SentAtMicros);
            }
        }

        if (!foundAnyPacketAfterRttSample || !foundAckElicitingLoss)
        {
            return true;
        }

        if (latestLostSentAtMicros - earliestLostSentAtMicros < persistentCongestionDurationMicros)
        {
            return true;
        }

        if (latestLossSentAtMicros != 0 && !IsInRecovery(latestLossSentAtMicros))
        {
            EnterRecovery(latestLossSentAtMicros);
        }

        foreach (QuicPersistentCongestionPacket packet in packets)
        {
            if (packet.SentAtMicros <= firstRttSampleMicros)
            {
                continue;
            }

            if (packet.SentAtMicros > earliestLostSentAtMicros
                && packet.SentAtMicros < latestLostSentAtMicros
                && packet.Acknowledged)
            {
                return true;
            }
        }

        persistentCongestionDetected = true;
        if (applyReset)
        {
            CongestionWindowBytes = MinimumCongestionWindowBytes;
            SlowStartThresholdBytes = ulong.MaxValue;
            RecoveryStartTimeMicros = null;
        }

        return true;
    }

    private bool IsInRecovery(ulong sentAtMicros)
    {
        return RecoveryStartTimeMicros.HasValue && sentAtMicros <= RecoveryStartTimeMicros.Value;
    }

    private void EnterRecovery(ulong sentAtMicros)
    {
        if (IsInRecovery(sentAtMicros))
        {
            return;
        }

        RecoveryStartTimeMicros = sentAtMicros;
        SlowStartThresholdBytes = ComputeReducedCongestionWindowBytes(
            CongestionWindowBytes,
            RecommendedLossReductionNumerator,
            RecommendedLossReductionDenominator,
            MinimumCongestionWindowBytes);
        CongestionWindowBytes = Math.Max(SlowStartThresholdBytes, MinimumCongestionWindowBytes);
    }

    /// <summary>
    /// Computes a reduced congestion window with an optional gentler reduction factor.
    /// </summary>
    internal static ulong ComputeReducedCongestionWindowBytes(
        ulong congestionWindowBytes,
        ulong reductionNumerator = RecommendedLossReductionNumerator,
        ulong reductionDenominator = RecommendedLossReductionDenominator,
        ulong minimumCongestionWindowBytes = 0)
    {
        if (congestionWindowBytes == 0)
        {
            return minimumCongestionWindowBytes;
        }

        if (reductionNumerator == 0 || reductionDenominator == 0)
        {
            throw new ArgumentOutOfRangeException(reductionNumerator == 0 ? nameof(reductionNumerator) : nameof(reductionDenominator));
        }

        ulong reducedWindowBytes = MultiplyAndDivide(congestionWindowBytes, reductionNumerator, reductionDenominator);
        return Math.Max(reducedWindowBytes, minimumCongestionWindowBytes);
    }

    private static int GetPacketNumberSpaceIndex(QuicPacketNumberSpace packetNumberSpace)
    {
        return packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => InitialPacketNumberSpaceIndex,
            QuicPacketNumberSpace.Handshake => HandshakePacketNumberSpaceIndex,
            QuicPacketNumberSpace.ApplicationData => ApplicationDataPacketNumberSpaceIndex,
            _ => throw new ArgumentOutOfRangeException(nameof(packetNumberSpace)),
        };
    }

    private static ulong MultiplyAndDivide(ulong value, ulong numerator, ulong denominator)
    {
        ulong wholeQuotient = value / denominator;
        ulong remainder = value % denominator;
        ulong scaledWhole = MultiplySaturating(wholeQuotient, numerator);
        ulong scaledRemainder = (remainder * numerator) / denominator;
        return SaturatingAdd(scaledWhole, scaledRemainder);
    }

    private static ulong DivideSaturating(ulong dividend, ulong divisor)
    {
        if (divisor == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(divisor));
        }

        return dividend / divisor;
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

    private static ulong SubtractSaturating(ulong value, ulong amount)
    {
        return value >= amount ? value - amount : 0;
    }
}

/// <summary>
/// Describes a packet relevant to persistent congestion evaluation.
/// </summary>
internal readonly struct QuicPersistentCongestionPacket
{
    /// <summary>
    /// Initializes a new persistent congestion packet descriptor.
    /// </summary>
    internal QuicPersistentCongestionPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong sentAtMicros,
        ulong sentBytes,
        bool ackEliciting,
        bool inFlight,
        bool acknowledged,
        bool lost,
        ulong packetNumber = 0)
    {
        PacketNumberSpace = packetNumberSpace;
        PacketNumber = packetNumber;
        SentAtMicros = sentAtMicros;
        SentBytes = sentBytes;
        AckEliciting = ackEliciting;
        InFlight = inFlight;
        Acknowledged = acknowledged;
        Lost = lost;
    }

    /// <summary>
    /// Gets the packet number space.
    /// </summary>
    internal QuicPacketNumberSpace PacketNumberSpace { get; }

    /// <summary>
    /// Gets the packet number.
    /// </summary>
    internal ulong PacketNumber { get; }

    /// <summary>
    /// Gets the send time in microseconds.
    /// </summary>
    internal ulong SentAtMicros { get; }

    /// <summary>
    /// Gets the number of sent bytes.
    /// </summary>
    internal ulong SentBytes { get; }

    /// <summary>
    /// Gets whether the packet was ack-eliciting.
    /// </summary>
    internal bool AckEliciting { get; }

    /// <summary>
    /// Gets whether the packet counted as in flight.
    /// </summary>
    internal bool InFlight { get; }

    /// <summary>
    /// Gets whether the packet was acknowledged.
    /// </summary>
    internal bool Acknowledged { get; }

    /// <summary>
    /// Gets whether the packet was lost.
    /// </summary>
    internal bool Lost { get; }
}

/// <summary>
/// Minimal sender-facing facade that ties ACK generation to congestion-control state.
/// </summary>
internal sealed class QuicSenderFlowController
{
    private readonly Dictionary<QuicPacketNumberSpace, SortedDictionary<ulong, SentPacketState>> sentPacketsBySpace = [];

    /// <summary>
    /// Initializes a new sender-flow controller.
    /// </summary>
    internal QuicSenderFlowController(
        ulong maxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
        int maximumRetainedAckRanges = 32,
        int minimumAckElicitingPacketsBeforeDelayedAck = 2)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        CongestionControlState = new QuicCongestionControlState(maxDatagramSizeBytes);
        AckGenerationState = new QuicAckGenerationState(maximumRetainedAckRanges, minimumAckElicitingPacketsBeforeDelayedAck);
    }

    /// <summary>
    /// Gets the per-path congestion controller used by this facade.
    /// </summary>
    internal QuicCongestionControlState CongestionControlState { get; }

    /// <summary>
    /// Gets the ACK-generation state used by this facade.
    /// </summary>
    internal QuicAckGenerationState AckGenerationState { get; }

    /// <summary>
    /// Checks congestion-window limits before sending.
    /// </summary>
    internal bool CanSend(
        QuicPacketNumberSpace packetNumberSpace,
        ulong sentBytes,
        bool isAckOnlyPacket = false,
        bool isProbePacket = false)
    {
        _ = packetNumberSpace;
        return CongestionControlState.CanSend(sentBytes, isAckOnlyPacket, isProbePacket);
    }

    /// <summary>
    /// Records a sent packet and tracks it for ACK and loss processing.
    /// </summary>
    internal void RecordPacketSent(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentBytes,
        ulong sentAtMicros,
        bool ackEliciting,
        bool isAckOnlyPacket = false,
        bool isProbePacket = false)
    {
        CongestionControlState.RegisterPacketSent(sentBytes, isAckOnlyPacket, isProbePacket);
        if (isAckOnlyPacket)
        {
            return;
        }

        SortedDictionary<ulong, SentPacketState> sentPackets = GetOrCreateSentPackets(packetNumberSpace);
        sentPackets[packetNumber] = new SentPacketState(sentBytes, sentAtMicros, ackEliciting, InFlight: true, isProbePacket);
    }

    /// <summary>
    /// Processes an incoming ACK frame and advances congestion state.
    /// </summary>
    internal bool TryProcessAckFrame(
        QuicPacketNumberSpace packetNumberSpace,
        QuicAckFrame ackFrame,
        ulong ackReceivedAtMicros,
        bool applicationLimited = false,
        bool flowControlLimited = false,
        bool pacingLimited = false,
        bool pathValidated = false)
    {
        bool updated = false;
        ulong largestAcknowledgedPacketSentAtMicros = 0;

        List<ulong> acknowledgedPacketNumbers = EnumerateAcknowledgedPacketNumbers(ackFrame);
        if (TryGetSentPackets(packetNumberSpace, out SortedDictionary<ulong, SentPacketState>? sentPackets))
        {
            HashSet<ulong> deduplicatedPacketNumbers = [];

            foreach (ulong packetNumber in acknowledgedPacketNumbers)
            {
                if (!deduplicatedPacketNumbers.Add(packetNumber))
                {
                    continue;
                }

                if (!sentPackets.TryGetValue(packetNumber, out SentPacketState sentPacket))
                {
                    continue;
                }

                updated = CongestionControlState.TryRegisterAcknowledgedPacket(
                    sentPacket.SentBytes,
                    sentPacket.SentAtMicros,
                    packetInFlight: sentPacket.InFlight,
                    applicationLimited: applicationLimited,
                    flowControlLimited: flowControlLimited,
                    pacingLimited: pacingLimited) || updated;

                sentPackets.Remove(packetNumber);
                largestAcknowledgedPacketSentAtMicros = Math.Max(largestAcknowledgedPacketSentAtMicros, sentPacket.SentAtMicros);
            }
        }

        foreach (ulong packetNumber in acknowledgedPacketNumbers)
        {
            updated = AckGenerationState.TryRetireAcknowledgedAckRanges(packetNumberSpace, packetNumber) || updated;
        }

        if (ackFrame.EcnCounts.HasValue)
        {
            ulong largestSentAtMicros = largestAcknowledgedPacketSentAtMicros == 0
                ? ackReceivedAtMicros
                : largestAcknowledgedPacketSentAtMicros;

            updated = CongestionControlState.TryProcessEcn(
                packetNumberSpace,
                ackFrame.EcnCounts.Value.EcnCeCount,
                largestSentAtMicros,
                pathValidated: pathValidated) || updated;
        }

        return updated;
    }

    /// <summary>
    /// Processes a loss signal for a specific sent packet number.
    /// </summary>
    internal bool TryRegisterLoss(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentAtMicros,
        bool packetCanBeDecrypted = true,
        bool keysAvailable = true,
        bool sentAfterEarliestAcknowledgedPacket = true,
        bool allowAckOnlyLossSignal = false)
    {
        if (!TryGetSentPackets(packetNumberSpace, out SortedDictionary<ulong, SentPacketState>? sentPackets)
            || !sentPackets.TryGetValue(packetNumber, out SentPacketState sentPacket))
        {
            return false;
        }

        sentPackets.Remove(packetNumber);
        return CongestionControlState.TryRegisterLoss(
            sentPacket.SentBytes,
            sentAtMicros,
            packetInFlight: sentPacket.InFlight,
            packetCanBeDecrypted: packetCanBeDecrypted,
            keysAvailable: keysAvailable,
            sentAfterEarliestAcknowledgedPacket: sentAfterEarliestAcknowledgedPacket,
            isProbePacket: sentPacket.IsProbePacket,
            allowAckOnlyLossSignal: allowAckOnlyLossSignal);
    }

    /// <summary>
    /// Discards all retained packets in the specified packet number space.
    /// </summary>
    internal bool TryDiscardPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        bool updated = AckGenerationState.TryDiscardPacketNumberSpace(packetNumberSpace);

        if (!TryGetSentPackets(packetNumberSpace, out SortedDictionary<ulong, SentPacketState>? sentPackets))
        {
            return updated;
        }

        foreach (SentPacketState sentPacket in sentPackets.Values)
        {
            updated = CongestionControlState.TryDiscardPacket(sentPacket.SentBytes, sentPacket.InFlight) || updated;
        }

        sentPacketsBySpace.Remove(packetNumberSpace);
        return updated || sentPackets.Count > 0;
    }

    /// <summary>
    /// Records a received packet and drives ACK scheduling logic.
    /// The optional buffering delay captures time spent waiting for decryption keys before processing.
    /// </summary>
    internal void RecordIncomingPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool ackEliciting,
        ulong receivedAtMicros,
        ulong bufferingDelayMicros = 0,
        bool congestionExperienced = false,
        QuicEcnCounts? ecnCounts = null)
    {
        AckGenerationState.RecordProcessedPacket(
            packetNumberSpace,
            packetNumber,
            ackEliciting,
            receivedAtMicros,
            bufferingDelayMicros,
            congestionExperienced,
            ecnCounts);
    }

    /// <summary>
    /// Determines whether this state should send an immediate ACK for a packet number space.
    /// </summary>
    internal bool ShouldSendAckImmediately(QuicPacketNumberSpace packetNumberSpace)
    {
        return AckGenerationState.ShouldSendAckImmediately(packetNumberSpace);
    }

    /// <summary>
    /// Determines whether an ACK frame should be included with an outgoing packet.
    /// </summary>
    internal bool ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, ulong maxAckDelayMicros)
    {
        return AckGenerationState.ShouldIncludeAckFrameWithOutgoingPacket(packetNumberSpace, nowMicros, maxAckDelayMicros);
    }

    /// <summary>
    /// Determines whether an ACK-only packet should be sent for received packets.
    /// </summary>
    internal bool CanSendAckOnlyPacket(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, ulong maxAckDelayMicros)
    {
        return AckGenerationState.CanSendAckOnlyPacket(packetNumberSpace, nowMicros, maxAckDelayMicros);
    }

    /// <summary>
    /// Builds an ACK frame for the given packet number space.
    /// </summary>
    internal bool TryBuildAckFrame(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, out QuicAckFrame frame)
    {
        return AckGenerationState.TryBuildAckFrame(packetNumberSpace, nowMicros, out frame);
    }

    /// <summary>
    /// Marks an ACK frame as sent after processing.
    /// </summary>
    internal void MarkAckFrameSent(QuicPacketNumberSpace packetNumberSpace, ulong sentAtMicros, bool ackOnlyPacket)
    {
        AckGenerationState.MarkAckFrameSent(packetNumberSpace, sentAtMicros, ackOnlyPacket);
    }

    /// <summary>
    /// Marks a sent ACK frame so its acknowledged ranges can be retired when the carrier packet is acknowledged.
    /// </summary>
    internal void MarkAckFrameSent(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        QuicAckFrame ackFrame,
        ulong sentAtMicros,
        bool ackOnlyPacket)
    {
        AckGenerationState.MarkAckFrameSent(packetNumberSpace, packetNumber, ackFrame, sentAtMicros, ackOnlyPacket);
    }

    private static List<ulong> EnumerateAcknowledgedPacketNumbers(QuicAckFrame ackFrame)
    {
        List<ulong> acknowledgedPackets = [];

        if (ackFrame.LargestAcknowledged < ackFrame.FirstAckRange)
        {
            return acknowledgedPackets;
        }

        ulong largestAcknowledged = ackFrame.LargestAcknowledged;
        ulong smallestAcknowledged = largestAcknowledged - ackFrame.FirstAckRange;
        for (ulong packetNumber = smallestAcknowledged; ; packetNumber++)
        {
            acknowledgedPackets.Add(packetNumber);
            if (packetNumber == largestAcknowledged)
            {
                break;
            }
        }

        foreach (QuicAckRange range in ackFrame.AdditionalRanges)
        {
            for (ulong packetNumber = range.SmallestAcknowledged; ; packetNumber++)
            {
                acknowledgedPackets.Add(packetNumber);
                if (packetNumber == range.LargestAcknowledged)
                {
                    break;
                }
            }
        }

        return acknowledgedPackets;
    }

    private SortedDictionary<ulong, SentPacketState> GetOrCreateSentPackets(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!sentPacketsBySpace.TryGetValue(packetNumberSpace, out SortedDictionary<ulong, SentPacketState>? sentPackets))
        {
            sentPackets = [];
            sentPacketsBySpace[packetNumberSpace] = sentPackets;
        }

        return sentPackets;
    }

    private bool TryGetSentPackets(QuicPacketNumberSpace packetNumberSpace, [NotNullWhen(true)] out SortedDictionary<ulong, SentPacketState>? sentPackets)
    {
        return sentPacketsBySpace.TryGetValue(packetNumberSpace, out sentPackets);
    }

    private readonly record struct SentPacketState(
        ulong SentBytes,
        ulong SentAtMicros,
        bool AckEliciting,
        bool InFlight,
        bool IsProbePacket);
}
