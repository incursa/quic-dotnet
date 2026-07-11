// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

internal enum QuicCongestionControlAlgorithm
{
    NewReno = 0,
    Cubic = 1,
}

/// <summary>
/// Tracks the RFC 9002 congestion-control state that can be modeled without a full sender or pacer.
/// </summary>
internal sealed class QuicCongestionControlState
{
    // CONTEXT: The three packet-number spaces are stored in fixed slots so send/ACK updates stay
    // allocation-free on the recovery hot path; the layout is immutable and should not become a map.
    // SEE: EcnCeCounters and the packet-number-space index constants
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

    private const double CubicBeta = 0.7d;
    private const double CubicC = 0.4d;
    private const double CubicMicrosecondsPerSecond = 1_000_000d;
    private const double CubicTcpFriendlyAlpha = 3d * (1d - CubicBeta) / (1d + CubicBeta);
    private const ulong CubicLossReductionNumerator = 7;
    private const ulong CubicLossReductionDenominator = 10;
    private const ulong CubicFastConvergenceNumerator = 17;
    private const ulong CubicFastConvergenceDenominator = 20;

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
    /// RFC 9002 does not use a max_datagram_size below QUIC v1's 1200-byte floor.
    /// </summary>
    internal const ulong MinimumMaxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;

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
    private readonly QuicCongestionControlAlgorithm congestionControlAlgorithm;
    private ulong cubicWindowMaxBytes;
    private ulong cubicEpochStartMicros;
    private ulong cubicPauseStartedMicros;
    private bool cubicHasEpochStart;
    private bool cubicEpochPaused;

    /// <summary>
    /// Initializes a new congestion-control state using the RFC 9002 default maximum datagram size.
    /// </summary>
    internal QuicCongestionControlState(
        ulong maxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
        QuicCongestionControlAlgorithm congestionControlAlgorithm = QuicCongestionControlAlgorithm.NewReno)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        this.congestionControlAlgorithm = congestionControlAlgorithm;
        MaxDatagramSizeBytes = maxDatagramSizeBytes;
        MinimumCongestionWindowBytes = ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes);
        CongestionWindowBytes = ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes);
        SlowStartThresholdBytes = ulong.MaxValue;
        ResetCongestionControlAlgorithmState();
    }

    /// <summary>
    /// Gets the current maximum datagram size used for congestion-window computations.
    /// </summary>
    internal ulong MaxDatagramSizeBytes { get; private set; }

    /// <summary>
    /// Gets the congestion-control algorithm selected for this state.
    /// </summary>
    internal QuicCongestionControlAlgorithm CongestionControlAlgorithm => congestionControlAlgorithm;

    internal ulong CubicWindowMaxBytes => cubicWindowMaxBytes;

    internal ulong? CubicEpochStartMicros => cubicHasEpochStart ? cubicEpochStartMicros : null;

    internal bool CubicEpochPaused => cubicEpochPaused;

    /// <summary>
    /// Gets the max_datagram_size value used by RFC 9002 recovery formulas.
    /// </summary>
    internal ulong RecoveryMaxDatagramSizeBytes => NormalizeMaxDatagramSizeForRecovery(MaxDatagramSizeBytes);

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

    internal ulong[] EcnCeCounters => ecnCeCounters;

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
        ulong normalizedMaxDatagramSizeBytes = NormalizeMaxDatagramSizeForRecovery(maxDatagramSizeBytes);

        ulong tenDatagrams = MultiplySaturating(normalizedMaxDatagramSizeBytes, InitialCongestionWindowDatagramCount);
        ulong twoDatagrams = MultiplySaturating(normalizedMaxDatagramSizeBytes, MinimumCongestionWindowMultiplier);
        ulong floor = Math.Max(twoDatagrams, MinimumInitialCongestionWindowBytes);
        return Math.Min(tenDatagrams, floor);
    }

    /// <summary>
    /// Computes the RFC 9002 minimum congestion window for the supplied datagram size.
    /// </summary>
    internal static ulong ComputeMinimumCongestionWindowBytes(ulong maxDatagramSizeBytes)
    {
        ulong normalizedMaxDatagramSizeBytes = NormalizeMaxDatagramSizeForRecovery(maxDatagramSizeBytes);

        return MultiplySaturating(normalizedMaxDatagramSizeBytes, MinimumCongestionWindowMultiplier);
    }

    /// <summary>
    /// Clamps path-derived maximum datagram sizes for RFC 9002 recovery formulas.
    /// </summary>
    internal static ulong NormalizeMaxDatagramSizeForRecovery(ulong maxDatagramSizeBytes)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        return Math.Max(maxDatagramSizeBytes, MinimumMaxDatagramSizeBytes);
    }

    /// <summary>
    /// Computes the QUIC payload bytes that count toward bytes_in_flight.
    /// </summary>
    internal static ulong ComputeBytesInFlightBytes(
        ulong quicHeaderBytes,
        ulong protectedPayloadBytes,
        ulong aeadOverheadBytes,
        ulong ipOverheadBytes = 0,
        ulong udpOverheadBytes = 0)
    {
        _ = ipOverheadBytes;
        _ = udpOverheadBytes;

        return SaturatingAdd(
            SaturatingAdd(quicHeaderBytes, protectedPayloadBytes),
            aeadOverheadBytes);
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
            ResetCongestionControlAlgorithmState();
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
        bool pacingLimited = false,
        ulong? ackReceivedAtMicros = null)
    {
        if (!packetInFlight)
        {
            return false;
        }

        ulong effectiveAckReceivedAtMicros = ackReceivedAtMicros ?? sentAtMicros;
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

        bool congestionWindowGrowthLimited = applicationLimited
            || flowControlLimited
            || (!pacingLimited && BytesInFlightBytes < CongestionWindowBytes);
        UpdateCubicEpochPause(effectiveAckReceivedAtMicros, congestionWindowGrowthLimited);
        if (congestionWindowGrowthLimited)
        {
            return true;
        }

        if (CongestionWindowBytes < SlowStartThresholdBytes)
        {
            CongestionWindowBytes = SaturatingAdd(CongestionWindowBytes, sentBytes);
            return true;
        }

        if (congestionControlAlgorithm == QuicCongestionControlAlgorithm.Cubic)
        {
            CongestionWindowBytes = ComputeCubicCongestionWindowBytes(
                currentCongestionWindowBytes: CongestionWindowBytes,
                ackReceivedAtMicros: effectiveAckReceivedAtMicros,
                sentAtMicros: sentAtMicros);
            return true;
        }

        ulong growthBytes = DivideSaturating(MultiplySaturating(RecoveryMaxDatagramSizeBytes, sentBytes), CongestionWindowBytes);
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

        ulong congestionEventFlightSizeBytes = BytesInFlightBytes;
        if (packetInFlight)
        {
            BytesInFlightBytes = SubtractSaturating(BytesInFlightBytes, sentBytes);
        }

        if (isProbePacket)
        {
            return true;
        }

        EnterRecovery(sentAtMicros, congestionEventFlightSizeBytes, ecnCongestionEvent: false);
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

        EnterRecovery(
            largestAcknowledgedPacketSentAtMicros,
            BytesInFlightBytes,
            ecnCongestionEvent: true);
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

        ulong congestionEventFlightSizeBytes = BytesInFlightBytes;
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
            EnterRecovery(
                latestLossSentAtMicros,
                congestionEventFlightSizeBytes,
                ecnCongestionEvent: false);
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
            ResetCongestionControlAlgorithmState();
        }

        return true;
    }

    private bool IsInRecovery(ulong sentAtMicros)
    {
        return RecoveryStartTimeMicros.HasValue && sentAtMicros <= RecoveryStartTimeMicros.Value;
    }

    private void EnterRecovery(
        ulong sentAtMicros,
        ulong congestionEventFlightSizeBytes,
        bool ecnCongestionEvent)
    {
        if (IsInRecovery(sentAtMicros))
        {
            return;
        }

        if (congestionControlAlgorithm == QuicCongestionControlAlgorithm.Cubic)
        {
            if (cubicWindowMaxBytes > 0 && CongestionWindowBytes < cubicWindowMaxBytes)
            {
                cubicWindowMaxBytes = ComputeReducedCongestionWindowBytes(
                    CongestionWindowBytes,
                    reductionNumerator: CubicFastConvergenceNumerator,
                    reductionDenominator: CubicFastConvergenceDenominator,
                    minimumCongestionWindowBytes: MinimumCongestionWindowBytes);
            }
            else
            {
                cubicWindowMaxBytes = CongestionWindowBytes;
            }
            cubicEpochStartMicros = sentAtMicros;
            cubicHasEpochStart = true;
            cubicPauseStartedMicros = 0;
            cubicEpochPaused = false;
        }

        RecoveryStartTimeMicros = sentAtMicros;
        if (congestionControlAlgorithm == QuicCongestionControlAlgorithm.Cubic)
        {
            ulong reducedFlightSizeBytes = ComputeReducedCongestionWindowBytes(
                congestionEventFlightSizeBytes,
                CubicLossReductionNumerator,
                CubicLossReductionDenominator);

            SlowStartThresholdBytes = Math.Max(reducedFlightSizeBytes, MinimumCongestionWindowBytes);
            ulong congestionWindowFloorBytes = ecnCongestionEvent
                ? RecoveryMaxDatagramSizeBytes
                : MinimumCongestionWindowBytes;
            CongestionWindowBytes = Math.Max(reducedFlightSizeBytes, congestionWindowFloorBytes);
            return;
        }

        SlowStartThresholdBytes = ComputeReducedCongestionWindowBytes(
            CongestionWindowBytes,
            RecommendedLossReductionNumerator,
            RecommendedLossReductionDenominator,
            MinimumCongestionWindowBytes);
        CongestionWindowBytes = SlowStartThresholdBytes;
    }

    private ulong ComputeCubicCongestionWindowBytes(
        ulong currentCongestionWindowBytes,
        ulong ackReceivedAtMicros,
        ulong sentAtMicros)
    {
        if (!cubicHasEpochStart)
        {
            InitializeCubicEpoch(ackReceivedAtMicros, currentCongestionWindowBytes);
        }

        double currentMssBytes = RecoveryMaxDatagramSizeBytes;
        double wMaxPackets = Math.Max(1d, cubicWindowMaxBytes / currentMssBytes);
        double elapsedSeconds = ackReceivedAtMicros <= cubicEpochStartMicros
            ? 0d
            : (ackReceivedAtMicros - cubicEpochStartMicros) / CubicMicrosecondsPerSecond;
        double roundTripSeconds = ackReceivedAtMicros <= sentAtMicros
            ? 0.000001d
            : (ackReceivedAtMicros - sentAtMicros) / CubicMicrosecondsPerSecond;
        double cubicKSeconds = Math.Cbrt(wMaxPackets * (1d - CubicBeta) / CubicC);
        double cubicPackets = CubicC * Math.Pow(elapsedSeconds - cubicKSeconds, 3d) + wMaxPackets;
        double tcpFriendlyPackets = wMaxPackets * CubicBeta + CubicTcpFriendlyAlpha * (elapsedSeconds / roundTripSeconds);
        double targetPackets = Math.Max(cubicPackets, tcpFriendlyPackets);
        if (double.IsNaN(targetPackets) || double.IsInfinity(targetPackets))
        {
            return currentCongestionWindowBytes;
        }

        ulong targetBytes = MultiplySaturating((ulong)Math.Ceiling(targetPackets), (ulong)currentMssBytes);
        return Math.Max(currentCongestionWindowBytes, targetBytes);
    }

    private void InitializeCubicEpoch(ulong ackReceivedAtMicros, ulong currentCongestionWindowBytes)
    {
        cubicWindowMaxBytes = Math.Max(cubicWindowMaxBytes, currentCongestionWindowBytes);
        cubicEpochStartMicros = ackReceivedAtMicros;
        cubicHasEpochStart = true;
    }

    private void UpdateCubicEpochPause(ulong ackReceivedAtMicros, bool congestionWindowGrowthLimited)
    {
        if (congestionControlAlgorithm != QuicCongestionControlAlgorithm.Cubic || !cubicHasEpochStart)
        {
            return;
        }

        if (congestionWindowGrowthLimited)
        {
            if (!cubicEpochPaused)
            {
                cubicPauseStartedMicros = ackReceivedAtMicros;
                cubicEpochPaused = true;
            }

            return;
        }

        if (!cubicEpochPaused)
        {
            return;
        }

        ulong pausedDurationMicros = ackReceivedAtMicros <= cubicPauseStartedMicros
            ? 0
            : ackReceivedAtMicros - cubicPauseStartedMicros;
        cubicEpochStartMicros = SaturatingAdd(cubicEpochStartMicros, pausedDurationMicros);
        cubicPauseStartedMicros = 0;
        cubicEpochPaused = false;
    }

    private void ResetCongestionControlAlgorithmState()
    {
        cubicWindowMaxBytes = 0;
        cubicEpochStartMicros = 0;
        cubicPauseStartedMicros = 0;
        cubicHasEpochStart = false;
        cubicEpochPaused = false;
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
    private const int InitialPacketNumberSpaceCapacity = 32;

    private readonly Dictionary<QuicPacketNumberSpace, SortedList<ulong, SentPacketState>> sentPacketsBySpace = [];

    /// <summary>
    /// Initializes a new sender-flow controller.
    /// </summary>
    internal QuicSenderFlowController(
        ulong maxDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
        int maximumRetainedAckRanges = 32,
        int minimumAckElicitingPacketsBeforeDelayedAck = 2,
        QuicCongestionControlAlgorithm congestionControlAlgorithm = QuicCongestionControlAlgorithm.NewReno)
    {
        if (maxDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDatagramSizeBytes));
        }

        CongestionControlState = new QuicCongestionControlState(maxDatagramSizeBytes, congestionControlAlgorithm);
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
        bool isProbePacket = false,
        QuicTlsEncryptionLevel? packetProtectionLevel = null,
        ulong? oneRttKeyPhase = null)
    {
        CongestionControlState.RegisterPacketSent(sentBytes, isAckOnlyPacket, isProbePacket);
        if (isAckOnlyPacket)
        {
            return;
        }

        SortedList<ulong, SentPacketState> sentPackets = GetOrCreateSentPackets(packetNumberSpace);
        sentPackets[packetNumber] = new SentPacketState(
            sentBytes,
            sentAtMicros,
            ackEliciting,
            InFlight: true,
            isProbePacket,
            packetProtectionLevel,
            oneRttKeyPhase);
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

        if (TryGetSentPackets(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets))
        {
            int index = 0;
            while (index < sentPackets.Count)
            {
                ulong sentPacketNumber = sentPackets.Keys[index];
                if (!AckFrameAcknowledgesPacketNumber(ackFrame, sentPacketNumber))
                {
                    index++;
                    continue;
                }

                SentPacketState sentPacket = sentPackets.Values[index];
                updated = CongestionControlState.TryRegisterAcknowledgedPacket(
                    sentPacket.SentBytes,
                    sentPacket.SentAtMicros,
                    packetInFlight: sentPacket.InFlight,
                    applicationLimited: applicationLimited,
                    flowControlLimited: flowControlLimited,
                    pacingLimited: pacingLimited,
                    ackReceivedAtMicros: ackReceivedAtMicros) || updated;

                largestAcknowledgedPacketSentAtMicros = Math.Max(largestAcknowledgedPacketSentAtMicros, sentPacket.SentAtMicros);
                sentPackets.RemoveAt(index);
            }
        }

        updated = AckGenerationState.TryRetireAcknowledgedAckRanges(packetNumberSpace, ackFrame) || updated;

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
        if (!TryGetSentPackets(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets)
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
    internal bool TryDiscardPacketNumberSpace(
        QuicPacketNumberSpace packetNumberSpace,
        bool discardAckGenerationState = true)
    {
        bool updated = discardAckGenerationState
            && AckGenerationState.TryDiscardPacketNumberSpace(packetNumberSpace);

        if (!TryGetSentPackets(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets))
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
    /// Discards retained packets with the specified packet protection level without altering ACK-generation state.
    /// </summary>
    internal bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        return TryDiscardPacketProtectionLevel(
            GetPacketNumberSpaceForPacketProtectionLevel(packetProtectionLevel),
            packetProtectionLevel);
    }

    /// <summary>
    /// Discards retained 1-RTT packets that were protected with a specific Key Phase.
    /// </summary>
    internal bool TryDiscardOneRttKeyPhase(ulong keyPhase)
    {
        return TryDiscardOneRttKeyPhase(QuicPacketNumberSpace.ApplicationData, keyPhase);
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

    private static bool AckFrameAcknowledgesPacketNumber(QuicAckFrame ackFrame, ulong packetNumber)
    {
        if (ackFrame.FirstAckRange > ackFrame.LargestAcknowledged)
        {
            return false;
        }

        ulong firstRangeSmallestAcknowledged = ackFrame.LargestAcknowledged - ackFrame.FirstAckRange;
        if (packetNumber >= firstRangeSmallestAcknowledged && packetNumber <= ackFrame.LargestAcknowledged)
        {
            return true;
        }

        foreach (QuicAckRange range in ackFrame.AdditionalRangeSpan)
        {
            if (packetNumber >= range.SmallestAcknowledged && packetNumber <= range.LargestAcknowledged)
            {
                return true;
            }
        }

        return false;
    }

    private SortedList<ulong, SentPacketState> GetOrCreateSentPackets(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!sentPacketsBySpace.TryGetValue(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets))
        {
            sentPackets = new SortedList<ulong, SentPacketState>(InitialPacketNumberSpaceCapacity);
            sentPacketsBySpace[packetNumberSpace] = sentPackets;
        }

        return sentPackets;
    }

    private bool TryGetSentPackets(QuicPacketNumberSpace packetNumberSpace, [NotNullWhen(true)] out SortedList<ulong, SentPacketState>? sentPackets)
    {
        return sentPacketsBySpace.TryGetValue(packetNumberSpace, out sentPackets);
    }

    private static QuicPacketNumberSpace GetPacketNumberSpaceForPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        return packetProtectionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Handshake => QuicPacketNumberSpace.Handshake,
            QuicTlsEncryptionLevel.ZeroRtt or QuicTlsEncryptionLevel.OneRtt => QuicPacketNumberSpace.ApplicationData,
            _ => QuicPacketNumberSpace.ApplicationData,
        };
    }

    private bool TryDiscardPacketProtectionLevel(
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel packetProtectionLevel)
    {
        if (!TryGetSentPackets(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets))
        {
            return false;
        }

        if (sentPackets.Count == 0)
        {
            sentPacketsBySpace.Remove(packetNumberSpace);
            return false;
        }

        ulong[]? removedPacketNumbers = null;
        int removedPacketNumberCount = 0;
        bool updated = false;

        try
        {
            foreach (KeyValuePair<ulong, SentPacketState> sentPacketEntry in sentPackets)
            {
                if (sentPacketEntry.Value.PacketProtectionLevel != packetProtectionLevel)
                {
                    continue;
                }

                updated = CongestionControlState.TryDiscardPacket(sentPacketEntry.Value.SentBytes, sentPacketEntry.Value.InFlight) || updated;
                (removedPacketNumbers ??= ArrayPool<ulong>.Shared.Rent(sentPackets.Count))[removedPacketNumberCount++] = sentPacketEntry.Key;
            }

            RemoveDiscardedPacketNumbers(packetNumberSpace, sentPackets, removedPacketNumbers, removedPacketNumberCount);
            return updated;
        }
        finally
        {
            if (removedPacketNumbers is not null)
            {
                ArrayPool<ulong>.Shared.Return(removedPacketNumbers);
            }
        }
    }

    private bool TryDiscardOneRttKeyPhase(QuicPacketNumberSpace packetNumberSpace, ulong keyPhase)
    {
        if (!TryGetSentPackets(packetNumberSpace, out SortedList<ulong, SentPacketState>? sentPackets))
        {
            return false;
        }

        if (sentPackets.Count == 0)
        {
            sentPacketsBySpace.Remove(packetNumberSpace);
            return false;
        }

        ulong[]? removedPacketNumbers = null;
        int removedPacketNumberCount = 0;
        bool updated = false;

        try
        {
            foreach (KeyValuePair<ulong, SentPacketState> sentPacketEntry in sentPackets)
            {
                if (sentPacketEntry.Value.PacketProtectionLevel != QuicTlsEncryptionLevel.OneRtt
                    || sentPacketEntry.Value.OneRttKeyPhase != keyPhase)
                {
                    continue;
                }

                updated = CongestionControlState.TryDiscardPacket(sentPacketEntry.Value.SentBytes, sentPacketEntry.Value.InFlight) || updated;
                (removedPacketNumbers ??= ArrayPool<ulong>.Shared.Rent(sentPackets.Count))[removedPacketNumberCount++] = sentPacketEntry.Key;
            }

            RemoveDiscardedPacketNumbers(packetNumberSpace, sentPackets, removedPacketNumbers, removedPacketNumberCount);
            return updated;
        }
        finally
        {
            if (removedPacketNumbers is not null)
            {
                ArrayPool<ulong>.Shared.Return(removedPacketNumbers);
            }
        }
    }

    private void RemoveDiscardedPacketNumbers(
        QuicPacketNumberSpace packetNumberSpace,
        SortedList<ulong, SentPacketState> sentPackets,
        ulong[]? removedPacketNumbers,
        int removedPacketNumberCount)
    {
        if (removedPacketNumberCount == 0 || removedPacketNumbers is null)
        {
            return;
        }

        for (int index = 0; index < removedPacketNumberCount; index++)
        {
            sentPackets.Remove(removedPacketNumbers[index]);
        }

        if (sentPackets.Count == 0)
        {
            sentPacketsBySpace.Remove(packetNumberSpace);
        }
    }

    private readonly record struct SentPacketState(
        ulong SentBytes,
        ulong SentAtMicros,
        bool AckEliciting,
        bool InFlight,
        bool IsProbePacket,
        QuicTlsEncryptionLevel? PacketProtectionLevel = null,
        ulong? OneRttKeyPhase = null);
}
