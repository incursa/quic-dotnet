// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicConnectionSentPacketKey(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber);

/// <summary>
/// Captures the TLS encryption level associated with a CRYPTO send effect.
/// </summary>
internal readonly record struct QuicConnectionCryptoSendMetadata(
    QuicTlsEncryptionLevel EncryptionLevel);

internal readonly record struct QuicConnectionSentPacket(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber,
    ulong PayloadBytes,
    ulong SentAtMicros,
    bool AckEliciting = true,
    bool AckOnlyPacket = false,
    bool ProbePacket = false,
    bool Retransmittable = true,
    QuicConnectionCryptoSendMetadata? CryptoMetadata = null,
    ReadOnlyMemory<byte> PacketBytes = default,
    QuicTlsEncryptionLevel? PacketProtectionLevel = null,
    ulong? StreamId = null,
    ulong[]? StreamIds = null,
    ReadOnlyMemory<byte> PlaintextPayload = default,
    ulong? OneRttKeyPhase = null,
    byte[]? PlaintextPayloadOwner = null,
    byte[]? PacketBytesOwner = null);

internal readonly record struct QuicConnectionRetransmissionPlan(
    QuicPacketNumberSpace PacketNumberSpace,
    ulong PacketNumber,
    ulong PayloadBytes,
    ulong SentAtMicros,
    bool ProbePacket = false,
    QuicConnectionCryptoSendMetadata? CryptoMetadata = null,
    ReadOnlyMemory<byte> PacketBytes = default,
    QuicTlsEncryptionLevel? PacketProtectionLevel = null,
    ulong? StreamId = null,
    ulong[]? StreamIds = null,
    ReadOnlyMemory<byte> PlaintextPayload = default,
    ulong? OneRttKeyPhase = null,
    byte[]? PlaintextPayloadOwner = null,
    byte[]? PacketBytesOwner = null);

/// <summary>
/// Owns connection-scoped send state, PTO bookkeeping, and retransmission planning.
/// </summary>
internal sealed class QuicConnectionSendRuntime
{
    private const int InitialSentPacketCapacity = 64;

    private static readonly bool ReceiveEcnMetadataSupported = QuicSocketEcnControl.GetReceiveEcnMetadataCapability().IsSupported;
    private readonly Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPackets = new(InitialSentPacketCapacity);
    private readonly QuicRetransmissionQueue retransmissionQueue = new();
    private readonly QuicSenderFlowController flowController;
    private readonly QuicRttEstimator rttEstimator;
    private QuicEcnValidationState ecnValidationState;

    public QuicConnectionSendRuntime(
        QuicSenderFlowController? flowController = null,
        QuicCongestionControlAlgorithm congestionControlAlgorithm = QuicCongestionControlAlgorithm.NewReno)
    {
        this.flowController = flowController ?? new QuicSenderFlowController(congestionControlAlgorithm: congestionControlAlgorithm);
        rttEstimator = new QuicRttEstimator();
        ecnValidationState = new QuicEcnValidationState();
    }

    public QuicSenderFlowController FlowController => flowController;

    internal QuicRttEstimator RttEstimator => rttEstimator;

    internal QuicEcnValidationState EcnValidationState => ecnValidationState;

    internal QuicEcnMarking CurrentEcnMarking => ReceiveEcnMetadataSupported && ecnValidationState.IsEcnEnabled
        ? QuicEcnMarking.Ect0
        : QuicEcnMarking.NotEct;

    public IReadOnlyDictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> SentPackets => sentPackets;

    public ulong? LossDetectionDeadlineMicros { get; private set; }

    public int ProbeTimeoutCount { get; private set; }

    public int PendingRetransmissionCount => retransmissionQueue.Count;

    internal bool HasPendingRetransmission(QuicPacketNumberSpace packetNumberSpace)
    {
        return retransmissionQueue.HasPendingRetransmission(packetNumberSpace);
    }

    internal ulong? GetLargestTrackedPacketNumber(QuicPacketNumberSpace packetNumberSpace)
    {
        ulong largestPacketNumber = default;
        bool found = false;

        foreach (QuicConnectionSentPacketKey key in sentPackets.Keys)
        {
            if (key.PacketNumberSpace != packetNumberSpace)
            {
                continue;
            }

            largestPacketNumber = found
                ? Math.Max(largestPacketNumber, key.PacketNumber)
                : key.PacketNumber;
            found = true;
        }

        ulong? largestQueuedPacketNumber = retransmissionQueue.GetLargestTrackedPacketNumber(packetNumberSpace);
        if (largestQueuedPacketNumber.HasValue)
        {
            largestPacketNumber = found
                ? Math.Max(largestPacketNumber, largestQueuedPacketNumber.Value)
                : largestQueuedPacketNumber.Value;
            found = true;
        }

        return found ? largestPacketNumber : null;
    }

    internal QuicConnectionPathRecoverySnapshot CapturePathRecoverySnapshot()
    {
        return new QuicConnectionPathRecoverySnapshot(
            SmoothedRttMicros: rttEstimator.SmoothedRttMicros,
            RttVarMicros: rttEstimator.RttVarMicros,
            CongestionWindowBytes: flowController.CongestionControlState.CongestionWindowBytes,
            BytesInFlightBytes: flowController.CongestionControlState.BytesInFlightBytes,
            EcnValidated: ecnValidationState.IsEcnEnabled);
    }

    internal void ResetPathRecoveryState()
    {
        rttEstimator.Reset();
        ecnValidationState = new QuicEcnValidationState();
        flowController.CongestionControlState.Reset();
    }

    public bool HasAckElicitingPacketsInFlight
    {
        get
        {
            foreach (QuicConnectionSentPacket packet in sentPackets.Values)
            {
                if (packet.AckEliciting)
                {
                    return true;
                }
            }

            return false;
        }
    }

    public void TrackSentPacket(QuicConnectionSentPacket packet)
    {
        if (packet.ProbePacket && (packet.AckOnlyPacket || !packet.AckEliciting))
        {
            throw new ArgumentException("Probe packets must be ack-eliciting packets.", nameof(packet));
        }

        packet = NormalizePacketProtectionLevel(packet);
        ValidateCryptoMetadata(packet);
        ecnValidationState.RecordPacketSent(packet.PacketNumberSpace, CurrentEcnMarking);
        QuicConnectionSentPacketKey key = new(packet.PacketNumberSpace, packet.PacketNumber);
        if (sentPackets.Remove(key, out QuicConnectionSentPacket replacedPacket))
        {
            ReleasePacketOwners(replacedPacket);
        }

        sentPackets[key] = packet;
        flowController.RecordPacketSent(
            packet.PacketNumberSpace,
            packet.PacketNumber,
            packet.PayloadBytes,
            packet.SentAtMicros,
            packet.AckEliciting,
            packet.AckOnlyPacket,
            packet.ProbePacket,
            packet.PacketProtectionLevel,
            packet.OneRttKeyPhase);
        if (packet.AckEliciting && !packet.ProbePacket)
        {
            ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ProbeTimeoutCount,
                ackElicitingPacketSent: true);
            LossDetectionDeadlineMicros = null;
        }
    }

    public bool TryAcknowledgePacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool handshakeConfirmed = false)
    {
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);
        bool removedSentPacket = sentPackets.Remove(key, out QuicConnectionSentPacket acknowledgedPacket);
        bool removedPendingRetransmission = retransmissionQueue.TryRemovePendingRetransmission(key);
        if (!removedSentPacket && !removedPendingRetransmission)
        {
            return false;
        }

        if (removedSentPacket)
        {
            _ = TrySuppressResetStreamRetransmissionForAcknowledgedStreamData(acknowledgedPacket.PlaintextPayload.Span);
            ReleasePacketOwners(acknowledgedPacket);
        }

        bool acknowledgmentRestartsProbeTimeout =
            packetNumberSpace != QuicPacketNumberSpace.Initial || handshakeConfirmed;

        ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ProbeTimeoutCount,
            acknowledgmentReceived: true,
            acknowledgmentPacketNumberSpace: packetNumberSpace,
            handshakeConfirmed: handshakeConfirmed);

        if (acknowledgmentRestartsProbeTimeout || sentPackets.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public bool TryDiscardPacketNumberSpace(
        QuicPacketNumberSpace packetNumberSpace,
        bool discardAckGenerationState = true)
    {
        // CONTEXT: Discarding a packet number space has to purge sent packets, retransmission plans,
        // and the flow-controller state together so no stale recovery bookkeeping survives across the
        // space boundary. The scan-and-remove shape is deliberate because the sent-packet store is keyed
        // by packet number space rather than partitioned into separate tables.
        // SEE: code:src/Incursa.Quic/QuicConnectionSendRuntime.cs#TrackSentPacket
        // SEE: code:src/Incursa.Quic/QuicConnectionSendRuntime.cs#TryDiscardPacketProtectionLevel
        bool updated = flowController.TryDiscardPacketNumberSpace(packetNumberSpace, discardAckGenerationState);

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Key.PacketNumberSpace == packetNumberSpace)
            {
                (removedKeys ??= []).Add(entry.Key);
            }
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (sentPackets.Remove(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(removedPacket);
                    updated = true;
                }
            }
        }

        updated |= retransmissionQueue.TryDiscardPacketNumberSpace(packetNumberSpace);

        if (packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake)
        {
            ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ProbeTimeoutCount,
                initialOrHandshakeKeysDiscarded: true);
            LossDetectionDeadlineMicros = null;
            updated = true;
        }
        else if (sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    internal bool TryDiscardPacketNumberSpaceForPathMigration(
        QuicPacketNumberSpace packetNumberSpace,
        bool discardAckGenerationState = false)
    {
        List<QuicConnectionRetransmissionPlan>? retainedRetransmissions = null;
        if (packetNumberSpace == QuicPacketNumberSpace.ApplicationData)
        {
            retransmissionQueue.CaptureBuildableApplicationRetransmissions(sentPackets.Values, ref retainedRetransmissions);
        }

        bool updated = TryDiscardPacketNumberSpace(packetNumberSpace, discardAckGenerationState);

        if (retainedRetransmissions is null || retainedRetransmissions.Count == 0)
        {
            return updated;
        }

        retainedRetransmissions.Sort(static (left, right) => left.PacketNumber.CompareTo(right.PacketNumber));
        foreach (QuicConnectionRetransmissionPlan retransmission in retainedRetransmissions)
        {
            retransmissionQueue.QueueRetransmission(retransmission);
        }

        return true;
    }

    /// <summary>
    /// Discards all retained recovery state for packets that used the specified packet protection level.
    /// </summary>
    internal bool TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel packetProtectionLevel)
    {
        // CONTEXT: Packet-protection-level discard is broader than packet-number-space discard because
        // the runtime can retire an entire TLS encryption level even when some packet numbers are still
        // represented in other recovery tables. Keeping the purge split across these axes prevents stale
        // recovery state from surviving a handshake or key-discard transition.
        // SEE: code:src/Incursa.Quic/QuicConnectionSendRuntime.cs#TryDiscardPacketNumberSpace
        // SEE: code:src/Incursa.Quic/QuicConnectionSendRuntime.cs#TryDiscardOneRttKeyPhase
        bool updated = flowController.TryDiscardPacketProtectionLevel(packetProtectionLevel);

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Value.PacketProtectionLevel != packetProtectionLevel)
            {
                continue;
            }

            (removedKeys ??= []).Add(entry.Key);
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (sentPackets.Remove(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(removedPacket);
                    updated = true;
                }
            }
        }

        updated |= retransmissionQueue.TryDiscardPacketProtectionLevel(packetProtectionLevel);

        if (sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    /// <summary>
    /// Discards retained send state for 1-RTT packets protected with a specific Key Phase.
    /// </summary>
    internal bool TryDiscardOneRttKeyPhase(ulong keyPhase)
    {
        bool updated = flowController.TryDiscardOneRttKeyPhase(keyPhase);

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Value.PacketProtectionLevel != QuicTlsEncryptionLevel.OneRtt
                || entry.Value.OneRttKeyPhase != keyPhase)
            {
                continue;
            }

            (removedKeys ??= []).Add(entry.Key);
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (sentPackets.Remove(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(removedPacket);
                    updated = true;
                }
            }
        }

        updated |= retransmissionQueue.TryDiscardOneRttKeyPhase(keyPhase);

        if (sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    /// <summary>
    /// Discards queued retransmission plans sent before a retention cutoff.
    /// </summary>
    /// <remarks>
    /// This is a retention-policy helper; it leaves the retained sent-packet records intact so late
    /// acknowledgments can still settle the original send history.
    /// </remarks>
    public bool TryDiscardPendingRetransmissionsOlderThan(ulong discardBeforeSentAtMicros)
    {
        bool updated = retransmissionQueue.TryDiscardPendingRetransmissionsOlderThan(discardBeforeSentAtMicros);

        if (updated && retransmissionQueue.Count == 0 && sentPackets.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    public bool TryRegisterLoss(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool handshakeConfirmed = false,
        bool scheduleRetransmission = true)
    {
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);
        if (!sentPackets.Remove(key, out QuicConnectionSentPacket packet))
        {
            return false;
        }

        _ = flowController.TryRegisterLoss(
            packet.PacketNumberSpace,
            packet.PacketNumber,
            packet.SentAtMicros,
            allowAckOnlyLossSignal: packet.AckOnlyPacket);

        if (scheduleRetransmission && packet.Retransmittable)
        {
            retransmissionQueue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros,
                packet.ProbePacket,
                packet.CryptoMetadata,
                packet.PacketBytes,
                packet.PacketProtectionLevel,
                packet.StreamId,
                packet.StreamIds,
                packet.PlaintextPayload,
                packet.OneRttKeyPhase,
                packet.PlaintextPayloadOwner,
                packet.PacketBytesOwner));
        }
        else
        {
            ReleasePacketOwners(packet);
        }

        ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ProbeTimeoutCount,
            acknowledgmentPacketNumberSpace: packet.PacketNumberSpace,
            handshakeConfirmed: handshakeConfirmed);

        if (sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public bool TrySuppressRetransmissionForStream(ulong streamId)
    {
        bool updated = false;
        List<QuicConnectionSentPacketKey>? updatedPacketKeys = null;

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Value.StreamId != streamId
                && (entry.Value.StreamIds is null
                    || entry.Value.StreamIds.Length != 1
                    || entry.Value.StreamIds[0] != streamId)
                || !entry.Value.Retransmittable)
            {
                continue;
            }

            (updatedPacketKeys ??= []).Add(entry.Key);
        }

        if (updatedPacketKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in updatedPacketKeys)
            {
                sentPackets[key] = sentPackets[key] with { Retransmittable = false };
                updated = true;
            }
        }

        updated |= retransmissionQueue.TrySuppressRetransmissionForStream(streamId);

        if (updated && sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    public bool TrySuppressStopSendingRetransmissionForStream(ulong streamId)
    {
        bool updated = false;
        List<QuicConnectionSentPacketKey>? updatedPacketKeys = null;

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (!entry.Value.Retransmittable
                || !QuicFramePayloadInspector.ContainsStopSendingFrameForStream(entry.Value.PlaintextPayload.Span, streamId))
            {
                continue;
            }

            (updatedPacketKeys ??= []).Add(entry.Key);
        }

        if (updatedPacketKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in updatedPacketKeys)
            {
                sentPackets[key] = sentPackets[key] with { Retransmittable = false };
                updated = true;
            }
        }

        updated |= retransmissionQueue.TrySuppressStopSendingRetransmissionForStream(streamId);

        if (updated && sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    private bool TrySuppressResetStreamRetransmissionForAcknowledgedStreamData(ReadOnlySpan<byte> payload)
    {
        Span<ulong> inlineStreamIds = stackalloc ulong[4];
        int streamIdCount = QuicFramePayloadInspector.CopyStreamDataStreamIds(
            payload,
            inlineStreamIds,
            out ulong[]? overflowStreamIds);
        if (streamIdCount == 0)
        {
            return false;
        }

        bool updated = false;
        if (overflowStreamIds is not null)
        {
            foreach (ulong streamId in overflowStreamIds)
            {
                if (!ContainsOutstandingStreamDataForStream(streamId))
                {
                    updated |= TrySuppressResetStreamRetransmissionForStream(streamId);
                }
            }

            return updated;
        }

        for (int index = 0; index < streamIdCount; index++)
        {
            if (!ContainsOutstandingStreamDataForStream(inlineStreamIds[index]))
            {
                updated |= TrySuppressResetStreamRetransmissionForStream(inlineStreamIds[index]);
            }
        }

        return updated;
    }

    private bool ContainsOutstandingStreamDataForStream(ulong streamId)
    {
        foreach (QuicConnectionSentPacket packet in sentPackets.Values)
        {
            if (QuicFramePayloadInspector.ContainsStreamDataForStream(packet.PlaintextPayload.Span, streamId))
            {
                return true;
            }
        }

        return retransmissionQueue.ContainsStreamDataForStream(streamId);
    }

    private bool TrySuppressResetStreamRetransmissionForStream(ulong streamId)
    {
        bool updated = false;
        List<QuicConnectionSentPacketKey>? updatedPacketKeys = null;

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (!entry.Value.Retransmittable
                || !QuicFramePayloadInspector.ContainsResetStreamFrameForStream(entry.Value.PlaintextPayload.Span, streamId))
            {
                continue;
            }

            (updatedPacketKeys ??= []).Add(entry.Key);
        }

        if (updatedPacketKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in updatedPacketKeys)
            {
                sentPackets[key] = sentPackets[key] with { Retransmittable = false };
                updated = true;
            }
        }

        updated |= retransmissionQueue.TrySuppressResetStreamRetransmissionForStream(streamId);

        if (updated && sentPackets.Count == 0 && retransmissionQueue.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return updated;
    }

    public bool TryArmProbeTimeout(
        QuicPacketNumberSpace packetNumberSpace,
        ulong nowMicros,
        ulong smoothedRttMicros,
        ulong rttVarMicros,
        ulong maxAckDelayMicros,
        bool handshakeConfirmed)
    {
        if (!QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            packetNumberSpace,
            smoothedRttMicros,
            rttVarMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
            out ulong probeTimeoutMicros))
        {
            return false;
        }

        ulong backedOffProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros,
            ProbeTimeoutCount);

        LossDetectionDeadlineMicros = SaturatingAdd(nowMicros, backedOffProbeTimeoutMicros);
        ProbeTimeoutCount++;
        return true;
    }

    public bool TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission)
    {
        if (!retransmissionQueue.TryDequeueRetransmission(out retransmission))
        {
            return false;
        }

        if (retransmissionQueue.Count == 0 && sentPackets.Count == 0)
        {
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    public bool TryDequeueRetransmission(
        QuicPacketNumberSpace packetNumberSpace,
        out QuicConnectionRetransmissionPlan retransmission)
    {
        if (retransmissionQueue.Count == 0)
        {
            retransmission = default;
            return false;
        }

        int remainingPlans = retransmissionQueue.Count;
        while (remainingPlans-- > 0
            && TryDequeueRetransmission(out QuicConnectionRetransmissionPlan candidate))
        {
            if (candidate.PacketNumberSpace == packetNumberSpace)
            {
                retransmission = candidate;
                return true;
            }

            retransmissionQueue.QueueRetransmission(candidate);
        }

        retransmission = default;
        return false;
    }

    internal void QueueRetransmission(QuicConnectionRetransmissionPlan retransmission)
    {
        retransmissionQueue.QueueRetransmission(retransmission);
    }

    internal static void ReleaseRetransmissionPlanResources(QuicConnectionRetransmissionPlan retransmission)
    {
        ReleasePacketOwners(retransmission.PlaintextPayloadOwner, retransmission.PacketBytesOwner);
    }

    public void ClearLossDetectionDeadline()
    {
        LossDetectionDeadlineMicros = null;
    }

    private static QuicConnectionSentPacket NormalizePacketProtectionLevel(QuicConnectionSentPacket packet)
    {
        QuicTlsEncryptionLevel? packetProtectionLevel = packet.PacketProtectionLevel;
        if (packetProtectionLevel.HasValue)
        {
            if (packet.CryptoMetadata.HasValue
                && packet.CryptoMetadata.Value.EncryptionLevel != packetProtectionLevel.Value)
            {
                throw new ArgumentException(
                    "Packet protection level must match the crypto metadata.",
                    nameof(packet));
            }

            return packet;
        }

        if (packet.CryptoMetadata.HasValue)
        {
            packetProtectionLevel = packet.CryptoMetadata.Value.EncryptionLevel;
        }
        else if (packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
        {
            packetProtectionLevel = QuicTlsEncryptionLevel.OneRtt;
        }

        return packet with
        {
            PacketProtectionLevel = packetProtectionLevel,
        };
    }

    private static void ValidateCryptoMetadata(QuicConnectionSentPacket packet)
    {
        if (!packet.CryptoMetadata.HasValue)
        {
            return;
        }

        if (!TryMapCryptoEncryptionLevelToPacketNumberSpace(
            packet.CryptoMetadata.Value.EncryptionLevel,
            out QuicPacketNumberSpace expectedPacketNumberSpace)
            || expectedPacketNumberSpace != packet.PacketNumberSpace)
        {
            throw new ArgumentException(
                "Crypto metadata must match the packet number space.",
                nameof(packet));
        }
    }

    private static void ReleasePacketOwners(QuicConnectionSentPacket packet)
    {
        ReleasePacketOwners(packet.PlaintextPayloadOwner, packet.PacketBytesOwner);
    }

    private static void ReleasePacketOwners(byte[]? plaintextPayloadOwner, byte[]? packetBytesOwner)
    {
        if (plaintextPayloadOwner is not null)
        {
            QuicBufferPool.ReturnBytes(plaintextPayloadOwner);
        }

        if (packetBytesOwner is not null)
        {
            QuicBufferPool.ReturnBytes(packetBytesOwner);
        }
    }

    private static bool TryMapCryptoEncryptionLevelToPacketNumberSpace(
        QuicTlsEncryptionLevel encryptionLevel,
        out QuicPacketNumberSpace packetNumberSpace)
    {
        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                packetNumberSpace = QuicPacketNumberSpace.Initial;
                return true;
            case QuicTlsEncryptionLevel.Handshake:
                packetNumberSpace = QuicPacketNumberSpace.Handshake;
                return true;
            default:
                packetNumberSpace = default;
                return false;
        }
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }
}
