// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicConnectionSentPacketKey
{
    private const int PacketNumberSpaceShift = 62;
    private const ulong PacketNumberMask = QuicVariableLengthInteger.MaxValue;

    private readonly ulong packedValue;

    internal QuicConnectionSentPacketKey(
        QuicPacketNumberSpace PacketNumberSpace,
        ulong PacketNumber)
    {
        if ((uint)PacketNumberSpace > (uint)QuicPacketNumberSpace.ApplicationData)
        {
            throw new ArgumentOutOfRangeException(nameof(PacketNumberSpace));
        }

        if (PacketNumber > PacketNumberMask)
        {
            throw new ArgumentOutOfRangeException(nameof(PacketNumber));
        }

        packedValue = PacketNumber | ((ulong)PacketNumberSpace << PacketNumberSpaceShift);
    }

    internal QuicPacketNumberSpace PacketNumberSpace =>
        (QuicPacketNumberSpace)(packedValue >> PacketNumberSpaceShift);

    internal ulong PacketNumber => packedValue & PacketNumberMask;
}

/// <summary>
/// Captures the TLS encryption level associated with a CRYPTO send effect.
/// </summary>
internal readonly record struct QuicConnectionCryptoSendMetadata(
    QuicTlsEncryptionLevel EncryptionLevel);

internal readonly record struct QuicSentPacketNumberSpaceStorageSnapshot(
    int RetainedPacketCount,
    ulong PacketNumberSpan);

internal readonly record struct QuicSentPacketStorageSnapshot(
    int RetainedPacketCount,
    int Capacity,
    QuicSentPacketNumberSpaceStorageSnapshot Initial,
    QuicSentPacketNumberSpaceStorageSnapshot Handshake,
    QuicSentPacketNumberSpaceStorageSnapshot ApplicationData)
{
    internal QuicSentPacketNumberSpaceStorageSnapshot GetPacketNumberSpace(
        QuicPacketNumberSpace packetNumberSpace)
        => packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => Initial,
            QuicPacketNumberSpace.Handshake => Handshake,
            QuicPacketNumberSpace.ApplicationData => ApplicationData,
            _ => throw new ArgumentOutOfRangeException(nameof(packetNumberSpace)),
        };
}

internal record struct QuicConnectionSentPacket
{
    private const byte AckElicitingFlag = 1 << 0;
    private const byte AckOnlyPacketFlag = 1 << 1;
    private const byte ProbePacketFlag = 1 << 2;
    private const byte RetransmittableFlag = 1 << 3;
    private const byte HasCryptoMetadataFlag = 1 << 4;
    private const byte HasPacketProtectionLevelFlag = 1 << 5;
    private const byte HasStreamIdFlag = 1 << 6;
    private const byte HasOneRttKeyPhaseFlag = 1 << 7;

    private byte flags;
    private QuicTlsEncryptionLevel cryptoEncryptionLevel;
    private QuicTlsEncryptionLevel packetProtectionLevel;
    private ulong streamId;
    private ulong oneRttKeyPhase;

    internal QuicConnectionSentPacket(
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
        byte[]? PacketBytesOwner = null,
        QuicBufferCopyLifetimeToken PlaintextPayloadLifetimeToken = default,
        QuicBufferCopyLifetimeToken PacketBytesLifetimeToken = default)
    {
        this.PacketNumberSpace = PacketNumberSpace;
        this.PacketNumber = PacketNumber;
        this.PayloadBytes = PayloadBytes;
        this.SentAtMicros = SentAtMicros;
        flags = (byte)(
            (AckEliciting ? AckElicitingFlag : 0)
            | (AckOnlyPacket ? AckOnlyPacketFlag : 0)
            | (ProbePacket ? ProbePacketFlag : 0)
            | (Retransmittable ? RetransmittableFlag : 0)
            | (CryptoMetadata.HasValue ? HasCryptoMetadataFlag : 0)
            | (PacketProtectionLevel.HasValue ? HasPacketProtectionLevelFlag : 0)
            | (StreamId.HasValue ? HasStreamIdFlag : 0)
            | (OneRttKeyPhase.HasValue ? HasOneRttKeyPhaseFlag : 0));
        cryptoEncryptionLevel = CryptoMetadata.GetValueOrDefault().EncryptionLevel;
        packetProtectionLevel = PacketProtectionLevel.GetValueOrDefault();
        streamId = StreamId.GetValueOrDefault();
        oneRttKeyPhase = OneRttKeyPhase.GetValueOrDefault();
        this.PacketBytes = PacketBytes;
        this.StreamIds = StreamIds;
        this.PlaintextPayload = PlaintextPayload;
        this.PlaintextPayloadOwner = PlaintextPayloadOwner;
        this.PacketBytesOwner = PacketBytesOwner;
        this.PlaintextPayloadLifetimeToken =
            PlaintextPayloadLifetimeToken;
        this.PacketBytesLifetimeToken =
            PacketBytesLifetimeToken;
    }

    public QuicPacketNumberSpace PacketNumberSpace { readonly get; init; }

    public ulong PacketNumber { readonly get; init; }

    public ulong PayloadBytes { readonly get; init; }

    public ulong SentAtMicros { readonly get; init; }

    public bool AckEliciting
    {
        readonly get => HasFlag(AckElicitingFlag);
        init => SetFlag(AckElicitingFlag, value);
    }

    public bool AckOnlyPacket
    {
        readonly get => HasFlag(AckOnlyPacketFlag);
        init => SetFlag(AckOnlyPacketFlag, value);
    }

    public bool ProbePacket
    {
        readonly get => HasFlag(ProbePacketFlag);
        init => SetFlag(ProbePacketFlag, value);
    }

    public bool Retransmittable
    {
        readonly get => HasFlag(RetransmittableFlag);
        init => SetFlag(RetransmittableFlag, value);
    }

    public QuicConnectionCryptoSendMetadata? CryptoMetadata
    {
        readonly get => HasFlag(HasCryptoMetadataFlag)
            ? new QuicConnectionCryptoSendMetadata(cryptoEncryptionLevel)
            : null;
        init
        {
            cryptoEncryptionLevel = value.GetValueOrDefault().EncryptionLevel;
            SetFlag(HasCryptoMetadataFlag, value.HasValue);
        }
    }

    public ReadOnlyMemory<byte> PacketBytes { readonly get; init; }

    public QuicTlsEncryptionLevel? PacketProtectionLevel
    {
        readonly get => HasFlag(HasPacketProtectionLevelFlag) ? packetProtectionLevel : null;
        init
        {
            packetProtectionLevel = value.GetValueOrDefault();
            SetFlag(HasPacketProtectionLevelFlag, value.HasValue);
        }
    }

    public ulong? StreamId
    {
        readonly get => HasFlag(HasStreamIdFlag) ? streamId : null;
        init
        {
            streamId = value.GetValueOrDefault();
            SetFlag(HasStreamIdFlag, value.HasValue);
        }
    }

    public ulong[]? StreamIds { readonly get; init; }

    public ReadOnlyMemory<byte> PlaintextPayload { readonly get; init; }

    public ulong? OneRttKeyPhase
    {
        readonly get => HasFlag(HasOneRttKeyPhaseFlag) ? oneRttKeyPhase : null;
        init
        {
            oneRttKeyPhase = value.GetValueOrDefault();
            SetFlag(HasOneRttKeyPhaseFlag, value.HasValue);
        }
    }

    public byte[]? PlaintextPayloadOwner { readonly get; init; }

    public byte[]? PacketBytesOwner { readonly get; init; }

    public QuicBufferCopyLifetimeToken PlaintextPayloadLifetimeToken
    {
        readonly get;
        init;
    }

    public QuicBufferCopyLifetimeToken PacketBytesLifetimeToken
    {
        readonly get;
        init;
    }

    public readonly void Deconstruct(
        out QuicPacketNumberSpace PacketNumberSpace,
        out ulong PacketNumber,
        out ulong PayloadBytes,
        out ulong SentAtMicros,
        out bool AckEliciting,
        out bool AckOnlyPacket,
        out bool ProbePacket,
        out bool Retransmittable,
        out QuicConnectionCryptoSendMetadata? CryptoMetadata,
        out ReadOnlyMemory<byte> PacketBytes,
        out QuicTlsEncryptionLevel? PacketProtectionLevel,
        out ulong? StreamId,
        out ulong[]? StreamIds,
        out ReadOnlyMemory<byte> PlaintextPayload,
        out ulong? OneRttKeyPhase,
        out byte[]? PlaintextPayloadOwner,
        out byte[]? PacketBytesOwner)
    {
        PacketNumberSpace = this.PacketNumberSpace;
        PacketNumber = this.PacketNumber;
        PayloadBytes = this.PayloadBytes;
        SentAtMicros = this.SentAtMicros;
        AckEliciting = this.AckEliciting;
        AckOnlyPacket = this.AckOnlyPacket;
        ProbePacket = this.ProbePacket;
        Retransmittable = this.Retransmittable;
        CryptoMetadata = this.CryptoMetadata;
        PacketBytes = this.PacketBytes;
        PacketProtectionLevel = this.PacketProtectionLevel;
        StreamId = this.StreamId;
        StreamIds = this.StreamIds;
        PlaintextPayload = this.PlaintextPayload;
        OneRttKeyPhase = this.OneRttKeyPhase;
        PlaintextPayloadOwner = this.PlaintextPayloadOwner;
        PacketBytesOwner = this.PacketBytesOwner;
    }

    private readonly bool HasFlag(byte flag) => (flags & flag) != 0;

    private void SetFlag(byte flag, bool value)
    {
        flags = value ? (byte)(flags | flag) : (byte)(flags & ~flag);
    }
}

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
    byte[]? PacketBytesOwner = null,
    QuicBufferCopyLifetimeToken PlaintextPayloadLifetimeToken = default,
    QuicBufferCopyLifetimeToken PacketBytesLifetimeToken = default);

internal readonly record struct QuicConnectionPendingSendReservation(ulong Sequence);

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
    private QuicOutstandingSentStreamPacketIndex outstandingSentStreamPacketIndex = new();
    private QuicEcnValidationState ecnValidationState;
    private long retainedSentPacketBufferCount;
    private long retainedSentPacketByteCount;
    private ulong? oldestSentPacketAtMicros;
    private QuicConnectionSentPacketKey? latestTrackedPacketKey;
    private QuicConnectionSentPacket pendingSendPacket;
    private IQuicBufferCopyOperationObserver? bufferCopyOperationObserver;
    private ulong pendingSendReservationSequence;
    private ulong nextPendingSendReservationSequence;
    private bool hasPendingSendReservation;

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

    internal int SentPacketStorageCapacity => sentPackets.EnsureCapacity(0);

    internal int GetOutstandingSentStreamPacketCount(ulong streamId)
        => outstandingSentStreamPacketIndex.GetCount(streamId);

    internal QuicRetentionSnapshot CaptureSentPacketRetentionSnapshot(ulong nowMicros)
    {
        return new QuicRetentionSnapshot(
            retainedSentPacketBufferCount,
            retainedSentPacketByteCount,
            QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                nowMicros,
                oldestSentPacketAtMicros));
    }

    internal QuicRetentionSnapshot CaptureSentPacketRetentionSnapshot(
        ulong nowMicros,
        out QuicSentPacketStorageSnapshot storageSnapshot)
    {
        Span<int> retainedPacketCounts = stackalloc int[3];
        Span<ulong> minimumPacketNumbers = stackalloc ulong[3];
        Span<ulong> maximumPacketNumbers = stackalloc ulong[3];

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            AddPacketNumberToStorageSnapshot(
                entry.Key,
                retainedPacketCounts,
                minimumPacketNumbers,
                maximumPacketNumbers);
        }

        storageSnapshot = CreateSentPacketStorageSnapshot(
            retainedPacketCounts,
            minimumPacketNumbers,
            maximumPacketNumbers);

        return new QuicRetentionSnapshot(
            retainedSentPacketBufferCount,
            retainedSentPacketByteCount,
            QuicRetentionSnapshot.GetOldestAgeMilliseconds(
                nowMicros,
                oldestSentPacketAtMicros));
    }

    internal QuicSentPacketStorageSnapshot CaptureSentPacketStorageSnapshot()
    {
        Span<int> retainedPacketCounts = stackalloc int[3];
        Span<ulong> minimumPacketNumbers = stackalloc ulong[3];
        Span<ulong> maximumPacketNumbers = stackalloc ulong[3];

        foreach (QuicConnectionSentPacketKey key in sentPackets.Keys)
        {
            AddPacketNumberToStorageSnapshot(
                key,
                retainedPacketCounts,
                minimumPacketNumbers,
                maximumPacketNumbers);
        }

        return CreateSentPacketStorageSnapshot(
            retainedPacketCounts,
            minimumPacketNumbers,
            maximumPacketNumbers);
    }

    private QuicSentPacketStorageSnapshot CreateSentPacketStorageSnapshot(
        ReadOnlySpan<int> retainedPacketCounts,
        ReadOnlySpan<ulong> minimumPacketNumbers,
        ReadOnlySpan<ulong> maximumPacketNumbers)
    {
        int initialIndex = (int)QuicPacketNumberSpace.Initial;
        int handshakeIndex = (int)QuicPacketNumberSpace.Handshake;
        int applicationDataIndex = (int)QuicPacketNumberSpace.ApplicationData;
        return new QuicSentPacketStorageSnapshot(
            sentPackets.Count,
            SentPacketStorageCapacity,
            CreatePacketNumberSpaceStorageSnapshot(
                retainedPacketCounts[initialIndex],
                minimumPacketNumbers[initialIndex],
                maximumPacketNumbers[initialIndex]),
            CreatePacketNumberSpaceStorageSnapshot(
                retainedPacketCounts[handshakeIndex],
                minimumPacketNumbers[handshakeIndex],
                maximumPacketNumbers[handshakeIndex]),
            CreatePacketNumberSpaceStorageSnapshot(
                retainedPacketCounts[applicationDataIndex],
                minimumPacketNumbers[applicationDataIndex],
                maximumPacketNumbers[applicationDataIndex]));
    }

    private static void AddPacketNumberToStorageSnapshot(
        QuicConnectionSentPacketKey key,
        Span<int> retainedPacketCounts,
        Span<ulong> minimumPacketNumbers,
        Span<ulong> maximumPacketNumbers)
    {
        int packetNumberSpaceIndex = GetPacketNumberSpaceIndex(key.PacketNumberSpace);
        ulong packetNumber = key.PacketNumber;
        if (retainedPacketCounts[packetNumberSpaceIndex] == 0)
        {
            minimumPacketNumbers[packetNumberSpaceIndex] = packetNumber;
            maximumPacketNumbers[packetNumberSpaceIndex] = packetNumber;
        }
        else
        {
            minimumPacketNumbers[packetNumberSpaceIndex] = Math.Min(
                minimumPacketNumbers[packetNumberSpaceIndex],
                packetNumber);
            maximumPacketNumbers[packetNumberSpaceIndex] = Math.Max(
                maximumPacketNumbers[packetNumberSpaceIndex],
                packetNumber);
        }

        retainedPacketCounts[packetNumberSpaceIndex]++;
    }

    private static int GetPacketNumberSpaceIndex(QuicPacketNumberSpace packetNumberSpace)
        => packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => (int)QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.Handshake => (int)QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.ApplicationData => (int)QuicPacketNumberSpace.ApplicationData,
            _ => throw new ArgumentOutOfRangeException(nameof(packetNumberSpace)),
        };

    private static QuicSentPacketNumberSpaceStorageSnapshot CreatePacketNumberSpaceStorageSnapshot(
        int retainedPacketCount,
        ulong minimumPacketNumber,
        ulong maximumPacketNumber)
    {
        ulong packetNumberSpan = retainedPacketCount == 0
            ? 0
            : maximumPacketNumber - minimumPacketNumber + 1;
        return new QuicSentPacketNumberSpaceStorageSnapshot(retainedPacketCount, packetNumberSpan);
    }

    internal QuicRetentionSnapshot CaptureRetransmissionRetentionSnapshot(ulong nowMicros)
        => retransmissionQueue.CaptureRetentionSnapshot(nowMicros);

    internal void ConfigureBufferCopyOperationObserver(
        IQuicBufferCopyOperationObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        if (Interlocked.CompareExchange(
                ref bufferCopyOperationObserver,
                observer,
                comparand: null) is not null)
        {
            throw new InvalidOperationException(
                "The send runtime buffer-copy observer has already been configured.");
        }

        retransmissionQueue.ConfigureBufferCopyOperationObserver(observer);
    }

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
        ReleasePendingSendReservation();
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

    internal bool TryReserveSentPacket(
        QuicConnectionSentPacket packet,
        out QuicConnectionPendingSendReservation reservation)
    {
        reservation = default;
        if (hasPendingSendReservation)
        {
            return false;
        }

        ValidateSentPacket(packet);
        packet = NormalizePacketProtectionLevel(packet);
        ValidateCryptoMetadata(packet);
        if (!flowController.TryReservePacketSend(
            packet.PacketNumberSpace,
            packet.PayloadBytes,
            packet.AckOnlyPacket,
            packet.ProbePacket))
        {
            return false;
        }

        nextPendingSendReservationSequence++;
        if (nextPendingSendReservationSequence == 0)
        {
            nextPendingSendReservationSequence++;
        }

        pendingSendPacket = packet;
        pendingSendReservationSequence = nextPendingSendReservationSequence;
        hasPendingSendReservation = true;
        reservation = new QuicConnectionPendingSendReservation(pendingSendReservationSequence);
        return true;
    }

    internal bool TryCommitReservedSentPacket(
        QuicConnectionPendingSendReservation reservation,
        ulong sentAtMicros)
    {
        if (!TryTakePendingSendReservation(reservation, out QuicConnectionSentPacket packet))
        {
            return false;
        }

        packet = packet with { SentAtMicros = sentAtMicros };
        if (!TrackSentPacketCore(packet, reservedSend: true))
        {
            ReleasePacketOwners(
                packet,
                QuicBufferReleaseReason.Failed);
            return false;
        }

        return true;
    }

    internal bool TryReleaseReservedSentPacket(QuicConnectionPendingSendReservation reservation)
    {
        if (!TryTakePendingSendReservation(reservation, out QuicConnectionSentPacket packet))
        {
            return false;
        }

        bool released = flowController.TryReleasePacketSendReservation(
            packet.PayloadBytes,
            packet.AckOnlyPacket);
        ReleasePacketOwners(
            packet,
            QuicBufferReleaseReason.Canceled);
        return released;
    }

    private bool TryTakePendingSendReservation(
        QuicConnectionPendingSendReservation reservation,
        out QuicConnectionSentPacket packet)
    {
        if (!hasPendingSendReservation
            || reservation.Sequence == 0
            || reservation.Sequence != pendingSendReservationSequence)
        {
            packet = default;
            return false;
        }

        packet = pendingSendPacket;
        pendingSendPacket = default;
        pendingSendReservationSequence = 0;
        hasPendingSendReservation = false;
        return true;
    }

    private void ReleasePendingSendReservation(
        QuicBufferReleaseReason releaseReason =
            QuicBufferReleaseReason.Canceled)
    {
        if (!hasPendingSendReservation)
        {
            return;
        }

        QuicConnectionSentPacket packet = pendingSendPacket;
        pendingSendPacket = default;
        pendingSendReservationSequence = 0;
        hasPendingSendReservation = false;
        _ = flowController.TryReleasePacketSendReservation(
            packet.PayloadBytes,
            packet.AckOnlyPacket);
        ReleasePacketOwners(
            packet,
            releaseReason);
    }

    public void TrackSentPacket(QuicConnectionSentPacket packet)
    {
        _ = TrackSentPacketCore(packet, reservedSend: false);
    }

    private bool TrackSentPacketCore(QuicConnectionSentPacket packet, bool reservedSend)
    {
        ValidateSentPacket(packet);
        packet = NormalizePacketProtectionLevel(packet);
        ValidateCryptoMetadata(packet);
        if (reservedSend
            && !flowController.TryRecordReservedPacketSent(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros,
                packet.AckEliciting,
                packet.AckOnlyPacket,
                packet.ProbePacket,
                packet.PacketProtectionLevel,
                packet.OneRttKeyPhase,
                retainPacketState: false))
        {
            return false;
        }

        ecnValidationState.RecordPacketSent(packet.PacketNumberSpace, CurrentEcnMarking);
        QuicConnectionSentPacketKey key = new(packet.PacketNumberSpace, packet.PacketNumber);
        if (TryRemoveSentPacket(key, out QuicConnectionSentPacket replacedPacket))
        {
            ReleasePacketOwners(
                replacedPacket,
                QuicBufferReleaseReason.Replaced);
        }

        if (!packet.AckOnlyPacket)
        {
            sentPackets[key] = packet;
            RecordSentPacketAddition(packet);
            outstandingSentStreamPacketIndex.Add(packet);
            latestTrackedPacketKey = key;
        }
        if (!reservedSend)
        {
            flowController.RecordPacketSent(
                packet.PacketNumberSpace,
                packet.PacketNumber,
                packet.PayloadBytes,
                packet.SentAtMicros,
                packet.AckEliciting,
                packet.AckOnlyPacket,
                packet.ProbePacket,
                packet.PacketProtectionLevel,
                packet.OneRttKeyPhase,
                retainPacketState: false);
        }

        if (packet.AckOnlyPacket)
        {
            ReleasePacketOwners(
                packet,
                QuicBufferReleaseReason.Completed);
            return true;
        }

        if (packet.AckEliciting && !packet.ProbePacket)
        {
            ProbeTimeoutCount = QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ProbeTimeoutCount,
                ackElicitingPacketSent: true);
            LossDetectionDeadlineMicros = null;
        }

        return true;
    }

    internal bool TryDetachLatestRebuildablePacketBytes(
        ReadOnlyMemory<byte> packetBytes,
        out byte[]? packetBytesOwner)
        => TryDetachLatestRebuildablePacketBytes(
            packetBytes,
            out packetBytesOwner,
            out _);

    internal bool TryDetachLatestRebuildablePacketBytes(
        ReadOnlyMemory<byte> packetBytes,
        out byte[]? packetBytesOwner,
        out QuicBufferCopyLifetimeToken packetBytesLifetimeToken)
    {
        packetBytesOwner = null;
        packetBytesLifetimeToken = default;
        if (!latestTrackedPacketKey.HasValue
            || !sentPackets.TryGetValue(latestTrackedPacketKey.Value, out QuicConnectionSentPacket packet)
            || packet.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
            || !packet.Retransmittable
            || packet.PlaintextPayload.IsEmpty
            || packet.PacketBytesOwner is null
            || ReferenceEquals(packet.PlaintextPayloadOwner, packet.PacketBytesOwner)
            || !packet.PacketBytes.Equals(packetBytes))
        {
            return false;
        }

        packetBytesOwner = packet.PacketBytesOwner;
        packetBytesLifetimeToken = packet.PacketBytesLifetimeToken;
        sentPackets[latestTrackedPacketKey.Value] = packet with
        {
            PacketBytes = default,
            PacketBytesOwner = null,
            PacketBytesLifetimeToken = default,
        };
        RecordSentPacketOwnerRemoval(
            plaintextPayloadOwner: null,
            packet.PacketBytesOwner);
        return true;
    }

    internal bool TryClearLatestRebuildablePacketBytes(ReadOnlyMemory<byte> packetBytes)
    {
        if (!latestTrackedPacketKey.HasValue
            || !sentPackets.TryGetValue(latestTrackedPacketKey.Value, out QuicConnectionSentPacket packet)
            || packet.PacketNumberSpace != QuicPacketNumberSpace.ApplicationData
            || !packet.Retransmittable
            || packet.PlaintextPayload.IsEmpty
            || packet.PacketBytesOwner is not null
            || !packet.PacketBytes.Equals(packetBytes))
        {
            return false;
        }

        sentPackets[latestTrackedPacketKey.Value] = packet with { PacketBytes = default };
        return true;
    }

    public bool TryAcknowledgePacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool handshakeConfirmed = false)
    {
        QuicConnectionSentPacketKey key = new(packetNumberSpace, packetNumber);
        bool removedSentPacket = TryRemoveSentPacket(key, out QuicConnectionSentPacket acknowledgedPacket);
        bool removedPendingRetransmission = retransmissionQueue.TryRemovePendingRetransmission(key);
        if (!removedSentPacket && !removedPendingRetransmission)
        {
            return false;
        }

        if (removedSentPacket)
        {
            _ = TrySuppressResetStreamRetransmissionForAcknowledgedStreamData(acknowledgedPacket.PlaintextPayload.Span);
            ReleasePacketOwners(
                acknowledgedPacket,
                QuicBufferReleaseReason.Completed);
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
        bool updated = flowController.TryDiscardAckGenerationState(packetNumberSpace, discardAckGenerationState);

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Key.PacketNumberSpace == packetNumberSpace)
            {
                updated = flowController.TryDiscardExternallyRetainedPacket(entry.Value) || updated;
                (removedKeys ??= []).Add(entry.Key);
            }
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (TryRemoveSentPacket(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(
                        removedPacket,
                        QuicBufferReleaseReason.Terminal);
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
        try
        {
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
            for (int index = 0; index < retainedRetransmissions.Count; index++)
            {
                QuicConnectionRetransmissionPlan retransmission = retainedRetransmissions[index];
                retransmissionQueue.QueueRetransmission(retransmission);
                retainedRetransmissions[index] = retransmission with
                {
                    PlaintextPayloadOwner = null,
                    PacketBytesOwner = null,
                    PlaintextPayloadLifetimeToken = default,
                    PacketBytesLifetimeToken = default,
                };
            }

            return true;
        }
        finally
        {
            if (retainedRetransmissions is not null)
            {
                foreach (QuicConnectionRetransmissionPlan retransmission in retainedRetransmissions)
                {
                    ReleaseRetransmissionPlanResources(
                        retransmission,
                        bufferCopyOperationObserver,
                        QuicBufferReleaseReason.Failed);
                }
            }
        }
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
        bool updated = false;

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Value.PacketProtectionLevel != packetProtectionLevel)
            {
                continue;
            }

            updated = flowController.TryDiscardExternallyRetainedPacket(entry.Value) || updated;
            (removedKeys ??= []).Add(entry.Key);
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (TryRemoveSentPacket(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(
                        removedPacket,
                        QuicBufferReleaseReason.Terminal);
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
        bool updated = false;

        List<QuicConnectionSentPacketKey>? removedKeys = null;
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sentPackets)
        {
            if (entry.Value.PacketProtectionLevel != QuicTlsEncryptionLevel.OneRtt
                || entry.Value.OneRttKeyPhase != keyPhase)
            {
                continue;
            }

            updated = flowController.TryDiscardExternallyRetainedPacket(entry.Value) || updated;
            (removedKeys ??= []).Add(entry.Key);
        }

        if (removedKeys is not null)
        {
            foreach (QuicConnectionSentPacketKey key in removedKeys)
            {
                if (TryRemoveSentPacket(key, out QuicConnectionSentPacket removedPacket))
                {
                    ReleasePacketOwners(
                        removedPacket,
                        QuicBufferReleaseReason.Terminal);
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
        if (!TryRemoveSentPacket(key, out QuicConnectionSentPacket packet))
        {
            return false;
        }

        _ = flowController.TryRegisterExternallyRetainedLoss(packet);

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
                packet.PacketBytesOwner,
                packet.PlaintextPayloadLifetimeToken,
                packet.PacketBytesLifetimeToken));
        }
        else
        {
            ReleasePacketOwners(
                packet,
                QuicBufferReleaseReason.Failed);
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
        return GetOutstandingSentStreamPacketCount(streamId) > 0
            || retransmissionQueue.ContainsStreamDataForStream(streamId);
    }

    private bool TryRemoveSentPacket(
        QuicConnectionSentPacketKey key,
        out QuicConnectionSentPacket packet)
    {
        if (!sentPackets.Remove(key, out packet))
        {
            return false;
        }

        bool removedOldest = RecordSentPacketRemoval(packet);
        outstandingSentStreamPacketIndex.Remove(packet);
        RefreshOldestSentPacketAtMicros(removedOldest);
        return true;
    }

    private void RecordSentPacketAddition(QuicConnectionSentPacket packet)
    {
        QuicRetentionSnapshot.AddOwners(
            packet.PlaintextPayloadOwner,
            packet.PacketBytesOwner,
            ref retainedSentPacketBufferCount,
            ref retainedSentPacketByteCount);
        if (!oldestSentPacketAtMicros.HasValue
            || packet.SentAtMicros < oldestSentPacketAtMicros.Value)
        {
            oldestSentPacketAtMicros = packet.SentAtMicros;
        }
    }

    private bool RecordSentPacketRemoval(QuicConnectionSentPacket packet)
    {
        RecordSentPacketOwnerRemoval(
            packet.PlaintextPayloadOwner,
            packet.PacketBytesOwner);
        return oldestSentPacketAtMicros == packet.SentAtMicros;
    }

    private void RecordSentPacketOwnerRemoval(
        byte[]? plaintextPayloadOwner,
        byte[]? packetBytesOwner)
    {
        if (plaintextPayloadOwner is not null)
        {
            retainedSentPacketBufferCount--;
            retainedSentPacketByteCount -= plaintextPayloadOwner.Length;
        }

        if (packetBytesOwner is not null
            && !ReferenceEquals(plaintextPayloadOwner, packetBytesOwner))
        {
            retainedSentPacketBufferCount--;
            retainedSentPacketByteCount -= packetBytesOwner.Length;
        }
    }

    private void RefreshOldestSentPacketAtMicros(bool removedOldest)
    {
        if (!removedOldest)
        {
            return;
        }

        oldestSentPacketAtMicros = null;
        foreach (QuicConnectionSentPacket retained in sentPackets.Values)
        {
            if (!oldestSentPacketAtMicros.HasValue
                || retained.SentAtMicros < oldestSentPacketAtMicros.Value)
            {
                oldestSentPacketAtMicros = retained.SentAtMicros;
            }
        }
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

    internal bool ReleaseAllOwnedPacketResources(
        QuicBufferReleaseReason releaseReason)
    {
        bool updated = hasPendingSendReservation;
        ReleasePendingSendReservation(releaseReason);

        if (sentPackets.Count != 0)
        {
            QuicConnectionSentPacketKey[] retainedKeys =
                [.. sentPackets.Keys];
            foreach (QuicConnectionSentPacketKey key in retainedKeys)
            {
                if (!TryRemoveSentPacket(
                    key,
                    out QuicConnectionSentPacket retainedPacket))
                {
                    continue;
                }

                _ = flowController.TryDiscardExternallyRetainedPacket(
                    retainedPacket);
                ReleasePacketOwners(retainedPacket, releaseReason);
                updated = true;
            }
        }

        updated |= retransmissionQueue.Clear(releaseReason);
        LossDetectionDeadlineMicros = null;
        latestTrackedPacketKey = null;
        return updated;
    }

    internal static void ReleaseRetransmissionPlanResources(
        QuicConnectionRetransmissionPlan retransmission,
        IQuicBufferCopyOperationObserver? observer = null,
        QuicBufferReleaseReason reason =
            QuicBufferReleaseReason.Terminal)
    {
        ReleasePacketOwners(
            retransmission.PlaintextPayloadOwner,
            retransmission.PacketBytesOwner,
            retransmission.PlaintextPayloadLifetimeToken,
            retransmission.PacketBytesLifetimeToken,
            observer,
            reason);
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

    private static void ValidateSentPacket(QuicConnectionSentPacket packet)
    {
        if (packet.ProbePacket && (packet.AckOnlyPacket || !packet.AckEliciting))
        {
            throw new ArgumentException("Probe packets must be ack-eliciting packets.", nameof(packet));
        }
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

    private void ReleasePacketOwners(
        QuicConnectionSentPacket packet,
        QuicBufferReleaseReason reason)
    {
        ReleasePacketOwners(
            packet.PlaintextPayloadOwner,
            packet.PacketBytesOwner,
            packet.PlaintextPayloadLifetimeToken,
            packet.PacketBytesLifetimeToken,
            bufferCopyOperationObserver,
            reason);
    }

    private static void ReleasePacketOwners(
        byte[]? plaintextPayloadOwner,
        byte[]? packetBytesOwner,
        QuicBufferCopyLifetimeToken plaintextPayloadLifetimeToken,
        QuicBufferCopyLifetimeToken packetBytesLifetimeToken,
        IQuicBufferCopyOperationObserver? observer,
        QuicBufferReleaseReason reason)
    {
        if (plaintextPayloadOwner is not null)
        {
            QuicBufferPool.ReturnBytes(plaintextPayloadOwner);
            if (observer is not null
                && !plaintextPayloadLifetimeToken.IsEmpty)
            {
                try
                {
                    observer.ObserveBufferRelease(
                        in plaintextPayloadLifetimeToken,
                        reason,
                        plaintextPayloadOwner.Length);
                }
                catch (Exception)
                {
                    // Release evidence follows the authoritative pool return
                    // and cannot change recovery ownership or progress.
                }
            }
        }

        if (packetBytesOwner is not null
            && !ReferenceEquals(plaintextPayloadOwner, packetBytesOwner))
        {
            QuicBufferPool.ReturnBytes(packetBytesOwner);
            if (observer is not null
                && !packetBytesLifetimeToken.IsEmpty)
            {
                try
                {
                    observer.ObserveBufferRelease(
                        in packetBytesLifetimeToken,
                        reason,
                        packetBytesOwner.Length);
                }
                catch (Exception)
                {
                    // Release evidence follows the authoritative pool return
                    // and cannot change recovery ownership or progress.
                }
            }
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
