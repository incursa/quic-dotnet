// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicConnectionEventKind
{
    PacketReceived = 0,
    TimerExpired = 1,
    PeerHandshakeTranscriptCompleted = 2,
    LocalCloseRequested = 3,
    ConnectionCloseFrameReceived = 4,
    AcceptedStatelessReset = 5,
    PathValidationSucceeded = 6,
    PathValidationFailed = 7,
    StreamAction = 8,
    TransportParametersCommitted = 9,
    ConnectionIdIssued = 10,
    ConnectionIdRetired = 11,
    ConnectionIdAcknowledged = 12,
    TlsStateUpdated = 13,
    CryptoFrameReceived = 14,
    HandshakeBootstrapRequested = 15,
    RetryReceived = 16,
    VersionNegotiationReceived = 17,
    FlowControlCreditUpdated = 18,
    IcmpMaximumDatagramSizeReduction = 19,
    DatagramSendRequested = 20,
}

internal enum QuicConnectionEffectKind
{
    SendDatagram = 0,
    ArmTimer = 1,
    CancelTimer = 2,
    PromoteActivePath = 3,
    UpdateEndpointBindings = 4,
    RegisterStatelessResetToken = 5,
    RetireStatelessResetToken = 6,
    NotifyStreamsOfTerminalState = 7,
    DiscardConnectionState = 8,
    EmitDiagnostic = 9,
    RegisterConnectionIdRoute = 10,
    RetireConnectionIdRoute = 11,
    UpdateMaxUdpPayloadSize = 12,
    DeliverDatagram = 13,
}

internal enum QuicConnectionStreamActionKind
{
    Open = 0,
    Write = 1,
    Finish = 2,
    StopSending = 3,
    Reset = 4,
    Abort = 5,
    ReleaseCapacity = 6,
}

internal abstract record QuicConnectionEvent(QuicConnectionEventKind Kind, long ObservedAtTicks);

internal sealed record QuicConnectionPacketReceivedEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> Datagram,
    ulong? RoutedLocallyIssuedConnectionId = null,
    QuicEcnCounts? EcnCounts = null,
    byte[]? OwnedDatagramBuffer = null,
    QuicReceiveBufferOwnership OwnedDatagramBufferOwnership = default)
    : QuicConnectionEvent(QuicConnectionEventKind.PacketReceived, ObservedAtTicks)
{
    private byte[]? ownedDatagramBuffer = OwnedDatagramBuffer;

    internal QuicConnectionPacketReceivedEvent WithBorrowedDatagramSlice(ReadOnlyMemory<byte> datagram)
    {
        return new QuicConnectionPacketReceivedEvent(
            ObservedAtTicks,
            PathIdentity,
            datagram,
            RoutedLocallyIssuedConnectionId,
            EcnCounts);
    }

    internal void ReleaseOwnedDatagramBuffer()
    {
        byte[]? buffer = Interlocked.Exchange(ref ownedDatagramBuffer, null);
        if (buffer is not null)
        {
            if (OwnedDatagramBufferOwnership.Pool is { } pool)
            {
                pool.Return(buffer, OwnedDatagramBufferOwnership);
            }
            else
            {
                QuicBufferPool.ReturnBytes(buffer);
            }
        }
    }
}

internal sealed record QuicConnectionTimerExpiredEvent(
    long ObservedAtTicks,
    QuicConnectionTimerKind TimerKind,
    ulong Generation)
    : QuicConnectionEvent(QuicConnectionEventKind.TimerExpired, ObservedAtTicks);

internal sealed record QuicConnectionPeerHandshakeTranscriptCompletedEvent(long ObservedAtTicks)
    : QuicConnectionEvent(QuicConnectionEventKind.PeerHandshakeTranscriptCompleted, ObservedAtTicks);

internal sealed record QuicConnectionHandshakeBootstrapRequestedEvent(
    long ObservedAtTicks,
    QuicTransportParameters? LocalTransportParameters,
    ReadOnlyMemory<byte> InitialAddressValidationToken = default)
    : QuicConnectionEvent(QuicConnectionEventKind.HandshakeBootstrapRequested, ObservedAtTicks);

internal sealed record QuicConnectionRetryReceivedEvent(
    long ObservedAtTicks,
    ReadOnlyMemory<byte> RetrySourceConnectionId,
    ReadOnlyMemory<byte> RetryToken,
    ReadOnlyMemory<byte> Datagram = default)
    : QuicConnectionEvent(QuicConnectionEventKind.RetryReceived, ObservedAtTicks);

internal sealed record QuicConnectionVersionNegotiationReceivedEvent(
    long ObservedAtTicks,
    ReadOnlyMemory<byte> Datagram)
    : QuicConnectionEvent(QuicConnectionEventKind.VersionNegotiationReceived, ObservedAtTicks);

internal sealed record QuicConnectionIcmpMaximumDatagramSizeReductionEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> QuotedPacket,
    ulong MaximumDatagramSizeBytes)
    : QuicConnectionEvent(QuicConnectionEventKind.IcmpMaximumDatagramSizeReduction, ObservedAtTicks);

internal sealed record QuicConnectionFlowControlCreditUpdatedEvent(
    long ObservedAtTicks,
    QuicMaxDataFrame? MaxDataFrame = null,
    QuicMaxStreamDataFrame? MaxStreamDataFrame = null)
    : QuicConnectionEvent(QuicConnectionEventKind.FlowControlCreditUpdated, ObservedAtTicks);

internal sealed record QuicConnectionLocalCloseRequestedEvent(
    long ObservedAtTicks,
    QuicConnectionCloseMetadata Close)
    : QuicConnectionEvent(QuicConnectionEventKind.LocalCloseRequested, ObservedAtTicks);

internal sealed record QuicConnectionConnectionCloseFrameReceivedEvent(
    long ObservedAtTicks,
    QuicConnectionCloseMetadata Close)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionCloseFrameReceived, ObservedAtTicks);

internal sealed record QuicConnectionAcceptedStatelessResetEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.AcceptedStatelessReset, ObservedAtTicks);

internal sealed record QuicConnectionPathValidationSucceededEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity)
    : QuicConnectionEvent(QuicConnectionEventKind.PathValidationSucceeded, ObservedAtTicks);

internal sealed record QuicConnectionPathValidationFailedEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity,
    bool IsAbandoned)
    : QuicConnectionEvent(QuicConnectionEventKind.PathValidationFailed, ObservedAtTicks);

internal sealed record QuicConnectionStreamActionEvent(
    long ObservedAtTicks,
    long RequestId,
    QuicConnectionStreamActionKind ActionKind,
    QuicStreamType? StreamType = null,
    ulong? StreamId = null,
    ReadOnlyMemory<byte> StreamData = default,
    ulong? ApplicationErrorCode = null)
    : QuicConnectionEvent(QuicConnectionEventKind.StreamAction, ObservedAtTicks);

internal sealed record QuicConnectionDatagramSendRequestedEvent(
    long ObservedAtTicks,
    long RequestId,
    ReadOnlyMemory<byte> DatagramData)
    : QuicConnectionEvent(QuicConnectionEventKind.DatagramSendRequested, ObservedAtTicks);

internal sealed record QuicConnectionTransportParametersCommittedEvent(
    long ObservedAtTicks,
    QuicConnectionTransportState TransportFlags,
    ulong? LocalMaxIdleTimeoutMicros = null,
    ulong? PeerMaxIdleTimeoutMicros = null,
    ulong? CurrentProbeTimeoutMicros = null)
    : QuicConnectionEvent(QuicConnectionEventKind.TransportParametersCommitted, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdIssuedEvent(
    long ObservedAtTicks,
    ulong ConnectionId,
    ReadOnlyMemory<byte> StatelessResetToken,
    ReadOnlyMemory<byte> ConnectionIdBytes = default)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdIssued, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdRetiredEvent(
    long ObservedAtTicks,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdRetired, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdAcknowledgedEvent(
    long ObservedAtTicks,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdAcknowledged, ObservedAtTicks);

internal sealed record QuicConnectionTlsStateUpdatedEvent(
    long ObservedAtTicks,
    QuicTlsStateUpdate Update)
    : QuicConnectionEvent(QuicConnectionEventKind.TlsStateUpdated, ObservedAtTicks);

internal sealed record QuicConnectionCryptoFrameReceivedEvent(
    long ObservedAtTicks,
    QuicTlsEncryptionLevel EncryptionLevel,
    ulong Offset,
    ReadOnlyMemory<byte> CryptoData)
    : QuicConnectionEvent(QuicConnectionEventKind.CryptoFrameReceived, ObservedAtTicks);

internal abstract record QuicConnectionEffect(QuicConnectionEffectKind Kind);

internal sealed record QuicConnectionSendDatagramEffect(
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> Datagram,
    QuicEcnMarking EcnMarking = QuicEcnMarking.NotEct)
    : QuicConnectionEffect(QuicConnectionEffectKind.SendDatagram);

internal sealed record QuicConnectionDeliverDatagramEffect(
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> Datagram,
    byte FrameType)
    : QuicConnectionEffect(QuicConnectionEffectKind.DeliverDatagram);

internal sealed record QuicConnectionArmTimerEffect(
    QuicConnectionTimerKind TimerKind,
    ulong Generation,
    QuicConnectionTimerPriority Priority)
    : QuicConnectionEffect(QuicConnectionEffectKind.ArmTimer);

internal sealed record QuicConnectionCancelTimerEffect(
    QuicConnectionTimerKind TimerKind,
    ulong Generation)
    : QuicConnectionEffect(QuicConnectionEffectKind.CancelTimer);

internal sealed record QuicConnectionPromoteActivePathEffect(
    QuicConnectionPathIdentity PathIdentity,
    bool RestoreSavedState = false)
    : QuicConnectionEffect(QuicConnectionEffectKind.PromoteActivePath);

internal sealed record QuicConnectionUpdateEndpointBindingsEffect(
    QuicConnectionPathIdentity PathIdentity)
    : QuicConnectionEffect(QuicConnectionEffectKind.UpdateEndpointBindings);

internal sealed record QuicConnectionRegisterStatelessResetTokenEffect(
    ulong ConnectionId,
    ReadOnlyMemory<byte> Token)
    : QuicConnectionEffect(QuicConnectionEffectKind.RegisterStatelessResetToken);

internal sealed record QuicConnectionRetireStatelessResetTokenEffect(ulong ConnectionId)
    : QuicConnectionEffect(QuicConnectionEffectKind.RetireStatelessResetToken);

internal sealed record QuicConnectionRegisterConnectionIdRouteEffect(
    ulong ConnectionId,
    ReadOnlyMemory<byte> ConnectionIdBytes)
    : QuicConnectionEffect(QuicConnectionEffectKind.RegisterConnectionIdRoute);

internal sealed record QuicConnectionRetireConnectionIdRouteEffect(
    ulong ConnectionId,
    ReadOnlyMemory<byte> ConnectionIdBytes)
    : QuicConnectionEffect(QuicConnectionEffectKind.RetireConnectionIdRoute);

internal sealed record QuicConnectionUpdateMaxUdpPayloadSizeEffect(ulong MaxUdpPayloadSize)
    : QuicConnectionEffect(QuicConnectionEffectKind.UpdateMaxUdpPayloadSize);

internal sealed record QuicConnectionNotifyStreamsOfTerminalStateEffect(
    QuicConnectionTerminalState TerminalState)
    : QuicConnectionEffect(QuicConnectionEffectKind.NotifyStreamsOfTerminalState);

internal sealed record QuicConnectionDiscardConnectionStateEffect(
    QuicConnectionTerminalState? TerminalState = null)
    : QuicConnectionEffect(QuicConnectionEffectKind.DiscardConnectionState);

internal sealed record QuicConnectionEmitDiagnosticEffect(QuicDiagnosticEvent Diagnostic)
    : QuicConnectionEffect(QuicConnectionEffectKind.EmitDiagnostic);

internal struct QuicConnectionEffectAccumulator
{
    private QuicConnectionEffect? singleEffect;
    private List<QuicConnectionEffect>? effectList;

    private QuicConnectionEffectAccumulator(List<QuicConnectionEffect> effectList)
    {
        singleEffect = null;
        this.effectList = effectList;
    }

    internal static QuicConnectionEffectAccumulator FromList(List<QuicConnectionEffect> effectList)
    {
        return new QuicConnectionEffectAccumulator(effectList);
    }

    internal QuicConnectionEffect? SingleEffect => effectList is null ? singleEffect : null;

    internal List<QuicConnectionEffect>? EffectList => effectList;

    internal bool HasEffects => singleEffect is not null || effectList is { Count: > 0 };

    internal int Count => effectList?.Count ?? (singleEffect is null ? 0 : 1);

    internal void Add(QuicConnectionEffect effect)
    {
        if (effectList is not null)
        {
            effectList.Add(effect);
            return;
        }

        if (singleEffect is null)
        {
            singleEffect = effect;
            return;
        }

        effectList = new List<QuicConnectionEffect>(capacity: 4)
        {
            singleEffect,
            effect,
        };
        singleEffect = null;
    }

    internal QuicConnectionEffect[] ToArray()
    {
        if (effectList is not null)
        {
            return effectList.ToArray();
        }

        return singleEffect is null
            ? Array.Empty<QuicConnectionEffect>()
            : [singleEffect];
    }

    internal List<QuicConnectionEffect>? ToList()
    {
        if (effectList is not null)
        {
            return effectList;
        }

        if (singleEffect is null)
        {
            return null;
        }

        return [singleEffect];
    }
}

internal readonly struct QuicConnectionTransitionResult
{
    private readonly QuicConnectionEffect[]? effects;
    private readonly QuicConnectionEffectAccumulator effectAccumulator;

    public QuicConnectionTransitionResult(
        ulong Sequence,
        long ObservedAtTicks,
        QuicConnectionEventKind EventKind,
        QuicConnectionPhase PreviousPhase,
        QuicConnectionPhase CurrentPhase,
        bool StateChanged,
        QuicConnectionEffect[] Effects)
    {
        this.Sequence = Sequence;
        this.ObservedAtTicks = ObservedAtTicks;
        this.EventKind = EventKind;
        this.PreviousPhase = PreviousPhase;
        this.CurrentPhase = CurrentPhase;
        this.StateChanged = StateChanged;
        this.effects = Effects ?? Array.Empty<QuicConnectionEffect>();
        effectAccumulator = default;
    }

    internal QuicConnectionTransitionResult(
        ulong Sequence,
        long ObservedAtTicks,
        QuicConnectionEventKind EventKind,
        QuicConnectionPhase PreviousPhase,
        QuicConnectionPhase CurrentPhase,
        bool StateChanged,
        QuicConnectionEffectAccumulator EffectAccumulator)
    {
        this.Sequence = Sequence;
        this.ObservedAtTicks = ObservedAtTicks;
        this.EventKind = EventKind;
        this.PreviousPhase = PreviousPhase;
        this.CurrentPhase = CurrentPhase;
        this.StateChanged = StateChanged;
        effects = null;
        effectAccumulator = EffectAccumulator;
    }

    public ulong Sequence { get; }

    public long ObservedAtTicks { get; }

    public QuicConnectionEventKind EventKind { get; }

    public QuicConnectionPhase PreviousPhase { get; }

    public QuicConnectionPhase CurrentPhase { get; }

    public bool StateChanged { get; }

    internal QuicConnectionEffect? SingleEffect => effects is null ? effectAccumulator.SingleEffect : null;

    internal List<QuicConnectionEffect>? EffectList => effects is null ? effectAccumulator.EffectList : null;

    public QuicConnectionEffect[] Effects => effects ?? effectAccumulator.ToArray();

    public bool HasEffects => effects is { Length: > 0 } || effectAccumulator.HasEffects;
}
