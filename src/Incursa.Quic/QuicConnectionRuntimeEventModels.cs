namespace Incursa.Quic;

internal enum QuicConnectionEventKind
{
    PacketReceived = 0,
    TimerExpired = 1,
    HandshakeConfirmed = 2,
    LocalCloseRequested = 3,
    ConnectionCloseFrameReceived = 4,
    StatelessResetMatched = 5,
    PathValidationSucceeded = 6,
    PathValidationFailed = 7,
    StreamAction = 8,
    TransportParametersCommitted = 9,
    ConnectionIdIssued = 10,
    ConnectionIdRetired = 11,
    ConnectionIdAcknowledged = 12,
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
}

internal enum QuicConnectionStreamActionKind
{
    Open = 0,
    Write = 1,
    Finish = 2,
    StopSending = 3,
    Reset = 4,
    Abort = 5,
}

internal abstract record QuicConnectionEvent(QuicConnectionEventKind Kind, long ObservedAtTicks);

internal sealed record QuicConnectionPacketReceivedEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> Datagram)
    : QuicConnectionEvent(QuicConnectionEventKind.PacketReceived, ObservedAtTicks);

internal sealed record QuicConnectionTimerExpiredEvent(
    long ObservedAtTicks,
    QuicConnectionTimerKind TimerKind,
    ulong Generation)
    : QuicConnectionEvent(QuicConnectionEventKind.TimerExpired, ObservedAtTicks);

internal sealed record QuicConnectionHandshakeConfirmedEvent(long ObservedAtTicks)
    : QuicConnectionEvent(QuicConnectionEventKind.HandshakeConfirmed, ObservedAtTicks);

internal sealed record QuicConnectionLocalCloseRequestedEvent(
    long ObservedAtTicks,
    QuicConnectionCloseMetadata Close)
    : QuicConnectionEvent(QuicConnectionEventKind.LocalCloseRequested, ObservedAtTicks);

internal sealed record QuicConnectionConnectionCloseFrameReceivedEvent(
    long ObservedAtTicks,
    QuicConnectionCloseMetadata Close)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionCloseFrameReceived, ObservedAtTicks);

internal sealed record QuicConnectionStatelessResetMatchedEvent(
    long ObservedAtTicks,
    QuicConnectionPathIdentity PathIdentity)
    : QuicConnectionEvent(QuicConnectionEventKind.StatelessResetMatched, ObservedAtTicks);

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
    ulong StreamId,
    QuicConnectionStreamActionKind ActionKind)
    : QuicConnectionEvent(QuicConnectionEventKind.StreamAction, ObservedAtTicks);

internal sealed record QuicConnectionTransportParametersCommittedEvent(
    long ObservedAtTicks,
    QuicConnectionTransportState TransportFlags,
    ulong? LocalMaxIdleTimeoutMicros = null,
    ulong? PeerMaxIdleTimeoutMicros = null,
    ulong? CurrentProbeTimeoutMicros = null)
    : QuicConnectionEvent(QuicConnectionEventKind.TransportParametersCommitted, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdIssuedEvent(
    long ObservedAtTicks,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdIssued, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdRetiredEvent(
    long ObservedAtTicks,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdRetired, ObservedAtTicks);

internal sealed record QuicConnectionConnectionIdAcknowledgedEvent(
    long ObservedAtTicks,
    ulong ConnectionId)
    : QuicConnectionEvent(QuicConnectionEventKind.ConnectionIdAcknowledged, ObservedAtTicks);

internal abstract record QuicConnectionEffect(QuicConnectionEffectKind Kind);

internal sealed record QuicConnectionSendDatagramEffect(
    QuicConnectionPathIdentity PathIdentity,
    ReadOnlyMemory<byte> Datagram)
    : QuicConnectionEffect(QuicConnectionEffectKind.SendDatagram);

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

internal sealed record QuicConnectionNotifyStreamsOfTerminalStateEffect(
    QuicConnectionTerminalState TerminalState)
    : QuicConnectionEffect(QuicConnectionEffectKind.NotifyStreamsOfTerminalState);

internal sealed record QuicConnectionDiscardConnectionStateEffect(
    QuicConnectionTerminalState? TerminalState = null)
    : QuicConnectionEffect(QuicConnectionEffectKind.DiscardConnectionState);

internal sealed record QuicConnectionEmitDiagnosticEffect(string Message)
    : QuicConnectionEffect(QuicConnectionEffectKind.EmitDiagnostic);

internal readonly record struct QuicConnectionTransitionResult(
    ulong Sequence,
    long ObservedAtTicks,
    QuicConnectionEventKind EventKind,
    QuicConnectionPhase PreviousPhase,
    QuicConnectionPhase CurrentPhase,
    bool StateChanged,
    QuicConnectionEffect[] Effects)
{
    public bool HasEffects => Effects.Length > 0;
}
