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
    ReleaseCapacity = 6,
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

internal sealed record QuicConnectionPeerHandshakeTranscriptCompletedEvent(long ObservedAtTicks)
    : QuicConnectionEvent(QuicConnectionEventKind.PeerHandshakeTranscriptCompleted, ObservedAtTicks);

internal sealed record QuicConnectionHandshakeBootstrapRequestedEvent(
    long ObservedAtTicks,
    QuicTransportParameters? LocalTransportParameters)
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
    ReadOnlyMemory<byte> StatelessResetToken)
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

internal sealed record QuicConnectionEmitDiagnosticEffect(QuicDiagnosticEvent Diagnostic)
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
