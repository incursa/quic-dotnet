namespace Incursa.Quic;

[Flags]
internal enum QuicConnectionTransportState
{
    None = 0,
    DisableActiveMigration = 1 << 0,
    PeerTransportParametersCommitted = 1 << 1,
    PeerAddressValidated = 1 << 2,
}

internal enum QuicConnectionCloseOrigin
{
    None = 0,
    Local = 1,
    Remote = 2,
    StatelessReset = 3,
    IdleTimeout = 4,
    ProtocolViolation = 5,
    Application = 6,
}

internal enum QuicConnectionTimerKind
{
    IdleTimeout = 0,
    CloseLifetime = 1,
    DrainLifetime = 2,
    PathValidation = 3,
}

internal enum QuicConnectionStreamOwnership
{
    Local = 0,
    Remote = 1,
}

internal enum QuicConnectionStreamDirection
{
    Bidirectional = 0,
    Unidirectional = 1,
}

internal readonly record struct QuicConnectionPathIdentity(
    string RemoteAddress,
    string? LocalAddress = null,
    int? RemotePort = null,
    int? LocalPort = null);

internal readonly record struct QuicConnectionPathRecoverySnapshot(
    ulong SmoothedRttMicros,
    ulong RttVarMicros,
    ulong CongestionWindowBytes,
    ulong BytesInFlightBytes,
    bool EcnValidated);

internal readonly record struct QuicConnectionPathValidationState(
    ulong Generation,
    bool IsValidated,
    bool IsAbandoned,
    ulong ChallengeSendCount,
    long? ChallengeSentAtTicks,
    long? ValidationDeadlineTicks,
    ReadOnlyMemory<byte> ChallengePayload);

internal readonly record struct QuicConnectionActivePathRecord(
    QuicConnectionPathIdentity Identity,
    long ActivatedAtTicks,
    long LastActivityTicks,
    bool IsValidated,
    QuicConnectionPathRecoverySnapshot? RecoverySnapshot);

internal readonly record struct QuicConnectionCandidatePathRecord(
    QuicConnectionPathIdentity Identity,
    long DiscoveredAtTicks,
    long LastActivityTicks,
    QuicConnectionPathValidationState Validation,
    QuicConnectionPathRecoverySnapshot? SavedRecoverySnapshot);

internal readonly record struct QuicConnectionValidatedPathRecord(
    QuicConnectionPathIdentity Identity,
    long ValidatedAtTicks,
    QuicConnectionPathRecoverySnapshot? SavedRecoverySnapshot);

internal readonly record struct QuicConnectionCloseMetadata(
    QuicTransportErrorCode? TransportErrorCode,
    ulong? ApplicationErrorCode,
    ulong? TriggeringFrameType,
    string? ReasonPhrase);

internal readonly record struct QuicConnectionTerminalState(
    QuicConnectionPhase Phase,
    QuicConnectionCloseOrigin Origin,
    QuicConnectionCloseMetadata Close,
    long EnteredAtTicks);

internal readonly record struct QuicConnectionTimerPriority(long DueTicks, ulong Sequence)
    : IComparable<QuicConnectionTimerPriority>
{
    public int CompareTo(QuicConnectionTimerPriority other)
    {
        int dueComparison = DueTicks.CompareTo(other.DueTicks);
        return dueComparison != 0 ? dueComparison : Sequence.CompareTo(other.Sequence);
    }

    public static bool operator <(QuicConnectionTimerPriority left, QuicConnectionTimerPriority right)
    {
        return left.CompareTo(right) < 0;
    }

    public static bool operator <=(QuicConnectionTimerPriority left, QuicConnectionTimerPriority right)
    {
        return left.CompareTo(right) <= 0;
    }

    public static bool operator >(QuicConnectionTimerPriority left, QuicConnectionTimerPriority right)
    {
        return left.CompareTo(right) > 0;
    }

    public static bool operator >=(QuicConnectionTimerPriority left, QuicConnectionTimerPriority right)
    {
        return left.CompareTo(right) >= 0;
    }
}

internal readonly record struct QuicConnectionTimerDeadlineState(
    long? IdleTimeoutDueTicks,
    long? CloseLifetimeDueTicks,
    long? DrainLifetimeDueTicks,
    ulong Generation,
    ulong NextSequence)
{
    public bool HasAnyDeadline => IdleTimeoutDueTicks.HasValue
        || CloseLifetimeDueTicks.HasValue
        || DrainLifetimeDueTicks.HasValue;

    public QuicConnectionTimerPriority CreatePriority(long dueTicks)
    {
        return new QuicConnectionTimerPriority(dueTicks, NextSequence);
    }
}

internal readonly record struct QuicConnectionStreamRecord(
    ulong StreamId,
    QuicConnectionStreamOwnership Ownership,
    QuicConnectionStreamDirection Direction,
    long LastActivityTicks);
