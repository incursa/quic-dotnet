namespace Incursa.Quic;

[Flags]
internal enum QuicConnectionTransportState
{
    None = 0,
    DisableActiveMigration = 1 << 0,
    PeerTransportParametersCommitted = 1 << 1,
    PeerAddressValidated = 1 << 2,
}

internal enum QuicConnectionPathClassification
{
    SamePathTraffic = 0,
    ProbableNatRebinding = 1,
    MigrationCandidate = 2,
    PreferredAddressTransition = 3,
    NoiseOrAttack = 4,
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
    VersionNegotiation = 7,
}

internal enum QuicConnectionSendingMode
{
    Ordinary = 0,
    CloseOnly = 1,
    None = 2,
}

internal enum QuicConnectionTimerKind
{
    IdleTimeout = 0,
    CloseLifetime = 1,
    DrainLifetime = 2,
    PathValidation = 3,
    ApplicationSendDelay = 4,
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

internal readonly record struct QuicConnectionHandle(ulong Value);

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

internal readonly record struct QuicConnectionPathMaximumDatagramSizeState
{
    internal const ulong MinimumAllowedMaximumDatagramSizeBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;

    internal QuicConnectionPathMaximumDatagramSizeState(ulong maximumDatagramSizeBytes)
    {
        if (maximumDatagramSizeBytes == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDatagramSizeBytes));
        }

        MaximumDatagramSizeBytes = maximumDatagramSizeBytes;
    }

    internal ulong MaximumDatagramSizeBytes { get; init; } = MinimumAllowedMaximumDatagramSizeBytes;

    internal static QuicConnectionPathMaximumDatagramSizeState CreateInitial()
    {
        return new QuicConnectionPathMaximumDatagramSizeState(MinimumAllowedMaximumDatagramSizeBytes);
    }

    internal QuicConnectionPathMaximumDatagramSizeState WithMaximumDatagramSize(ulong maximumDatagramSizeBytes)
    {
        return new QuicConnectionPathMaximumDatagramSizeState(maximumDatagramSizeBytes);
    }
}

internal readonly record struct QuicConnectionPathAmplificationState(
    ulong ReceivedPayloadBytes,
    ulong SentPayloadBytes,
    bool IsAddressValidated)
{
    public ulong RemainingSendBudget => IsAddressValidated
        ? ulong.MaxValue
        : GetRemainingSendBudget();

    public bool CanSend(int payloadBytes)
    {
        return payloadBytes >= 0
            && (IsAddressValidated || (ulong)payloadBytes <= RemainingSendBudget);
    }

    public bool TryRegisterReceivedDatagramPayloadBytes(
        int payloadBytes,
        bool uniquelyAttributedToSingleConnection,
        out QuicConnectionPathAmplificationState updatedState)
    {
        updatedState = this;

        if (payloadBytes < 0)
        {
            return false;
        }

        if (!uniquelyAttributedToSingleConnection)
        {
            return true;
        }

        updatedState = this with
        {
            ReceivedPayloadBytes = SaturatingAdd(ReceivedPayloadBytes, (ulong)payloadBytes),
        };
        return true;
    }

    public bool TryConsumeSendBudget(int payloadBytes, out QuicConnectionPathAmplificationState updatedState)
    {
        updatedState = this;

        if (!CanSend(payloadBytes))
        {
            return false;
        }

        updatedState = this with
        {
            SentPayloadBytes = SaturatingAdd(SentPayloadBytes, (ulong)payloadBytes),
        };
        return true;
    }

    public QuicConnectionPathAmplificationState MarkAddressValidated()
    {
        return IsAddressValidated ? this : this with { IsAddressValidated = true };
    }

    private ulong GetRemainingSendBudget()
    {
        ulong maximumAllowedBytes = SaturatingMultiply(ReceivedPayloadBytes, 3);
        return SentPayloadBytes >= maximumAllowedBytes ? 0 : maximumAllowedBytes - SentPayloadBytes;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong result = left + right;
        return result < left ? ulong.MaxValue : result;
    }

    private static ulong SaturatingMultiply(ulong value, ulong multiplier)
    {
        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }
}

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
    QuicConnectionPathRecoverySnapshot? RecoverySnapshot)
{
    public QuicConnectionPathAmplificationState AmplificationState { get; init; }

    public QuicConnectionPathMaximumDatagramSizeState MaximumDatagramSizeState { get; init; } = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();
}

internal readonly record struct QuicConnectionCandidatePathRecord(
    QuicConnectionPathIdentity Identity,
    long DiscoveredAtTicks,
    long LastActivityTicks,
    QuicConnectionPathValidationState Validation,
    QuicConnectionPathRecoverySnapshot? SavedRecoverySnapshot)
{
    public QuicConnectionPathAmplificationState AmplificationState { get; init; }

    public QuicConnectionPathMaximumDatagramSizeState MaximumDatagramSizeState { get; init; } = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();
}

internal readonly record struct QuicConnectionValidatedPathRecord(
    QuicConnectionPathIdentity Identity,
    long ValidatedAtTicks,
    QuicConnectionPathRecoverySnapshot? SavedRecoverySnapshot)
{
    public long LastActivityTicks { get; init; }

    public QuicConnectionPathAmplificationState AmplificationState { get; init; }

    public QuicConnectionPathMaximumDatagramSizeState MaximumDatagramSizeState { get; init; } = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();
}

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

internal readonly record struct QuicConnectionTimerSchedule(
    long? DueTicks,
    ulong Generation);

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
    QuicConnectionTimerSchedule IdleTimeout,
    QuicConnectionTimerSchedule CloseLifetime,
    QuicConnectionTimerSchedule DrainLifetime,
    QuicConnectionTimerSchedule PathValidation,
    QuicConnectionTimerSchedule ApplicationSendDelay,
    ulong NextSequence)
{
    public bool HasAnyDeadline => IdleTimeout.DueTicks.HasValue
        || CloseLifetime.DueTicks.HasValue
        || DrainLifetime.DueTicks.HasValue
        || PathValidation.DueTicks.HasValue
        || ApplicationSendDelay.DueTicks.HasValue;

    public QuicConnectionTimerPriority CreatePriority(long dueTicks)
    {
        return new QuicConnectionTimerPriority(dueTicks, NextSequence);
    }

    public long? GetDueTicks(QuicConnectionTimerKind timerKind)
    {
        return GetSchedule(timerKind).DueTicks;
    }

    public ulong GetGeneration(QuicConnectionTimerKind timerKind)
    {
        return GetSchedule(timerKind).Generation;
    }

    public bool IsCurrent(QuicConnectionTimerKind timerKind, ulong generation)
    {
        QuicConnectionTimerSchedule schedule = GetSchedule(timerKind);
        return schedule.DueTicks.HasValue && schedule.Generation == generation;
    }

    public QuicConnectionTimerDeadlineState WithSchedule(
        QuicConnectionTimerKind timerKind,
        long? dueTicks,
        ulong generation)
    {
        QuicConnectionTimerSchedule schedule = new(dueTicks, generation);

        return timerKind switch
        {
            QuicConnectionTimerKind.IdleTimeout => this with { IdleTimeout = schedule },
            QuicConnectionTimerKind.CloseLifetime => this with { CloseLifetime = schedule },
            QuicConnectionTimerKind.DrainLifetime => this with { DrainLifetime = schedule },
            QuicConnectionTimerKind.PathValidation => this with { PathValidation = schedule },
            QuicConnectionTimerKind.ApplicationSendDelay => this with { ApplicationSendDelay = schedule },
            _ => throw new ArgumentOutOfRangeException(nameof(timerKind)),
        };
    }

    public QuicConnectionTimerDeadlineState AdvancePrioritySequence()
    {
        return this with { NextSequence = IncrementCounter(NextSequence) };
    }

    public static ulong IncrementCounter(ulong value)
    {
        return value == ulong.MaxValue ? ulong.MaxValue : value + 1;
    }

    private QuicConnectionTimerSchedule GetSchedule(QuicConnectionTimerKind timerKind)
    {
        return timerKind switch
        {
            QuicConnectionTimerKind.IdleTimeout => IdleTimeout,
            QuicConnectionTimerKind.CloseLifetime => CloseLifetime,
            QuicConnectionTimerKind.DrainLifetime => DrainLifetime,
            QuicConnectionTimerKind.PathValidation => PathValidation,
            QuicConnectionTimerKind.ApplicationSendDelay => ApplicationSendDelay,
            _ => throw new ArgumentOutOfRangeException(nameof(timerKind)),
        };
    }
}

internal readonly record struct QuicConnectionStreamRecord(
    ulong StreamId,
    QuicConnectionStreamOwnership Ownership,
    QuicConnectionStreamDirection Direction,
    long LastActivityTicks);

internal readonly record struct QuicConnectionRuntimeScheduledTimerKey(
    QuicConnectionHandle Handle,
    QuicConnectionTimerKind TimerKind);

internal readonly record struct QuicConnectionRuntimeScheduledTimerEntry(
    QuicConnectionHandle Handle,
    QuicConnectionRuntime Runtime,
    QuicConnectionTimerKind TimerKind,
    long DueTicks,
    ulong Generation,
    QuicConnectionTimerPriority Priority);

internal readonly record struct QuicConnectionRuntimeScheduledTimerRegistration(
    QuicConnectionRuntime Runtime,
    long DueTicks,
    ulong Generation);
