using System.Threading;
using System.Threading.Channels;

namespace Incursa.Quic;

/// <summary>
/// Owns the connection runtime shell, its single-consumer inbox, and the connection-owned transition path.
/// </summary>
internal sealed class QuicConnectionRuntime : IAsyncDisposable, IDisposable
{
    private readonly IMonotonicClock clock;
    private readonly QuicConnectionStreamRegistry streamRegistry;
    private readonly Channel<QuicConnectionEvent> inbox;
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> candidatePaths = [];
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> recentlyValidatedPaths = [];
    private readonly QuicConnectionPhase phase = QuicConnectionPhase.Establishing;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;
    private bool handshakeConfirmed;
    private QuicConnectionTransportState transportFlags;
    private QuicConnectionActivePathRecord? activePath = null;
    private QuicConnectionTimerDeadlineState timerState = default;
    private QuicConnectionTerminalState? terminalState = null;
    private readonly string? lastValidatedRemoteAddress = null;
    private long lastTransitionTicks;
    private ulong transitionSequence;

    public QuicConnectionRuntime(
        QuicConnectionStreamState bookkeeping,
        IMonotonicClock? clock = null,
        int maximumCandidatePaths = 8,
        int maximumRecentlyValidatedPaths = 8)
    {
        this.clock = clock ?? new MonotonicClock();
        streamRegistry = new QuicConnectionStreamRegistry(bookkeeping);
        inbox = Channel.CreateUnbounded<QuicConnectionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });

        if (maximumCandidatePaths < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCandidatePaths));
        }

        if (maximumRecentlyValidatedPaths < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecentlyValidatedPaths));
        }

        MaximumCandidatePaths = maximumCandidatePaths;
        MaximumRecentlyValidatedPaths = maximumRecentlyValidatedPaths;
    }

    public QuicConnectionPhase Phase => phase;

    public bool HandshakeConfirmed => handshakeConfirmed;

    public QuicConnectionTransportState TransportFlags => transportFlags;

    public QuicConnectionActivePathRecord? ActivePath => activePath;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> CandidatePaths => candidatePaths;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> RecentlyValidatedPaths => recentlyValidatedPaths;

    public QuicConnectionTimerDeadlineState TimerState => timerState;

    public QuicConnectionTerminalState? TerminalState => terminalState;

    public string? LastValidatedRemoteAddress => lastValidatedRemoteAddress;

    public QuicConnectionStreamRegistry StreamRegistry => streamRegistry;

    public int MaximumCandidatePaths { get; }

    public int MaximumRecentlyValidatedPaths { get; }

    public long LastTransitionTicks => lastTransitionTicks;

    public ulong TransitionSequence => transitionSequence;

    internal bool IsInboxConsumerRunning => Volatile.Read(ref consumerStarted) != 0;

    internal bool IsDisposed => Volatile.Read(ref disposed) != 0;

    internal IMonotonicClock Clock => clock;

    /// <summary>
    /// Posts a network-originated event to the connection inbox.
    /// </summary>
    public bool TryPostNetworkEvent(QuicConnectionEvent networkEvent)
    {
        return TryPostEvent(networkEvent);
    }

    /// <summary>
    /// Posts a timer-originated event to the connection inbox.
    /// </summary>
    public bool TryPostTimerEvent(QuicConnectionTimerExpiredEvent timerEvent)
    {
        return TryPostEvent(timerEvent);
    }

    /// <summary>
    /// Posts a local API event to the connection inbox.
    /// </summary>
    public bool TryPostLocalApiEvent(QuicConnectionEvent localApiEvent)
    {
        return TryPostEvent(localApiEvent);
    }

    /// <summary>
    /// Runs the single logical consumer for the connection inbox until the inbox is completed or canceled.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref consumerStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The connection runtime consumer can only be started once.");
        }

        Task processing = ConsumeInboxAsync(transitionObserver, effectObserver, cancellationToken);
        processingTask = processing;
        return processing;
    }

    public QuicConnectionTransitionResult Transition(QuicConnectionEvent connectionEvent)
    {
        return Transition(connectionEvent, clock.Ticks);
    }

    public QuicConnectionTransitionResult Transition(QuicConnectionEvent connectionEvent, long nowTicks)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);

        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        bool stateChanged = connectionEvent switch
        {
            QuicConnectionHandshakeConfirmedEvent => ConfirmHandshake(),
            QuicConnectionTransportParametersCommittedEvent transportParametersCommittedEvent
                => ApplyTransportParameters(transportParametersCommittedEvent.TransportFlags),
            QuicConnectionTimerExpiredEvent timerExpiredEvent => TryHandleTimerExpired(timerExpiredEvent),
            _ => false,
        };

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            connectionEvent.Kind,
            previousPhase,
            phase,
            stateChanged,
            Array.Empty<QuicConnectionEffect>());
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        inbox.Writer.TryComplete();

        Task? processing = processingTask;
        if (processing is not null)
        {
            await processing.ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private async Task ConsumeInboxAsync(
        Action<QuicConnectionTransitionResult>? transitionObserver,
        Action<QuicConnectionEffect>? effectObserver,
        CancellationToken cancellationToken)
    {
        ChannelReader<QuicConnectionEvent> reader = inbox.Reader;

        try
        {
            while (await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (reader.TryRead(out QuicConnectionEvent? connectionEvent))
                {
                    QuicConnectionTransitionResult result = Transition(connectionEvent);
                    transitionObserver?.Invoke(result);

                    if (effectObserver is not null)
                    {
                        foreach (QuicConnectionEffect effect in result.Effects)
                        {
                            effectObserver(effect);
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The owner requested a stop; queued events are left to the caller's shutdown policy.
        }
    }

    private bool TryPostEvent(QuicConnectionEvent connectionEvent)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        return inbox.Writer.TryWrite(connectionEvent);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntime));
        }
    }

    private bool ConfirmHandshake()
    {
        if (handshakeConfirmed)
        {
            return false;
        }

        handshakeConfirmed = true;
        return true;
    }

    private bool ApplyTransportParameters(QuicConnectionTransportState committedFlags)
    {
        QuicConnectionTransportState updatedFlags = transportFlags | committedFlags;
        if (updatedFlags == transportFlags)
        {
            return false;
        }

        transportFlags = updatedFlags;
        return true;
    }

    internal QuicConnectionEffect[] SetTimerDeadline(QuicConnectionTimerKind timerKind, long? dueTicks)
    {
        QuicConnectionTimerSchedule currentSchedule = GetTimerSchedule(timerKind);
        if (currentSchedule.DueTicks == dueTicks)
        {
            return Array.Empty<QuicConnectionEffect>();
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(currentSchedule.Generation);
        timerState = timerState.WithSchedule(timerKind, dueTicks, nextGeneration);

        if (!dueTicks.HasValue)
        {
            return [new QuicConnectionCancelTimerEffect(timerKind, nextGeneration)];
        }

        QuicConnectionTimerPriority priority = timerState.CreatePriority(dueTicks.Value);
        timerState = timerState.AdvancePrioritySequence();
        return [new QuicConnectionArmTimerEffect(timerKind, nextGeneration, priority)];
    }

    private QuicConnectionTimerSchedule GetTimerSchedule(QuicConnectionTimerKind timerKind)
    {
        return timerKind switch
        {
            QuicConnectionTimerKind.IdleTimeout => timerState.IdleTimeout,
            QuicConnectionTimerKind.CloseLifetime => timerState.CloseLifetime,
            QuicConnectionTimerKind.DrainLifetime => timerState.DrainLifetime,
            QuicConnectionTimerKind.PathValidation => timerState.PathValidation,
            _ => throw new ArgumentOutOfRangeException(nameof(timerKind)),
        };
    }

    private bool TryHandleTimerExpired(QuicConnectionTimerExpiredEvent timerExpiredEvent)
    {
        if (!timerState.IsCurrent(timerExpiredEvent.TimerKind, timerExpiredEvent.Generation))
        {
            return false;
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(
            timerState.GetGeneration(timerExpiredEvent.TimerKind));

        timerState = timerState.WithSchedule(timerExpiredEvent.TimerKind, null, nextGeneration);
        return true;
    }
}
