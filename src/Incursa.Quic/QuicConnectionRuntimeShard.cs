using System.Threading.Channels;

namespace Incursa.Quic;

/// <summary>
/// Owns a single runtime inbox and deadline scheduler for one shard of connection processing.
/// </summary>
/// <remarks>
/// The host is responsible for starting and stopping the shard consumer; this type only processes work routed to
/// its inbox and keeps the timer scheduler in sync with the connection runtime.
/// </remarks>
internal sealed class QuicConnectionRuntimeShard : IAsyncDisposable, IDisposable
{
    private readonly IMonotonicClock clock;
    private readonly QuicConnectionRuntimeDeadlineScheduler deadlineScheduler = new();
    private readonly Channel<QuicConnectionRuntimeShardWorkItem> inbox;
    private readonly int shardIndex;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;

    /// <summary>
    /// Creates a shard with the supplied shard index and optional shared clock.
    /// </summary>
    public QuicConnectionRuntimeShard(int shardIndex, IMonotonicClock? clock = null)
    {
        if (shardIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shardIndex));
        }

        this.shardIndex = shardIndex;
        this.clock = clock ?? new MonotonicClock();
        inbox = Channel.CreateUnbounded<QuicConnectionRuntimeShardWorkItem>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
    }

    /// <summary>
    /// Gets the shard index assigned by the host.
    /// </summary>
    public int ShardIndex => shardIndex;

    /// <summary>
    /// Exposes the shard-local timer scheduler so the runtime can arm and cancel deadlines through this shard.
    /// </summary>
    internal QuicConnectionRuntimeDeadlineScheduler DeadlineScheduler => deadlineScheduler;

    /// <summary>
    /// Enqueues a connection event onto the shard inbox if the shard is still active.
    /// </summary>
    public bool TryPost(QuicConnectionHandle handle, QuicConnectionRuntime runtime, QuicConnectionEvent connectionEvent)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(connectionEvent);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return inbox.Writer.TryWrite(new QuicConnectionRuntimeShardWorkItem(handle, runtime, connectionEvent));
    }

    /// <summary>
    /// Starts the shard consumer loop and returns the task that represents its lifetime.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionHandle, QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref consumerStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The shard consumer can only be started once.");
        }

        Task processing = ConsumeInboxAsync(transitionObserver, effectObserver, cancellationToken);
        processingTask = processing;
        return processing;
    }

    /// <summary>
    /// Completes the shard inbox and waits for the consumer loop to exit.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        // Completing the inbox tells the single reader to finish after draining any already-posted work.
        inbox.Writer.TryComplete();

        Task? processing = processingTask;
        if (processing is not null)
        {
            await processing.ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Synchronously disposes the shard by waiting for the asynchronous shutdown path.
    /// </summary>
    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private async Task ConsumeInboxAsync(
        Action<QuicConnectionHandle, QuicConnectionTransitionResult>? transitionObserver,
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver,
        CancellationToken cancellationToken)
    {
        ChannelReader<QuicConnectionRuntimeShardWorkItem> reader = inbox.Reader;

        try
        {
            while (true)
            {
                // Drain any timer expirations into the inbox before and after reading so deadlines do not wait for
                // a separate wake-up when the shard is already active.
                deadlineScheduler.EnqueueDueEntries(clock.Ticks, inbox.Writer);

                while (reader.TryRead(out QuicConnectionRuntimeShardWorkItem workItem))
                {
                    ProcessWorkItem(workItem, transitionObserver, effectObserver);
                }

                deadlineScheduler.EnqueueDueEntries(clock.Ticks, inbox.Writer);
                if (reader.TryRead(out QuicConnectionRuntimeShardWorkItem queuedTimerWorkItem))
                {
                    ProcessWorkItem(queuedTimerWorkItem, transitionObserver, effectObserver);
                    continue;
                }

                if (!deadlineScheduler.TryGetNextWait(clock.Ticks, out TimeSpan wait))
                {
                    if (!await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        break;
                    }

                    continue;
                }

                if (wait == TimeSpan.Zero)
                {
                    continue;
                }

                Task<bool> waitToReadTask = reader.WaitToReadAsync(cancellationToken).AsTask();
                Task delayTask = Task.Delay(wait, cancellationToken);
                Task completed = await Task.WhenAny(waitToReadTask, delayTask).ConfigureAwait(false);
                if (completed == delayTask)
                {
                    continue;
                }

                if (!await waitToReadTask.ConfigureAwait(false))
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The shard owner requested a stop; any remaining queued events are left to its shutdown policy.
        }
    }

    /// <summary>
    /// Applies a runtime-emitted effect to the shard-local deadline scheduler.
    /// </summary>
    internal void ApplyEffect(QuicConnectionHandle handle, QuicConnectionRuntime runtime, QuicConnectionEffect effect)
    {
        deadlineScheduler.Apply(handle, runtime, effect);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntimeShard));
        }
    }

    private void ProcessWorkItem(
        QuicConnectionRuntimeShardWorkItem workItem,
        Action<QuicConnectionHandle, QuicConnectionTransitionResult>? transitionObserver,
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver)
    {
        if (workItem.Runtime.IsDisposed || workItem.Runtime.IsInboxConsumerRunning)
        {
            return;
        }

        QuicConnectionTransitionResult result = workItem.Runtime.Transition(workItem.ConnectionEvent, clock.Ticks);
        transitionObserver?.Invoke(workItem.Handle, result);

        foreach (QuicConnectionEffect effect in result.Effects)
        {
            deadlineScheduler.Apply(workItem.Handle, workItem.Runtime, effect);
            effectObserver?.Invoke(workItem.Handle, effect);
        }
    }
}
