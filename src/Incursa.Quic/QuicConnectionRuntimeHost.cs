using System.Collections.Concurrent;

namespace Incursa.Quic;

/// <summary>
/// Owns the shard set for runtime-driven QUIC connection processing and routes handles to the correct shard.
/// </summary>
/// <remarks>
/// The host starts at most one consumer fan-out, tracks handle ownership, and coordinates orderly shutdown of
/// all shard inboxes before waiting for the processing task to finish.
/// </remarks>
internal sealed class QuicConnectionRuntimeHost : IAsyncDisposable, IDisposable
{
    private const int HashShift = 33;
    private const ulong HashConstant1 = 0xff51afd7ed558ccdUL;
    private const ulong HashConstant2 = 0xc4ceb9fe1a85ec53UL;

    private readonly ConcurrentDictionary<QuicConnectionHandle, QuicConnectionRuntimeRoute> routes = new();
    private readonly ConcurrentDictionary<QuicConnectionRuntime, QuicConnectionHandle> runtimeOwnership =
        new(ReferenceEqualityComparer.Instance);
    private readonly QuicConnectionRuntimeShard[] shards;

    private long nextHandleValue;
    private int consumerStarted;
    private int disposed;
    private Task? processingTask;

    /// <summary>
    /// Creates a runtime host with the requested number of shards.
    /// </summary>
    public QuicConnectionRuntimeHost(int shardCount, IMonotonicClock? clock = null)
    {
        if (shardCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shardCount));
        }

        IMonotonicClock sharedClock = clock ?? new MonotonicClock();
        shards = new QuicConnectionRuntimeShard[shardCount];
        for (int index = 0; index < shards.Length; index++)
        {
            shards[index] = new QuicConnectionRuntimeShard(index, sharedClock);
        }
    }

    /// <summary>
    /// Gets the number of shards owned by this host.
    /// </summary>
    public int ShardCount => shards.Length;

    /// <summary>
    /// Allocates a new connection handle owned by this host.
    /// </summary>
    public QuicConnectionHandle AllocateConnectionHandle()
    {
        ThrowIfDisposed();

        long nextValue = Interlocked.Increment(ref nextHandleValue);
        return new QuicConnectionHandle(unchecked((ulong)nextValue));
    }

    /// <summary>
    /// Maps a handle to its owning shard index.
    /// </summary>
    public int GetShardIndex(QuicConnectionHandle handle)
    {
        return SelectShardIndex(handle, ShardCount);
    }

    /// <summary>
    /// Registers a runtime handle pair so later events can be routed back to the same shard.
    /// </summary>
    public bool TryRegisterConnection(QuicConnectionHandle handle, QuicConnectionRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed || runtime.IsInboxConsumerRunning)
        {
            return false;
        }

        if (!runtimeOwnership.TryAdd(runtime, handle))
        {
            return false;
        }

        int shardIndex = GetShardIndex(handle);
        if (!routes.TryAdd(handle, new QuicConnectionRuntimeRoute(shardIndex, runtime)))
        {
            runtimeOwnership.TryRemove(runtime, out _);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Removes the handle-to-runtime routing owned by this host.
    /// </summary>
    public bool TryUnregisterConnection(QuicConnectionHandle handle)
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (!routes.TryRemove(handle, out QuicConnectionRuntimeRoute route))
        {
            return false;
        }

        runtimeOwnership.TryRemove(route.Runtime, out _);
        return true;
    }

    /// <summary>
    /// Posts a connection event to the shard that owns the registered runtime.
    /// </summary>
    public bool TryPostEvent(QuicConnectionHandle handle, QuicConnectionEvent connectionEvent)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (!routes.TryGetValue(handle, out QuicConnectionRuntimeRoute route))
        {
            return false;
        }

        if (route.Runtime.IsDisposed)
        {
            return false;
        }

        return shards[route.ShardIndex].TryPost(handle, route.Runtime, connectionEvent);
    }

    /// <summary>
    /// Starts the shard consumers and returns a task that completes when all shards stop.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionHandle, int, QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionHandle, int, QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref consumerStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The runtime host consumer can only be started once.");
        }

        Task[] processingTasks = new Task[shards.Length];
        for (int index = 0; index < shards.Length; index++)
        {
            int shardIndex = index;
            processingTasks[index] = shards[index].RunAsync(
                (handle, transition) => transitionObserver?.Invoke(handle, shardIndex, transition),
                (handle, effect) => effectObserver?.Invoke(handle, shardIndex, effect),
                cancellationToken);
        }

        Task processing = Task.WhenAll(processingTasks);
        // Cache the fan-out task so disposal can await the same completion path even if the caller discards it.
        processingTask = processing;
        return processing;
    }

    /// <summary>
    /// Stops all shards, clears routing state, and waits for the consumer fan-out to complete.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        // Close the shard inboxes first so the single-reader loops observe shutdown and exit cleanly.
        foreach (QuicConnectionRuntimeShard shard in shards)
        {
            await shard.DisposeAsync().ConfigureAwait(false);
        }

        routes.Clear();
        runtimeOwnership.Clear();

        Task? processing = processingTask;
        if (processing is not null)
        {
            await processing.ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Synchronously disposes the host by waiting for the asynchronous shutdown path.
    /// </summary>
    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private static int SelectShardIndex(QuicConnectionHandle handle, int shardCount)
    {
        ulong mixed = handle.Value;
        mixed ^= mixed >> HashShift;
        mixed *= HashConstant1;
        mixed ^= mixed >> HashShift;
        mixed *= HashConstant2;
        mixed ^= mixed >> HashShift;

        return (int)(mixed % (ulong)shardCount);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntimeHost));
        }
    }
}
