using System.Collections.Concurrent;

namespace Incursa.Quic;

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

    public int ShardCount => shards.Length;

    public QuicConnectionHandle AllocateConnectionHandle()
    {
        ThrowIfDisposed();

        long nextValue = Interlocked.Increment(ref nextHandleValue);
        return new QuicConnectionHandle(unchecked((ulong)nextValue));
    }

    public int GetShardIndex(QuicConnectionHandle handle)
    {
        return SelectShardIndex(handle, ShardCount);
    }

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
        processingTask = processing;
        return processing;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

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
