// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
    private static readonly TimerCallback DeadlineWakeTimerCallback = static state =>
    {
        DeadlineWakeTimerState timerState = (DeadlineWakeTimerState)state!;
        QuicConnectionRuntimeShardWorkItem workItem = default;
        workItem = workItem with { EnqueuedTimestamp = QuicMetrics.GetRuntimeShardEnqueueTimestamp() };
        if (timerState.Writer.TryWrite(workItem))
        {
            QuicMetrics.RecordRuntimeShardWorkItemEnqueued(timerState.ShardIndex, in workItem);
        }
    };

    private sealed class DeadlineWakeTimerState
    {
        internal DeadlineWakeTimerState(ChannelWriter<QuicConnectionRuntimeShardWorkItem> writer, int shardIndex)
        {
            Writer = writer;
            ShardIndex = shardIndex;
        }

        internal ChannelWriter<QuicConnectionRuntimeShardWorkItem> Writer { get; }

        internal int ShardIndex { get; }
    }

    private readonly IMonotonicClock clock;
    private readonly Timer deadlineWakeTimer;
    private readonly QuicConnectionRuntimeDeadlineScheduler deadlineScheduler = new();
    private readonly Channel<QuicConnectionRuntimeShardWorkItem> inbox;
    private readonly int shardIndex;
    private readonly bool suppressHostedTimerEffectObjects;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;

    /// <summary>
    /// Creates a shard with the supplied shard index and optional shared clock.
    /// </summary>
    public QuicConnectionRuntimeShard(
        int shardIndex,
        IMonotonicClock? clock = null,
        bool suppressHostedTimerEffectObjects = false)
    {
        if (shardIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shardIndex));
        }

        this.shardIndex = shardIndex;
        this.clock = clock ?? new MonotonicClock();
        this.suppressHostedTimerEffectObjects = suppressHostedTimerEffectObjects;
        inbox = Channel.CreateUnbounded<QuicConnectionRuntimeShardWorkItem>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });

        deadlineWakeTimer = new Timer(
            DeadlineWakeTimerCallback,
            new DeadlineWakeTimerState(inbox.Writer, shardIndex),
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);
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

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(handle, runtime, connectionEvent));
    }

    public bool TryPostPacketReceived(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionPacketReceivedContext packetReceived,
        byte[]? ownedDatagramBuffer,
        QuicReceiveBufferOwnership ownedDatagramBufferOwnership)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(
            handle,
            runtime,
            packetReceived,
            ownedDatagramBuffer,
            ownedDatagramBufferOwnership));
    }

    public bool TryPostStreamCapacityRelease(QuicConnectionHandle handle, QuicConnectionRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(
            handle,
            runtime,
            QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease));
    }

    public bool TryPostFlowControlCreditUpdate(QuicConnectionHandle handle, QuicConnectionRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(
            handle,
            runtime,
            QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate));
    }

    public bool TryPostStreamOpen(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        long requestId,
        QuicStreamType streamType)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(
            handle,
            runtime,
            requestId,
            streamType));
    }

    public bool TryPostStreamWrite(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        long requestId,
        QuicConnectionStreamActionKind actionKind,
        ulong streamId,
        ReadOnlyMemory<byte> streamData)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        if (runtime.IsDisposed)
        {
            return false;
        }

        return TryWriteWorkItem(new QuicConnectionRuntimeShardWorkItem(
            handle,
            runtime,
            requestId,
            actionKind,
            streamId,
            streamData));
    }

    /// <summary>
    /// Starts the shard consumer loop and returns the task that represents its lifetime.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionHandle, QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default,
        Action<QuicConnectionHandle, QuicConnectionSendDatagramUpdate>? sendDatagramObserver = null)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref consumerStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The shard consumer can only be started once.");
        }

        Task processing = ConsumeInboxAsync(
            transitionObserver,
            effectObserver,
            sendDatagramObserver,
            cancellationToken);
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
        deadlineWakeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

        Task? processing = processingTask;
        try
        {
            if (processing is not null)
            {
                await processing.ConfigureAwait(false);
            }
        }
        finally
        {
            await deadlineWakeTimer.DisposeAsync().ConfigureAwait(false);
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
        Action<QuicConnectionHandle, QuicConnectionSendDatagramUpdate>? sendDatagramObserver,
        CancellationToken cancellationToken)
    {
        ChannelReader<QuicConnectionRuntimeShardWorkItem> reader = inbox.Reader;
        CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.UnsafeRegister(static state =>
            {
                ChannelWriter<QuicConnectionRuntimeShardWorkItem> writer = (ChannelWriter<QuicConnectionRuntimeShardWorkItem>)state!;
                writer.TryComplete();
            }, inbox.Writer)
            : default;

        try
        {
            while (true)
            {
                // CONTEXT: The shard loop drains timer expirations before and after inbox reads because
                // both timer completion and connection work share this single-reader path; that keeps
                // due timers from waiting on a separate wake-up when the shard is already active.
                // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeShard.cs#ConsumeInboxAsync
                // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeDeadlineScheduler.cs#EnqueueDueEntries
                // Drain any timer expirations into the inbox before and after reading so deadlines do not wait for
                // a separate wake-up when the shard is already active.
                EnqueueDueEntries(clock.Ticks);

                while (reader.TryRead(out QuicConnectionRuntimeShardWorkItem workItem))
                {
                    QuicMetrics.RecordRuntimeShardWorkItemDequeued(shardIndex, in workItem);
                    if (IsDeadlineWakeWorkItem(workItem))
                    {
                        continue;
                    }

                    ProcessWorkItem(workItem, transitionObserver, effectObserver, sendDatagramObserver);
                }

                EnqueueDueEntries(clock.Ticks);
                if (reader.TryRead(out QuicConnectionRuntimeShardWorkItem queuedTimerWorkItem))
                {
                    QuicMetrics.RecordRuntimeShardWorkItemDequeued(shardIndex, in queuedTimerWorkItem);
                    if (IsDeadlineWakeWorkItem(queuedTimerWorkItem))
                    {
                        continue;
                    }

                    ProcessWorkItem(queuedTimerWorkItem, transitionObserver, effectObserver, sendDatagramObserver);
                    continue;
                }

                if (!deadlineScheduler.TryGetNextWait(clock.Ticks, out TimeSpan wait))
                {
                    if (!await reader.WaitToReadAsync().ConfigureAwait(false))
                    {
                        break;
                    }

                    continue;
                }

                if (wait == TimeSpan.Zero)
                {
                    continue;
                }

                deadlineWakeTimer.Change(wait, Timeout.InfiniteTimeSpan);
                if (!await reader.WaitToReadAsync().ConfigureAwait(false))
                {
                    break;
                }

                deadlineWakeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            }
        }
        finally
        {
            deadlineWakeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            await cancellationRegistration.DisposeAsync().ConfigureAwait(false);
            while (reader.TryRead(out QuicConnectionRuntimeShardWorkItem workItem))
            {
                QuicMetrics.RecordRuntimeShardWorkItemDequeued(shardIndex, in workItem);
                if (IsDeadlineWakeWorkItem(workItem))
                {
                    continue;
                }

                ReleaseWorkItemResources(workItem);
            }
        }
    }

    /// <summary>
    /// Applies a runtime-emitted effect to the shard-local deadline scheduler.
    /// </summary>
    internal void ApplyEffect(QuicConnectionHandle handle, QuicConnectionRuntime runtime, QuicConnectionEffect effect)
    {
        deadlineScheduler.Apply(handle, runtime, effect);
    }

    private bool TryWriteWorkItem(in QuicConnectionRuntimeShardWorkItem workItem)
    {
        QuicConnectionRuntimeShardWorkItem queuedWorkItem = workItem with
        {
            EnqueuedTimestamp = QuicMetrics.GetRuntimeShardEnqueueTimestamp(),
        };
        if (!inbox.Writer.TryWrite(queuedWorkItem))
        {
            return false;
        }

        QuicMetrics.RecordRuntimeShardWorkItemEnqueued(shardIndex, in queuedWorkItem);
        return true;
    }

    private void EnqueueDueEntries(long nowTicks)
    {
        while (deadlineScheduler.TryDequeueDueEntry(nowTicks, out QuicConnectionRuntimeScheduledTimerEntry entry))
        {
            QuicConnectionRuntimeShardWorkItem workItem = new(
                entry.Handle,
                entry.Runtime,
                new QuicConnectionTimerExpiredEvent(nowTicks, entry.TimerKind, entry.Generation));
            if (!TryWriteWorkItem(in workItem))
            {
                break;
            }
        }
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
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver,
        Action<QuicConnectionHandle, QuicConnectionSendDatagramUpdate>? sendDatagramObserver)
    {
        long serviceStartedTimestamp = QuicMetrics.GetRuntimeShardServiceStartTimestamp();
        QuicConnectionRuntime? runtime = workItem.Runtime;
        bool flushMeasurementStarted = false;
        try
        {
            if (runtime is null)
            {
                return;
            }

            if ((runtime.IsDisposed
                    && workItem.ConnectionEvent is not QuicConnectionLocalCloseRequestedEvent)
                || runtime.IsInboxConsumerRunning)
            {
                return;
            }

            runtime.ConfigureHostedTimerEffectSuppression(
                suppressHostedTimerEffectObjects,
                suppressSendDatagramEffects: suppressHostedTimerEffectObjects && sendDatagramObserver is not null);
            flushMeasurementStarted = runtime.BeginRuntimeWorkItemFlushMeasurement();

            QuicConnectionTransitionResult result = workItem.Kind switch
            {
                QuicConnectionRuntimeShardWorkItemKind.PacketReceived
                    => runtime.TransitionPacketReceived(workItem.PacketReceived, clock.Ticks),
                QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease
                    => runtime.TransitionStreamCapacityRelease(clock.Ticks),
                QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate
                    => runtime.TransitionFlowControlCreditUpdate(clock.Ticks),
                QuicConnectionRuntimeShardWorkItemKind.StreamOpen
                    => runtime.TransitionStreamOpen(workItem.RequestId, workItem.StreamType, clock.Ticks),
                QuicConnectionRuntimeShardWorkItemKind.StreamWrite
                    => runtime.TransitionStreamWrite(
                        workItem.RequestId,
                        workItem.StreamActionKind,
                        workItem.StreamId,
                        workItem.StreamData,
                        clock.Ticks),
                _ => runtime.Transition(workItem.ConnectionEvent!, clock.Ticks),
            };
            transitionObserver?.Invoke(workItem.Handle, result);
            runtime.ApplyPendingHostedTimerUpdates(workItem.Handle, deadlineScheduler);

            for (int index = 0; index < result.EffectCount; index++)
            {
                QuicConnectionEffect effect = result.GetEffect(index);
                if (effect is QuicConnectionHostedSendDatagramMarkerEffect)
                {
                    if (!runtime.TryTakePendingHostedSendDatagramUpdate(out QuicConnectionSendDatagramUpdate update))
                    {
                        throw new InvalidOperationException(
                            "The hosted send-datagram marker did not have a matching value update.");
                    }

                    try
                    {
                        if (sendDatagramObserver is not null)
                        {
                            sendDatagramObserver(workItem.Handle, update);
                        }
                        else
                        {
                            effectObserver?.Invoke(workItem.Handle, update.ToEffect());
                        }
                    }
                    finally
                    {
                        update.ReleaseDatagramOwner();
                    }

                    continue;
                }

                deadlineScheduler.Apply(workItem.Handle, runtime, effect);
                effectObserver?.Invoke(workItem.Handle, effect);
            }

            QuicMetrics.RecordRuntimePressureSnapshot(shardIndex, runtime);
        }
        finally
        {
            if (flushMeasurementStarted)
            {
                runtime!.TakeRuntimeWorkItemFlushMeasurement(
                    out int applicationSendCount,
                    out int flowControlCount,
                    out int streamCapacityCount);
                QuicMetrics.RecordRuntimeFollowOnFlushItems(
                    shardIndex,
                    in workItem,
                    applicationSendCount,
                    flowControlCount,
                    streamCapacityCount);
            }

            QuicMetrics.RecordRuntimeShardServiceTime(shardIndex, in workItem, serviceStartedTimestamp);
            runtime?.ConfigureHostedTimerEffectSuppression(suppress: false);
            ReleaseWorkItemResources(workItem);
        }
    }

    private static bool IsDeadlineWakeWorkItem(QuicConnectionRuntimeShardWorkItem workItem)
        => workItem.Runtime is null && workItem.ConnectionEvent is null && workItem.Kind == QuicConnectionRuntimeShardWorkItemKind.Event;

    private static void ReleaseWorkItemResources(QuicConnectionRuntimeShardWorkItem workItem)
    {
        if (workItem.ConnectionEvent is QuicConnectionPacketReceivedEvent packetReceivedEvent)
        {
            packetReceivedEvent.ReleaseOwnedDatagramBuffer();
            return;
        }

        if (workItem.Kind == QuicConnectionRuntimeShardWorkItemKind.PacketReceived
            && workItem.OwnedDatagramBuffer is { } ownedDatagramBuffer)
        {
            if (workItem.OwnedDatagramBufferOwnership.Pool is { } pool)
            {
                pool.Return(ownedDatagramBuffer, workItem.OwnedDatagramBufferOwnership);
            }
            else
            {
                QuicBufferPool.ReturnBytes(ownedDatagramBuffer);
            }
        }
    }
}
