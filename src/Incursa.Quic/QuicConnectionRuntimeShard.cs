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
    private const int MaximumDeferredApplicationAckPacketCount = 8;
    private static readonly TimerCallback DeadlineWakeTimerCallback = static state =>
    {
        DeadlineWakeTimerState timerState = (DeadlineWakeTimerState)state!;
        QuicConnectionRuntimeShardWorkItem workItem = default;
        workItem = workItem with { EnqueuedTimestamp = QuicMetrics.GetRuntimeShardEnqueueTimestamp() };
        timerState.MetricsRegistration.BeginEnqueue(in workItem);
        if (timerState.Writer.TryWrite(workItem))
        {
            QuicMetrics.RecordRuntimeShardWorkItemEnqueued(timerState.ShardIndex, in workItem);
            return;
        }

        timerState.MetricsRegistration.CancelEnqueue(in workItem);
    };

    private sealed class DeadlineWakeTimerState
    {
        internal DeadlineWakeTimerState(
            ChannelWriter<QuicConnectionRuntimeShardWorkItem> writer,
            int shardIndex,
            QuicMetrics.RuntimeShardMetricsRegistration metricsRegistration)
        {
            Writer = writer;
            ShardIndex = shardIndex;
            MetricsRegistration = metricsRegistration;
        }

        internal ChannelWriter<QuicConnectionRuntimeShardWorkItem> Writer { get; }

        internal int ShardIndex { get; }

        internal QuicMetrics.RuntimeShardMetricsRegistration MetricsRegistration { get; }
    }

    private readonly IMonotonicClock clock;
    private readonly Timer deadlineWakeTimer;
    private readonly QuicConnectionRuntimeDeadlineScheduler deadlineScheduler = new();
    private readonly Channel<QuicConnectionRuntimeShardWorkItem> inbox;
    private readonly QuicMetrics.RuntimeShardMetricsRegistration metricsRegistration;
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
        metricsRegistration = QuicMetrics.RegisterRuntimeShard(shardIndex, inbox.Reader);

        deadlineWakeTimer = new Timer(
            DeadlineWakeTimerCallback,
            new DeadlineWakeTimerState(inbox.Writer, shardIndex, metricsRegistration),
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
        ReadOnlyMemory<byte> streamData,
        ReadOnlyMemory<byte> streamDataSuffix = default)
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
            streamData,
            streamDataSuffix));
    }

    /// <summary>
    /// Starts the shard consumer loop and returns the task that represents its lifetime.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionHandle, QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionHandle, QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default,
        Action<QuicConnectionHandle, QuicConnectionSendDatagramUpdate>? sendDatagramObserver = null,
        QuicConnectionSendDatagramBatchObserver? sendDatagramBatchObserver = null)
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
            sendDatagramBatchObserver,
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
            try
            {
                await deadlineWakeTimer.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                QuicMetrics.UnregisterRuntimeShard(metricsRegistration);
            }
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
        QuicConnectionSendDatagramBatchObserver? sendDatagramBatchObserver,
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
        bool hasActiveWakeCycle = false;
        bool activeWakeCompletedSynchronously = false;
        var productiveWorkItemsInWakeCycle = 0;
        bool measurePacketRuns = false;
        QuicConnectionRuntime? packetRunRuntime = null;
        var packetRunLength = 0;

        try
        {
            while (true)
            {
                measurePacketRuns = QuicMetrics.RuntimeShardPacketRunMetricsEnabled;
                // CONTEXT: The shard loop drains timer expirations before and after inbox reads because
                // both timer completion and connection work share this single-reader path; that keeps
                // due timers from waiting on a separate wake-up when the shard is already active.
                // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeShard.cs#ConsumeInboxAsync
                // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeDeadlineScheduler.cs#EnqueueDueEntries
                // Drain any timer expirations into the inbox before and after reading so deadlines do not wait for
                // a separate wake-up when the shard is already active.
                EnqueueDueEntries(clock.Ticks);

                // Keep one item as lookahead so ACK finalization is deferred only when the
                // next same-connection packet or stream write is already queued.
                bool hasBufferedWorkItem = false;
                QuicConnectionRuntimeShardWorkItem bufferedWorkItem = default;
                bool finalizeBufferedApplicationAck = false;
                var deferredApplicationAckPacketCount = 0;
                while (hasBufferedWorkItem || reader.TryRead(out bufferedWorkItem))
                {
                    QuicConnectionRuntimeShardWorkItem workItem = bufferedWorkItem;
                    bool finalizePendingApplicationAck = finalizeBufferedApplicationAck;
                    hasBufferedWorkItem = false;
                    finalizeBufferedApplicationAck = false;
                    QuicMetrics.RecordRuntimeShardWorkItemDequeued(metricsRegistration, in workItem);
                    if (IsDeadlineWakeWorkItem(workItem))
                    {
                        deferredApplicationAckPacketCount = 0;
                        RecordPacketRunBoundary("deadline_wake");
                        continue;
                    }

                    bool deferApplicationAckFinalization = false;
                    if (workItem.Kind == QuicConnectionRuntimeShardWorkItemKind.PacketReceived
                        && workItem.Runtime is not null
                        && deferredApplicationAckPacketCount < MaximumDeferredApplicationAckPacketCount)
                    {
                        hasBufferedWorkItem = reader.TryRead(out bufferedWorkItem);
                        if (hasBufferedWorkItem)
                        {
                            deferApplicationAckFinalization = ShouldDeferApplicationAckFinalization(
                                in workItem,
                                in bufferedWorkItem,
                                deferredApplicationAckPacketCount,
                                out finalizeBufferedApplicationAck);
                        }
                    }

                    TrackPacketRun(in workItem);
                    productiveWorkItemsInWakeCycle++;
                    ProcessWorkItem(
                        workItem,
                        transitionObserver,
                        effectObserver,
                        sendDatagramObserver,
                        sendDatagramBatchObserver,
                        deferApplicationAckFinalization,
                        finalizePendingApplicationAck);
                    deferredApplicationAckPacketCount = deferApplicationAckFinalization
                        ? deferredApplicationAckPacketCount + 1
                        : 0;
                }

                RecordPacketRunBoundary("drain_end");

                EnqueueDueEntries(clock.Ticks);
                if (reader.TryRead(out QuicConnectionRuntimeShardWorkItem queuedTimerWorkItem))
                {
                    QuicMetrics.RecordRuntimeShardWorkItemDequeued(metricsRegistration, in queuedTimerWorkItem);
                    if (IsDeadlineWakeWorkItem(queuedTimerWorkItem))
                    {
                        RecordPacketRunBoundary("deadline_wake");
                        continue;
                    }

                    TrackPacketRun(in queuedTimerWorkItem);
                    productiveWorkItemsInWakeCycle++;
                    ProcessWorkItem(
                        queuedTimerWorkItem,
                        transitionObserver,
                        effectObserver,
                        sendDatagramObserver,
                        sendDatagramBatchObserver);
                    RecordPacketRunBoundary("single_read");
                    continue;
                }

                if (!deadlineScheduler.TryGetNextWait(clock.Ticks, out TimeSpan wait))
                {
                    if (hasActiveWakeCycle)
                    {
                        QuicMetrics.RecordRuntimeShardWakeCycle(
                            shardIndex,
                            activeWakeCompletedSynchronously,
                            productiveWorkItemsInWakeCycle);
                        hasActiveWakeCycle = false;
                    }

                    ValueTask<bool> waitToRead = reader.WaitToReadAsync();
                    bool completedSynchronously = waitToRead.IsCompletedSuccessfully;
                    if (!await waitToRead.ConfigureAwait(false))
                    {
                        break;
                    }

                    hasActiveWakeCycle = true;
                    activeWakeCompletedSynchronously = completedSynchronously;
                    productiveWorkItemsInWakeCycle = 0;
                    continue;
                }

                if (wait == TimeSpan.Zero)
                {
                    continue;
                }

                deadlineWakeTimer.Change(wait, Timeout.InfiniteTimeSpan);
                if (hasActiveWakeCycle)
                {
                    QuicMetrics.RecordRuntimeShardWakeCycle(
                        shardIndex,
                        activeWakeCompletedSynchronously,
                        productiveWorkItemsInWakeCycle);
                    hasActiveWakeCycle = false;
                }

                ValueTask<bool> timedWaitToRead = reader.WaitToReadAsync();
                bool timedWaitCompletedSynchronously = timedWaitToRead.IsCompletedSuccessfully;
                if (!await timedWaitToRead.ConfigureAwait(false))
                {
                    break;
                }

                hasActiveWakeCycle = true;
                activeWakeCompletedSynchronously = timedWaitCompletedSynchronously;
                productiveWorkItemsInWakeCycle = 0;
                deadlineWakeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            }
        }
        finally
        {
            if (hasActiveWakeCycle)
            {
                QuicMetrics.RecordRuntimeShardWakeCycle(
                    shardIndex,
                    activeWakeCompletedSynchronously,
                    productiveWorkItemsInWakeCycle);
            }

            deadlineWakeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            await cancellationRegistration.DisposeAsync().ConfigureAwait(false);
            while (reader.TryRead(out QuicConnectionRuntimeShardWorkItem workItem))
            {
                QuicMetrics.RecordRuntimeShardWorkItemDequeued(metricsRegistration, in workItem);
                if (IsDeadlineWakeWorkItem(workItem))
                {
                    continue;
                }

                ReleaseWorkItemResources(workItem);
            }
        }

        void TrackPacketRun(in QuicConnectionRuntimeShardWorkItem workItem)
        {
            if (!measurePacketRuns)
            {
                return;
            }

            if (workItem.Kind != QuicConnectionRuntimeShardWorkItemKind.PacketReceived)
            {
                RecordPacketRunBoundary("work_item");
                return;
            }

            if (ReferenceEquals(packetRunRuntime, workItem.Runtime))
            {
                packetRunLength++;
                return;
            }

            RecordPacketRunBoundary("runtime_change");
            packetRunRuntime = workItem.Runtime;
            packetRunLength = 1;
        }

        void RecordPacketRunBoundary(string boundary)
        {
            if (!measurePacketRuns || packetRunLength == 0)
            {
                return;
            }

            QuicMetrics.RecordRuntimeShardPacketRun(shardIndex, packetRunLength, boundary);
            packetRunRuntime = null;
            packetRunLength = 0;
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
        metricsRegistration.BeginEnqueue(in queuedWorkItem);
        if (!inbox.Writer.TryWrite(queuedWorkItem))
        {
            metricsRegistration.CancelEnqueue(in queuedWorkItem);
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
        Action<QuicConnectionHandle, QuicConnectionSendDatagramUpdate>? sendDatagramObserver,
        QuicConnectionSendDatagramBatchObserver? sendDatagramBatchObserver,
        bool deferApplicationAckFinalization = false,
        bool finalizePendingApplicationAck = false)
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
                suppressSendDatagramEffects: suppressHostedTimerEffectObjects
                    && (sendDatagramObserver is not null || sendDatagramBatchObserver is not null),
                enableApplicationDatagramBatches: sendDatagramBatchObserver is not null);
            flushMeasurementStarted = runtime.BeginRuntimeWorkItemFlushMeasurement();

            long transitionStartedTimestamp = QuicMetrics.GetRuntimeShardPhaseStartTimestamp();
            QuicConnectionTransitionResult result = workItem.Kind switch
            {
                QuicConnectionRuntimeShardWorkItemKind.PacketReceived
                    => runtime.TransitionPacketReceived(
                        workItem.PacketReceived,
                        clock.Ticks,
                        deferApplicationAckFinalization),
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
                        workItem.StreamDataSuffix,
                        clock.Ticks,
                        finalizePendingApplicationAck),
                _ => runtime.Transition(workItem.ConnectionEvent!, clock.Ticks),
            };
            transitionObserver?.Invoke(workItem.Handle, result);
            runtime.ApplyPendingHostedTimerUpdates(workItem.Handle, deadlineScheduler);
            QuicMetrics.RecordRuntimeShardPhaseTime(
                shardIndex,
                in workItem,
                "transition",
                transitionStartedTimestamp);

            long effectsStartedTimestamp = QuicMetrics.GetRuntimeShardPhaseStartTimestamp();
            try
            {
                int index = 0;
                while (index < result.EffectCount)
                {
                    QuicConnectionEffect effect = result.GetEffect(index);
                    if (effect is QuicConnectionHostedSendDatagramMarkerEffect)
                    {
                        if (sendDatagramBatchObserver is not null)
                        {
                            int batchCount = 1;
                            while (index + batchCount < result.EffectCount
                                && result.GetEffect(index + batchCount) is QuicConnectionHostedSendDatagramMarkerEffect)
                            {
                                batchCount++;
                            }

                            if (!runtime.TryTakePendingHostedSendDatagramUpdates(
                                    batchCount,
                                    out ReadOnlySpan<QuicConnectionSendDatagramUpdate> updates))
                            {
                                throw new InvalidOperationException(
                                    "The hosted send-datagram markers did not have matching value updates.");
                            }

                            long sendBatchStartedTimestamp = QuicMetrics.GetRuntimeShardPhaseStartTimestamp();
                            try
                            {
                                sendDatagramBatchObserver(workItem.Handle, updates);
                            }
                            finally
                            {
                                QuicMetrics.RecordRuntimeShardPhaseTime(
                                    shardIndex,
                                    in workItem,
                                    "send_datagram_effect",
                                    sendBatchStartedTimestamp);
                                foreach (QuicConnectionSendDatagramUpdate batchUpdate in updates)
                                {
                                    batchUpdate.ReleaseDatagramOwner();
                                }
                            }

                            index += batchCount;
                            continue;
                        }

                        if (!runtime.TryTakePendingHostedSendDatagramUpdate(out QuicConnectionSendDatagramUpdate update))
                        {
                            throw new InvalidOperationException(
                                "The hosted send-datagram marker did not have a matching value update.");
                        }

                        long sendDatagramStartedTimestamp = QuicMetrics.GetRuntimeShardPhaseStartTimestamp();
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
                            QuicMetrics.RecordRuntimeShardPhaseTime(
                                shardIndex,
                                in workItem,
                                "send_datagram_effect",
                                sendDatagramStartedTimestamp);
                            update.ReleaseDatagramOwner();
                        }

                        index++;
                        continue;
                    }

                    long otherEffectStartedTimestamp = QuicMetrics.GetRuntimeShardPhaseStartTimestamp();
                    try
                    {
                        deadlineScheduler.Apply(workItem.Handle, runtime, effect);
                        effectObserver?.Invoke(workItem.Handle, effect);
                    }
                    finally
                    {
                        QuicMetrics.RecordRuntimeShardPhaseTime(
                            shardIndex,
                            in workItem,
                            "other_effect",
                            otherEffectStartedTimestamp);
                    }

                    index++;
                }
            }
            finally
            {
                QuicMetrics.RecordRuntimeShardPhaseTime(
                    shardIndex,
                    in workItem,
                    "effects",
                    effectsStartedTimestamp);
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

    internal static bool ShouldDeferApplicationAckFinalization(
        in QuicConnectionRuntimeShardWorkItem current,
        in QuicConnectionRuntimeShardWorkItem next,
        int deferredPacketCount,
        out bool finalizeAfterNext)
    {
        finalizeAfterNext = false;
        if (deferredPacketCount >= MaximumDeferredApplicationAckPacketCount
            || current.Kind != QuicConnectionRuntimeShardWorkItemKind.PacketReceived
            || current.Runtime is null
            || !ReferenceEquals(current.Runtime, next.Runtime))
        {
            return false;
        }

        if (next.Kind == QuicConnectionRuntimeShardWorkItemKind.PacketReceived)
        {
            return true;
        }

        if (next.Kind == QuicConnectionRuntimeShardWorkItemKind.StreamWrite)
        {
            finalizeAfterNext = true;
            return true;
        }

        return false;
    }

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
