// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
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
    private int serviceContenderStateInvalid;
    private int serviceContenderArithmeticSaturated;
    private long serviceContenderCount;
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

    internal long ServiceContenderCount =>
        Math.Max(0, Volatile.Read(ref serviceContenderCount));

    internal bool ServiceContenderStateValid =>
        Volatile.Read(ref serviceContenderStateInvalid) == 0;

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
            else
            {
                while (inbox.Reader.TryRead(
                    out QuicConnectionRuntimeShardWorkItem workItem))
                {
                    QuicMetrics.RecordRuntimeShardWorkItemDequeued(
                        metricsRegistration,
                        in workItem);
                    if (IsDeadlineWakeWorkItem(workItem))
                    {
                        continue;
                    }

                    try
                    {
                        ReleaseWorkItemResources(workItem);
                    }
                    finally
                    {
                        CompleteActorServiceContenderTracking(
                            in workItem);
                    }
                }
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
        ulong actorWakeSequence = 1;
        uint actorWakePosition = 0;
        QuicActorWakeCompletion actorWakeCompletion =
            QuicActorWakeCompletion.ConsumerStart;
        QuicActorWakeSource actorWakeSource =
            QuicActorWakeSource.ConsumerStart;

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
                        actorWakeSource = QuicActorWakeSource.Deadline;
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
                    actorWakePosition = IncrementSaturating(actorWakePosition);
                    ProcessWorkItem(
                        workItem,
                        transitionObserver,
                        effectObserver,
                        sendDatagramObserver,
                        sendDatagramBatchObserver,
                        deferApplicationAckFinalization,
                        finalizePendingApplicationAck,
                        actorWakeSequence,
                        actorWakePosition,
                        actorWakeCompletion,
                        actorWakeSource,
                        GetPendingWorkItemCount());
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
                        actorWakeSource = QuicActorWakeSource.Deadline;
                        RecordPacketRunBoundary("deadline_wake");
                        continue;
                    }

                    TrackPacketRun(in queuedTimerWorkItem);
                    productiveWorkItemsInWakeCycle++;
                    actorWakePosition = IncrementSaturating(actorWakePosition);
                    ProcessWorkItem(
                        queuedTimerWorkItem,
                        transitionObserver,
                        effectObserver,
                        sendDatagramObserver,
                        sendDatagramBatchObserver,
                        actorWakeSequence: actorWakeSequence,
                        actorWakePosition: actorWakePosition,
                        actorWakeCompletion: actorWakeCompletion,
                        actorWakeSource: actorWakeSource,
                        pendingWorkItemsAfterDequeue:
                            GetPendingWorkItemCount());
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
                    actorWakeSequence = IncrementSaturating(
                        actorWakeSequence);
                    actorWakePosition = 0;
                    actorWakeCompletion = completedSynchronously
                        ? QuicActorWakeCompletion.Synchronous
                        : QuicActorWakeCompletion.Asynchronous;
                    actorWakeSource = QuicActorWakeSource.Inbox;
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
                actorWakeSequence = IncrementSaturating(actorWakeSequence);
                actorWakePosition = 0;
                actorWakeCompletion = timedWaitCompletedSynchronously
                    ? QuicActorWakeCompletion.Synchronous
                    : QuicActorWakeCompletion.Asynchronous;
                actorWakeSource = QuicActorWakeSource.Inbox;
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

                try
                {
                    ReleaseWorkItemResources(workItem);
                }
                finally
                {
                    CompleteActorServiceContenderTracking(in workItem);
                }
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

        ulong GetPendingWorkItemCount()
        {
            long count = metricsRegistration.InboxDepth;
            return count <= 0 ? 0 : (ulong)count;
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
        long enqueuedTimestamp =
            workItem.Runtime?.ActorServiceObservationEnabled == true
                ? Stopwatch.GetTimestamp()
                : QuicMetrics.GetRuntimeShardEnqueueTimestamp(workItem.Kind);
        QuicConnectionRuntimeShardWorkItem queuedWorkItem = workItem with
        {
            EnqueuedTimestamp = enqueuedTimestamp,
        };
        if (queuedWorkItem.Runtime is { } runtime)
        {
            if (runtime.TryBeginActorShardWorkItem(
                    out bool becameServiceContender))
            {
                bool aggregateAccepted =
                    !becameServiceContender
                    || TryIncrementServiceContenderCount();
                if (aggregateAccepted)
                {
                    queuedWorkItem =
                        queuedWorkItem
                            .WithActorServiceContenderTrackingAccepted();
                }
                else
                {
                    _ = runtime.TryCompleteActorShardWorkItem(out _);
                }
            }
            else
            {
                Volatile.Write(
                    ref serviceContenderStateInvalid,
                    1);
                Volatile.Write(
                    ref serviceContenderArithmeticSaturated,
                    1);
            }
        }

        metricsRegistration.BeginEnqueue(in queuedWorkItem);
        if (!inbox.Writer.TryWrite(queuedWorkItem))
        {
            metricsRegistration.CancelEnqueue(in queuedWorkItem);
            CompleteActorServiceContenderTracking(in queuedWorkItem);
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
                new QuicConnectionTimerExpiredEvent(
                    nowTicks,
                    entry.TimerKind,
                    entry.Generation),
                entry.DueTicks);
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
        bool finalizePendingApplicationAck = false,
        ulong actorWakeSequence = 0,
        uint actorWakePosition = 0,
        QuicActorWakeCompletion actorWakeCompletion =
            QuicActorWakeCompletion.ConsumerStart,
        QuicActorWakeSource actorWakeSource =
            QuicActorWakeSource.ConsumerStart,
        ulong pendingWorkItemsAfterDequeue = 0)
    {
        QuicConnectionRuntime? runtime = workItem.Runtime;
        bool observeActorService =
            runtime?.ActorServiceObservationEnabled == true;
        long serviceStartedTimestamp = observeActorService
            ? Stopwatch.GetTimestamp()
            : QuicMetrics.GetRuntimeShardServiceStartTimestamp();
        long serviceStartedClockTicks = observeActorService
            ? clock.Ticks
            : 0;
        bool flushMeasurementStarted = false;
        var effectCount = 0;
        var applicationSendFollowOnCount = 0;
        var flowControlFollowOnCount = 0;
        var streamCapacityFollowOnCount = 0;
        QuicActorContinuationAssessment continuationAssessment = default;
        bool transitionCompleted = false;
        ulong? actorServiceSequence = null;
        bool actorObservationPublished = false;
        QuicActorServiceDisposition actorDisposition =
            QuicActorServiceDisposition.Completed;
        try
        {
            if (runtime is null)
            {
                return;
            }

            if (runtime.IsDisposed
                && workItem.ConnectionEvent
                    is not QuicConnectionLocalCloseRequestedEvent)
            {
                actorDisposition =
                    QuicActorServiceDisposition.SkippedDisposed;
                return;
            }

            if (runtime.IsInboxConsumerRunning)
            {
                actorDisposition =
                    QuicActorServiceDisposition.SkippedIndependentConsumer;
                return;
            }

            runtime.ConfigureHostedTimerEffectSuppression(
                suppressHostedTimerEffectObjects,
                suppressSendDatagramEffects: suppressHostedTimerEffectObjects
                    && (sendDatagramObserver is not null || sendDatagramBatchObserver is not null),
                enableApplicationDatagramBatches:
                    sendDatagramBatchObserver is not null
                    || runtime.ApplicationDatagramBatchPolicy is not null);
            flushMeasurementStarted =
                runtime.BeginRuntimeWorkItemFlushMeasurement(
                    observeActorService);

            if (workItem.Kind == QuicConnectionRuntimeShardWorkItemKind.StreamWrite
                && workItem.EnqueuedTimestamp != 0
                && QuicMetrics.ApplicationSendPressureShadowEnabled)
            {
                runtime.ObserveApplicationSendWorkItemQueueDelay(
                    Stopwatch.GetElapsedTime(workItem.EnqueuedTimestamp).TotalMilliseconds);
            }

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
            transitionCompleted = true;
            effectCount = result.EffectCount;
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
                            bool batchHandoffCompleted = false;
                            try
                            {
                                sendDatagramBatchObserver(workItem.Handle, updates);
                                batchHandoffCompleted = true;
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
                                    batchUpdate.ReleaseDatagramOwner(
                                        batchHandoffCompleted
                                            ? QuicBufferReleaseReason.Completed
                                            : QuicBufferReleaseReason.Failed);
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
                        bool sendDatagramHandoffCompleted = false;
                        try
                        {
                            if (sendDatagramObserver is not null)
                            {
                                sendDatagramObserver(workItem.Handle, update);
                                sendDatagramHandoffCompleted = true;
                            }
                            else if (effectObserver is not null)
                            {
                                effectObserver.Invoke(
                                    workItem.Handle,
                                    update.ToEffect());
                                sendDatagramHandoffCompleted = true;
                            }
                        }
                        finally
                        {
                            QuicMetrics.RecordRuntimeShardPhaseTime(
                                shardIndex,
                                in workItem,
                                "send_datagram_effect",
                                sendDatagramStartedTimestamp);
                            update.ReleaseDatagramOwner(
                                sendDatagramHandoffCompleted
                                    ? QuicBufferReleaseReason.Completed
                                    : QuicBufferReleaseReason.Failed);
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
        catch
        {
            // The assignment is consumed by the post-service work in finally
            // while this exception unwinds.
#pragma warning disable S1854
            actorDisposition = QuicActorServiceDisposition.Faulted;
#pragma warning restore S1854
            throw;
        }
        finally
        {
            if (flushMeasurementStarted)
            {
                runtime!.TakeRuntimeWorkItemFlushMeasurement(
                    out applicationSendFollowOnCount,
                    out flowControlFollowOnCount,
                    out streamCapacityFollowOnCount,
                    out continuationAssessment);
                QuicMetrics.RecordRuntimeFollowOnFlushItems(
                    shardIndex,
                    in workItem,
                    applicationSendFollowOnCount,
                    flowControlFollowOnCount,
                    streamCapacityFollowOnCount);
            }

            QuicMetrics.RecordRuntimeShardServiceTime(shardIndex, in workItem, serviceStartedTimestamp);
            runtime?.ConfigureHostedTimerEffectSuppression(suppress: false);
            if (observeActorService && runtime is not null)
            {
                QuicActorServiceValidity validity =
                    QuicActorServiceValidity.MissingRunnableConnectionCount
                    | QuicActorServiceValidity.MissingOldestShardItemAge
                    | QuicActorServiceValidity.UsefulWorkUnitsUndefined;
                ulong? queueDelayMicros = null;
                if (workItem.EnqueuedTimestamp == 0
                    || workItem.EnqueuedTimestamp > serviceStartedTimestamp)
                {
                    validity |=
                        QuicActorServiceValidity.MissingQueueDelay;
                }
                else
                {
                    queueDelayMicros = GetElapsedMicros(
                        workItem.EnqueuedTimestamp,
                        serviceStartedTimestamp);
                }

                ulong? interServiceGapMicros = null;
                long previousServiceStartedTimestamp =
                    runtime.ExchangeActorServiceStartedTimestamp(
                        serviceStartedTimestamp);
                if (previousServiceStartedTimestamp <= 0
                    || previousServiceStartedTimestamp
                        > serviceStartedTimestamp)
                {
                    validity |=
                        QuicActorServiceValidity.MissingInterServiceGap;
                    if (previousServiceStartedTimestamp
                        > serviceStartedTimestamp)
                    {
                        validity |=
                            QuicActorServiceValidity.TimeDomainOutOfRange;
                    }
                }
                else
                {
                    interServiceGapMicros = GetElapsedMicros(
                        previousServiceStartedTimestamp,
                        serviceStartedTimestamp);
                }

                ulong? deadlineLatenessMicros = null;
                if (GetActorWorkKind(in workItem)
                    == QuicActorWorkKind.Timer)
                {
                    if (workItem.ScheduledDueTicks is { } scheduledDueTicks
                        && scheduledDueTicks >= 0
                        && serviceStartedClockTicks >= scheduledDueTicks)
                    {
                        deadlineLatenessMicros =
                            ConvertStopwatchTicksToMicros(
                                serviceStartedClockTicks
                                - scheduledDueTicks);
                    }
                    else
                    {
                        validity |=
                            QuicActorServiceValidity.MissingDeadlineLateness;
                        if (workItem.ScheduledDueTicks.HasValue)
                        {
                            validity |=
                                QuicActorServiceValidity.TimeDomainOutOfRange;
                        }
                    }
                }

                ulong? serviceContenderCountAtStart =
                    CaptureServiceContenderCount(ref validity);
                ulong? acceptedConnectionWorkItemsAfterCurrent =
                    CaptureAcceptedConnectionWorkItemsAfterCurrent(
                        runtime,
                        ref validity);
                if (!continuationAssessment.IsComplete)
                {
                    validity |=
                        QuicActorServiceValidity
                            .IncompleteContinuationAssessment;
                }

                if (continuationAssessment.HasInvalidState)
                {
                    validity |=
                        QuicActorServiceValidity
                            .ContinuationAssessmentInvalid;
                }

                actorServiceSequence =
                    runtime.GetNextActorServiceObservationSequence();
                QuicActorServiceObservation observation = new(
                    actorServiceSequence.Value,
                    shardIndex,
                    actorWakeSequence,
                    actorWakePosition,
                    actorWakeCompletion,
                    actorWakeSource,
                    GetActorWorkKind(in workItem),
                    actorDisposition,
                    queueDelayMicros,
                    GetElapsedMicros(
                        serviceStartedTimestamp,
                        Stopwatch.GetTimestamp()),
                    pendingWorkItemsAfterDequeue,
                    ToUInt32Saturating(effectCount, ref validity),
                    ToUInt32Saturating(
                        applicationSendFollowOnCount,
                        ref validity),
                    ToUInt32Saturating(
                        flowControlFollowOnCount,
                        ref validity),
                    ToUInt32Saturating(
                        streamCapacityFollowOnCount,
                        ref validity),
                    runtime.Phase,
                    runtime.IsDisposed,
                    validity,
                    interServiceGapMicros,
                    deadlineLatenessMicros,
                    serviceContenderCountAtStart,
                    acceptedConnectionWorkItemsAfterCurrent,
                    continuationAssessment);
                actorObservationPublished =
                    runtime.TryPublishActorServiceObservation(in observation);
            }

            try
            {
                bool resourceReleaseCompleted = false;
                try
                {
                    ReleaseWorkItemResources(workItem);
                    resourceReleaseCompleted = true;
                }
                finally
                {
                    if (transitionCompleted && runtime is not null)
                    {
                        runtime.TryPublishReceiveCreditShadowAtPostServiceBoundary(
                            clock.Ticks,
                            QuicAdaptiveRuntimePostServiceBoundarySource.HostedShard,
                            actorDisposition,
                            actorServiceSequence,
                            actorObservationPublished,
                            resourceReleaseCompleted);
                    }
                }
            }
            finally
            {
                CompleteActorServiceContenderTracking(in workItem);
            }
        }
    }

    private bool TryIncrementServiceContenderCount()
    {
        while (true)
        {
            long current = Volatile.Read(ref serviceContenderCount);
            if (current == long.MaxValue)
            {
                Volatile.Write(ref serviceContenderStateInvalid, 1);
                Volatile.Write(
                    ref serviceContenderArithmeticSaturated,
                    1);
                return false;
            }

            if (Interlocked.CompareExchange(
                    ref serviceContenderCount,
                    current + 1,
                    current)
                == current)
            {
                return true;
            }
        }
    }

    private void CompleteActorServiceContenderTracking(
        in QuicConnectionRuntimeShardWorkItem workItem)
    {
        if (!workItem.ActorServiceContenderTrackingAccepted
            || workItem.Runtime is not { } runtime)
        {
            return;
        }

        if (!runtime.TryCompleteActorShardWorkItem(
                out bool stoppedBeingServiceContender))
        {
            Volatile.Write(ref serviceContenderStateInvalid, 1);
            return;
        }

        if (!stoppedBeingServiceContender)
        {
            return;
        }

        long remaining = Interlocked.Decrement(
            ref serviceContenderCount);
        if (remaining < 0)
        {
            Interlocked.Exchange(ref serviceContenderCount, 0);
            Volatile.Write(ref serviceContenderStateInvalid, 1);
        }
    }

    private ulong? CaptureServiceContenderCount(
        ref QuicActorServiceValidity validity)
    {
        long count = Volatile.Read(ref serviceContenderCount);
        bool stateInvalid =
            Volatile.Read(ref serviceContenderStateInvalid) != 0;
        if (count <= 0 || stateInvalid)
        {
            validity |=
                QuicActorServiceValidity.MissingServiceContenderCount;
            if (stateInvalid)
            {
                validity |=
                    QuicActorServiceValidity.ServiceContenderStateInvalid;
            }

            if (Volatile.Read(
                    ref serviceContenderArithmeticSaturated) != 0)
            {
                validity |=
                    QuicActorServiceValidity.ArithmeticSaturated;
            }

            return null;
        }

        return (ulong)count;
    }

    private ulong? CaptureAcceptedConnectionWorkItemsAfterCurrent(
        QuicConnectionRuntime runtime,
        ref QuicActorServiceValidity validity)
    {
        bool stateInvalid =
            Volatile.Read(ref serviceContenderStateInvalid) != 0;
        if (stateInvalid
            || !runtime.TryCaptureAcceptedActorShardWorkItemsAfterCurrent(
                out ulong acceptedWorkItemsAfterCurrent))
        {
            validity |=
                QuicActorServiceValidity
                    .MissingAcceptedConnectionWorkItemsAfterCurrent;
            if (stateInvalid)
            {
                validity |=
                    QuicActorServiceValidity.ServiceContenderStateInvalid;
            }

            if (Volatile.Read(
                    ref serviceContenderArithmeticSaturated) != 0)
            {
                validity |=
                    QuicActorServiceValidity.ArithmeticSaturated;
            }

            return null;
        }

        return acceptedWorkItemsAfterCurrent;
    }


    private static QuicActorWorkKind GetActorWorkKind(
        in QuicConnectionRuntimeShardWorkItem workItem)
        => workItem.Kind switch
        {
            QuicConnectionRuntimeShardWorkItemKind.Event
                when workItem.ConnectionEvent
                    is QuicConnectionTimerExpiredEvent =>
                QuicActorWorkKind.Timer,
            QuicConnectionRuntimeShardWorkItemKind.Event =>
                QuicActorWorkKind.ConnectionEvent,
            QuicConnectionRuntimeShardWorkItemKind.PacketReceived =>
                QuicActorWorkKind.PacketReceived,
            QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease =>
                QuicActorWorkKind.StreamCapacityRelease,
            QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate =>
                QuicActorWorkKind.FlowControlCreditUpdate,
            QuicConnectionRuntimeShardWorkItemKind.StreamOpen =>
                QuicActorWorkKind.StreamOpen,
            QuicConnectionRuntimeShardWorkItemKind.StreamWrite =>
                QuicActorWorkKind.StreamWrite,
            _ => throw new ArgumentOutOfRangeException(nameof(workItem)),
        };

    private static ulong GetElapsedMicros(
        long startedTimestamp,
        long completedTimestamp)
    {
        if (completedTimestamp <= startedTimestamp)
        {
            return 0;
        }

        long ticks = Stopwatch.GetElapsedTime(
            startedTimestamp,
            completedTimestamp).Ticks;
        return ticks <= 0 ? 0 : (ulong)(ticks / TimeSpan.TicksPerMicrosecond);
    }

    private static ulong ConvertStopwatchTicksToMicros(long ticks)
    {
        if (ticks <= 0)
        {
            return 0;
        }

        ulong positiveTicks = (ulong)ticks;
        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeSeconds = positiveTicks / frequency;
        ulong remainingTicks = positiveTicks % frequency;
        const ulong microsPerSecond = 1_000_000UL;
        if (wholeSeconds > ulong.MaxValue / microsPerSecond)
        {
            return ulong.MaxValue;
        }

        ulong wholeMicros = wholeSeconds * microsPerSecond;
        ulong partialMicros =
            (remainingTicks * microsPerSecond) / frequency;
        return ulong.MaxValue - wholeMicros < partialMicros
            ? ulong.MaxValue
            : wholeMicros + partialMicros;
    }

    private static uint ToUInt32Saturating(
        int value,
        ref QuicActorServiceValidity validity)
    {
        if (value < 0)
        {
            validity |= QuicActorServiceValidity.ArithmeticSaturated;
            return 0;
        }

        return (uint)value;
    }

    private static uint IncrementSaturating(uint value)
        => value == uint.MaxValue ? uint.MaxValue : value + 1;

    private static ulong IncrementSaturating(ulong value)
        => value == ulong.MaxValue ? ulong.MaxValue : value + 1;

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
