// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

using System.Reflection;

public sealed class QuicConnectionRuntimeWriteRequestCancellationTests
{
    [Fact]
    public async Task TryQueueStreamCapacityRelease_SuppressesDuplicatePendingReleaseEvents()
    {
        await using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        int releaseEventCount = 0;
        QuicConnectionStreamActionEvent? releaseEvent = null;
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.ReleaseCapacity,
                } streamActionEvent)
            {
                releaseEventCount++;
                releaseEvent = streamActionEvent;
            }

            return true;
        });

        runtime.TryQueueStreamCapacityRelease(streamId: 0);
        runtime.TryQueueStreamCapacityRelease(streamId: 0);

        Assert.Equal(1, releaseEventCount);
        Assert.NotNull(releaseEvent);
        Assert.Null(releaseEvent.StreamId);
    }

    [Fact]
    public async Task TryQueueStreamCapacityRelease_SuppressesPendingReleaseEventsForDifferentStreams()
    {
        await using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        int releaseEventCount = 0;
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.ReleaseCapacity,
                })
            {
                releaseEventCount++;
            }

            return true;
        });

        runtime.TryQueueStreamCapacityRelease(streamId: 0);
        runtime.TryQueueStreamCapacityRelease(streamId: 4);

        Assert.Equal(1, releaseEventCount);
    }

    [Fact]
    public async Task TryQueueStreamCapacityRelease_PostsAnotherEventAfterTheScheduledSetIsDrained()
    {
        await using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        int releaseEventCount = 0;
        QuicConnectionStreamActionEvent? firstReleaseEvent = null;
        QuicConnectionStreamActionEvent? secondReleaseEvent = null;
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.ReleaseCapacity,
                } releaseEvent)
            {
                releaseEventCount++;
                if (firstReleaseEvent is null)
                {
                    firstReleaseEvent = releaseEvent;
                }
                else
                {
                    secondReleaseEvent = releaseEvent;
                }
            }

            return true;
        });

        runtime.TryQueueStreamCapacityRelease(streamId: 0);
        Assert.Equal(1, releaseEventCount);

        MethodInfo drainMethod = typeof(QuicConnectionRuntime).GetMethod(
            "TryDeferScheduledPeerStreamCapacityReleases",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        Assert.True((bool)drainMethod.Invoke(runtime, null)!);

        runtime.TryQueueStreamCapacityRelease(streamId: 4);

        Assert.Equal(2, releaseEventCount);
        Assert.Same(firstReleaseEvent, secondReleaseEvent);
    }

    [Fact]
    public async Task TransitionStreamCapacityRelease_ArmsRecoveryForTheMaxStreamsPacket()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionStreamState state = runtime.StreamRegistry.Bookkeeping;

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 1, streamData: []),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryAbortLocalStreamWrites(1, out _, out errorCode));
        Assert.Equal(default, errorCode);
        ulong originalLimit = state.IncomingBidirectionalStreamLimit;

        runtime.TryQueueStreamCapacityRelease(streamId: 1);
        QuicConnectionTransitionResult result = runtime.TransitionStreamCapacityRelease(nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(originalLimit + 1, state.IncomingBidirectionalStreamLimit);
        Assert.Contains(result.Effects, static effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(
            result.Effects,
            static effect => effect is QuicConnectionArmTimerEffect
            {
                TimerKind: QuicConnectionTimerKind.Recovery,
            });
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery).HasValue);
    }

    [Fact]
    public async Task TryQueueStreamCapacityRelease_AllowsRetryAfterPostFailure()
    {
        await using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.SetLocalApiEventDispatcher(_ => false);

        runtime.TryQueueStreamCapacityRelease(streamId: 0);

        int releaseEventCount = 0;
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.ReleaseCapacity,
                })
            {
                releaseEventCount++;
            }

            return true;
        });

        runtime.TryQueueStreamCapacityRelease(streamId: 0);

        Assert.Equal(1, releaseEventCount);
    }

    [Fact]
    public async Task WriteStreamAsync_ObservesCancellationWhileTheRequestIsPending()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        TaskCompletionSource writePosted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                })
            {
                writePosted.TrySetResult();
            }

            return true;
        });

        using CancellationTokenSource cancellation = new();
        Task writeTask = runtime.WriteStreamAsync(streamId.Value, new byte[] { 0x21, 0x22 }, cancellation.Token).AsTask();

        await writePosted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await cancellation.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() => writeTask);
    }

    [Fact]
    public async Task WriteStreamAsync_CompletionActionRunsBeforeDelayedValueTaskConsumption()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Queue<QuicConnectionStreamActionEvent> postedWrites = new();
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                } writeEvent)
            {
                postedWrites.Enqueue(writeEvent);
            }

            return true;
        });

        int completionCount = 0;
        ValueTask firstWrite = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[] { 0x21 },
            () => completionCount++);
        Assert.False(firstWrite.IsCompleted);

        _ = runtime.Transition(postedWrites.Dequeue());
        Assert.Equal(1, completionCount);

        ValueTask secondWrite = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[] { 0x22 },
            () => completionCount++);
        _ = runtime.Transition(postedWrites.Dequeue());
        await secondWrite;

        ValueTask thirdWrite = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[] { 0x23 },
            () => completionCount++);
        _ = runtime.Transition(postedWrites.Dequeue());
        await thirdWrite;

        Assert.Equal(3, completionCount);
        await firstWrite;
    }

    [Fact]
    public async Task TryWriteStreamAsync_CompletionActionRunsBeforeDelayedValueTaskConsumption()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Queue<QuicConnectionStreamActionEvent> postedWrites = new();
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                } writeEvent)
            {
                postedWrites.Enqueue(writeEvent);
            }

            return true;
        });

        int completionCount = 0;
        ValueTask<bool> firstWrite = runtime.TryWriteStreamAsync(
            streamId.Value,
            new byte[] { 0x51 },
            _ => completionCount++);
        Assert.False(firstWrite.IsCompleted);

        _ = runtime.Transition(postedWrites.Dequeue());
        Assert.Equal(1, completionCount);

        ValueTask<bool> secondWrite = runtime.TryWriteStreamAsync(
            streamId.Value,
            new byte[] { 0x52 },
            _ => completionCount++);
        _ = runtime.Transition(postedWrites.Dequeue());
        Assert.True(await secondWrite);

        ValueTask<bool> thirdWrite = runtime.TryWriteStreamAsync(
            streamId.Value,
            new byte[] { 0x53 },
            _ => completionCount++);
        _ = runtime.Transition(postedWrites.Dequeue());
        Assert.True(await thirdWrite);

        Assert.Equal(3, completionCount);
        Assert.True(await firstWrite);
    }

    [Fact]
    public async Task QuicStreamTryWriteAsync_ReleasesWriteGateBeforeDelayedValueTaskConsumption()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Queue<QuicConnectionStreamActionEvent> postedWrites = new();
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                } writeEvent)
            {
                postedWrites.Enqueue(writeEvent);
            }

            return true;
        });

        QuicStream stream = new(runtime.StreamRegistry.Bookkeeping, streamId.Value, runtime);
        ValueTask<bool> firstWrite = stream.TryWriteAsync(new byte[] { 0x61 }, CancellationToken.None);
        Assert.False(firstWrite.IsCompleted);

        _ = runtime.Transition(postedWrites.Dequeue());

        ValueTask<bool> secondWrite = stream.TryWriteAsync(new byte[] { 0x62 }, CancellationToken.None);
        Assert.False(secondWrite.IsCompleted);
        Assert.Single(postedWrites);

        _ = runtime.Transition(postedWrites.Dequeue());
        Assert.True(await secondWrite);
        Assert.True(await firstWrite);
    }

    [Fact]
    public async Task QuicStreamTryWriteSequenceAsync_PreservesSegmentsAndReleasesGateBeforeConsumption()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Queue<QuicConnectionStreamActionEvent> postedWrites = new();
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                } writeEvent)
            {
                postedWrites.Enqueue(writeEvent);
            }

            return true;
        });

        QuicStream stream = new(runtime.StreamRegistry.Bookkeeping, streamId.Value, runtime);
        ValueTask<bool> firstWrite = stream.TryWriteSequenceAsync(
            new byte[] { 0x00, 0x03 },
            new byte[] { 0x61, 0x62, 0x63 },
            CancellationToken.None);
        Assert.False(firstWrite.IsCompleted);
        QuicConnectionStreamActionEvent firstEvent = postedWrites.Dequeue();
        Assert.True(firstEvent.StreamData.Span.SequenceEqual(new byte[] { 0x00, 0x03 }));
        Assert.True(firstEvent.StreamDataSuffix.Span.SequenceEqual(new byte[] { 0x61, 0x62, 0x63 }));

        _ = runtime.Transition(firstEvent);

        ValueTask<bool> secondWrite = stream.TryWriteAsync(new byte[] { 0x64 }, CancellationToken.None);
        Assert.False(secondWrite.IsCompleted);
        _ = runtime.Transition(postedWrites.Dequeue());

        Assert.True(await secondWrite);
        Assert.True(await firstWrite);
    }

    [Fact]
    public async Task QuicStreamTryWriteSequenceAsync_ObservesCancellationWhilePending()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        QuicStream stream = new(runtime.StreamRegistry.Bookkeeping, streamId.Value, runtime);
        using CancellationTokenSource cancellation = new();
        ValueTask<bool> write = stream.TryWriteSequenceAsync(
            new byte[] { 0x00, 0x01 },
            new byte[] { 0x61 },
            cancellation.Token);

        await cancellation.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() => write.AsTask());
    }

    [Fact]
    public async Task StreamActionRequestCompletionSource_OwnsBothSequenceSegmentsForRetry()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionRuntime.StreamActionRequestCompletionSource completion = new(runtime);
        completion.Prepare();
        byte[] prefix = [0x00, 0x03];
        byte[] suffix = [0x61, 0x62, 0x63];

        completion.EnsureOwnedStreamData(prefix, suffix);
        prefix.AsSpan().Fill(0xFF);
        suffix.AsSpan().Fill(0xEE);

        Assert.True(completion.HasOwnedStreamData);
        Assert.Equal(5, completion.StreamDataLength);
        Assert.True(completion.GetOwnedStreamDataSpan().SequenceEqual(new byte[] { 0x00, 0x03, 0x61, 0x62, 0x63 }));

        completion.ReleaseOwnedStreamData();
        Assert.False(completion.HasOwnedStreamData);
        Assert.True(completion.GetOwnedStreamDataSpan().IsEmpty);
    }

    [Fact]
    public async Task QuicStreamTryWriteFinalAsync_CompletesWritesBeforeDelayedValueTaskConsumption()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        Queue<QuicConnectionStreamActionEvent> postedWrites = new();
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent writeEvent
                && writeEvent.ActionKind is QuicConnectionStreamActionKind.Write
                    or QuicConnectionStreamActionKind.Finish)
            {
                postedWrites.Enqueue(writeEvent);
            }

            return true;
        });

        QuicStream stream = new(runtime.StreamRegistry.Bookkeeping, streamId.Value, runtime);
        ValueTask<bool> finalWrite = stream.TryWriteFinalAsync(new byte[] { 0x71 }, CancellationToken.None);
        Assert.False(finalWrite.IsCompleted);
        Assert.False(stream.WritesClosed.IsCompleted);

        _ = runtime.Transition(postedWrites.Dequeue());

        Assert.True(stream.WritesClosed.IsCompletedSuccessfully);
        Assert.True(await finalWrite);
    }

    [Fact]
    public async Task QuicStreamTryWriteFinalAsync_DoesNotCompleteWritesWhenCanceled()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        QuicStream stream = new(runtime.StreamRegistry.Bookkeeping, streamId.Value, runtime);
        using CancellationTokenSource cancellation = new();
        ValueTask<bool> finalWrite = stream.TryWriteFinalAsync(new byte[] { 0x72 }, cancellation.Token);

        await cancellation.CancelAsync();

        Assert.False(stream.WritesClosed.IsCompleted);
        await Assert.ThrowsAsync<OperationCanceledException>(() => finalWrite.AsTask());
    }

    [Fact]
    public async Task WriteStreamAsync_CompletionActionRunsBeforeCancellationIsObserved()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        using CancellationTokenSource cancellation = new();
        int completionCount = 0;
        ValueTask writeTask = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[] { 0x31 },
            () => completionCount++,
            cancellation.Token);

        await cancellation.CancelAsync();

        Assert.Equal(1, completionCount);
        await Assert.ThrowsAsync<OperationCanceledException>(() => writeTask.AsTask());
    }

    [Fact]
    public async Task TryWriteStreamAsync_CompletionActionRunsBeforeCancellationIsObserved()
    {
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        using CancellationTokenSource cancellation = new();
        int completionCount = 0;
        ValueTask<bool> writeTask = runtime.TryWriteStreamAsync(
            streamId.Value,
            new byte[] { 0x61 },
            _ => completionCount++,
            cancellation.Token);

        await cancellation.CancelAsync();

        Assert.Equal(1, completionCount);
        await Assert.ThrowsAsync<OperationCanceledException>(() => writeTask.AsTask());
    }

    [Fact]
    public async Task WriteStreamAsync_CompletionActionRunsBeforeDisposalIsObserved()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        int completionCount = 0;
        ValueTask writeTask = runtime.WriteStreamAsync(
            streamId.Value,
            new byte[] { 0x41 },
            () => completionCount++);

        await runtime.DisposeAsync();

        Assert.Equal(1, completionCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => writeTask.AsTask());
    }

    [Fact]
    public async Task TryWriteStreamAsync_CompletionActionRunsBeforeDisposalIsObserved()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        runtime.SetLocalApiEventDispatcher(_ => true);
        int completionCount = 0;
        ValueTask<bool> writeTask = runtime.TryWriteStreamAsync(
            streamId.Value,
            new byte[] { 0x71 },
            _ => completionCount++);

        await runtime.DisposeAsync();

        Assert.Equal(1, completionCount);
        Assert.False(await writeTask);
    }

    [Fact]
    public async Task WriteStreamAsync_PublicWriteStillThrowsWhenPendingWriteIsCompletedByRuntimeDisposal()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        TaskCompletionSource writePosted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                })
            {
                writePosted.TrySetResult();
            }

            return true;
        });

        Task writeTask = runtime.WriteStreamAsync(streamId.Value, new byte[] { 0x31, 0x32 }).AsTask();

        await writePosted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await runtime.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => writeTask);
    }

    [Fact]
    public async Task TryWriteStreamAsync_ReturnsFalseWhenPendingWriteIsCompletedByRuntimeDisposal()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        TaskCompletionSource writePosted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent
                {
                    ActionKind: QuicConnectionStreamActionKind.Write,
                })
            {
                writePosted.TrySetResult();
            }

            return true;
        });

        Task<bool> writeTask = runtime.TryWriteStreamAsync(streamId.Value, new byte[] { 0x41, 0x42 }).AsTask();

        await writePosted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await runtime.DisposeAsync();

        Assert.False(await writeTask);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        // Initialize a sendable active path without going through path-migration validation.
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);

        return runtime;
    }
}
