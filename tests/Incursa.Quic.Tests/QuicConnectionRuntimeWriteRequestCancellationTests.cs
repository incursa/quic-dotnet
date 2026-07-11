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
