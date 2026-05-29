// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeWriteRequestCancellationTests
{
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
