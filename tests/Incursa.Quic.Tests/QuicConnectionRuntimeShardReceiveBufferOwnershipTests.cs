// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeShardReceiveBufferOwnershipTests
{
    [Fact]
    public async Task ShardConsumer_CompletesWhenRunCancellationIsRequested()
    {
        FakeMonotonicClock clock = new(0);
        await using QuicConnectionRuntimeShard shard = new(0, clock);
        using CancellationTokenSource cancellation = new();

        Task consumer = shard.RunAsync(cancellationToken: cancellation.Token);

        await cancellation.CancelAsync();
        await consumer.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ShardConsumer_ReturnsOwnedPacketBufferAfterTransition()
    {
        FakeMonotonicClock clock = new(0);
        using QuicReceiveBufferPool pool = new(bufferSize: 32, ringSize: 1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        await using QuicConnectionRuntimeShard shard = new(0, clock);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));

        TaskCompletionSource<QuicConnectionTransitionResult> processed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task consumer = shard.RunAsync(
            (_, result) => processed.TrySetResult(result),
            cancellationToken: timeout.Token);

        QuicReceiveBufferLease lease = pool.Rent();
        byte[] buffer = lease.Buffer;
        QuicConnectionPacketReceivedEvent packetReceived = new(
            clock.Ticks,
            new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
            buffer.AsMemory(0, 1),
            OwnedDatagramBuffer: buffer,
            OwnedDatagramBufferOwnership: lease.Ownership);

        Assert.True(shard.TryPost(new QuicConnectionHandle(1), runtime, packetReceived));
        lease.TransferToRuntime();

        await processed.Task.WaitAsync(timeout.Token);
        await WaitForReturnAsync(pool, timeout.Token);
        await shard.DisposeAsync();
        await consumer;

        QuicReceiveBufferPoolSnapshot snapshot = pool.Snapshot;
        Assert.Equal(1, snapshot.Returns);
        Assert.Equal(0, snapshot.CurrentOutstanding);
        Assert.Equal(0, snapshot.DoubleReturnAttempts);
    }

    private static async Task WaitForReturnAsync(QuicReceiveBufferPool pool, CancellationToken cancellationToken)
    {
        while (pool.Snapshot.Returns == 0)
        {
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
    }
}
