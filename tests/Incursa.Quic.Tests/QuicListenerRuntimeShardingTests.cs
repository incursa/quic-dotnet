// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Tests;

public sealed class QuicListenerRuntimeShardingTests
{
    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(4, 4)]
    [InlineData(5, 5)]
    [InlineData(8, 8)]
    [InlineData(9, QuicListener.MaximumDefaultRuntimeShardCount)]
    [InlineData(32, QuicListener.MaximumDefaultRuntimeShardCount)]
    public void Default_runtime_shard_count_is_bounded_by_processor_count(int processorCount, int expected)
    {
        Assert.Equal(expected, QuicListener.SelectDefaultRuntimeShardCount(processorCount));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Default_runtime_shard_count_rejects_nonpositive_processor_count(int processorCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicListener.SelectDefaultRuntimeShardCount(processorCount));
    }

    [Fact]
    public async Task Public_listener_uses_the_bounded_runtime_shard_default()
    {
        QuicListenerOptions options = new()
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [new SslApplicationProtocol("runtime-sharding-test")],
            ListenBacklog = 1,
            ConnectionOptionsCallback = static (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions())
        };

        await using QuicListener listener = await QuicListener.ListenAsync(options);

        Assert.Equal(
            QuicListener.SelectDefaultRuntimeShardCount(Environment.ProcessorCount),
            listener.Host.RuntimeShardCount);
    }
}
