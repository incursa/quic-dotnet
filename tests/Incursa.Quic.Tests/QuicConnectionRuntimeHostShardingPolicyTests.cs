// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeHostShardingPolicyTests
{
    [Fact]
    public void ContiguousHandleWindowDistributesEvenlyAcrossRuntimeShards()
    {
        using QuicConnectionRuntimeHost host = new(4);
        int[] connectionsPerShard = new int[host.ShardCount];

        for (int index = 0; index < 32; index++)
        {
            QuicConnectionHandle handle = host.AllocateConnectionHandle();
            connectionsPerShard[host.GetShardIndex(handle)]++;
        }

        Assert.Equal([8, 8, 8, 8], connectionsPerShard);
    }

    [Theory]
    [InlineData(1, 4)]
    [InlineData(3, 4)]
    [InlineData(5, 4)]
    [InlineData(31, 4)]
    [InlineData(33, 4)]
    [InlineData(64, 7)]
    public void ContiguousHandleWindowDistributionDiffersByAtMostOne(int connectionCount, int shardCount)
    {
        using QuicConnectionRuntimeHost host = new(shardCount);
        int[] connectionsPerShard = new int[host.ShardCount];

        for (int index = 0; index < connectionCount; index++)
        {
            QuicConnectionHandle handle = host.AllocateConnectionHandle();
            connectionsPerShard[host.GetShardIndex(handle)]++;
        }

        Assert.InRange(connectionsPerShard.Max() - connectionsPerShard.Min(), 0, 1);
    }

    [Fact]
    public async Task ReusingAHandleAfterUnregistrationPreservesItsDeterministicShard()
    {
        using QuicConnectionRuntimeHost host = new(4);
        QuicConnectionHandle handle = host.AllocateConnectionHandle();
        int expectedShard = host.GetShardIndex(handle);

        for (int iteration = 0; iteration < 3; iteration++)
        {
            QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            Assert.True(host.TryRegisterConnection(handle, runtime));
            Assert.Equal(expectedShard, host.GetShardIndex(handle));
            Assert.True(host.TryUnregisterConnection(handle));
            await runtime.DisposeAsync();
        }
    }
}
