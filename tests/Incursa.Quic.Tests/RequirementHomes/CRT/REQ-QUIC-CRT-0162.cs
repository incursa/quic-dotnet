// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

public sealed class ReqQuicCrt0162
{
    [Fact]
    public void SparseQueuePressureRemainsBatchEligible()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            pressureStreamCount: 4,
            requiredConsecutivePressureTurns: 2);

        Assert.True(policy.ShouldBuildBatch(1));
        Assert.True(policy.ShouldBuildBatch(3));
        Assert.False(policy.IsPromoted);
    }

    [Fact]
    public void OnePressureTurnDoesNotPromoteAndSparseTurnResetsPressure()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            pressureStreamCount: 4,
            requiredConsecutivePressureTurns: 2);

        Assert.True(policy.ShouldBuildBatch(4));
        Assert.True(policy.ShouldBuildBatch(1));
        Assert.True(policy.ShouldBuildBatch(4));
        Assert.False(policy.IsPromoted);
    }

    [Fact]
    public void SustainedPressurePromotesOnceAndNeverReactivatesBatching()
    {
        QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
            pressureStreamCount: 4,
            requiredConsecutivePressureTurns: 2);

        Assert.True(policy.ShouldBuildBatch(4));
        Assert.False(policy.ShouldBuildBatch(4));
        Assert.True(policy.IsPromoted);
        Assert.False(policy.ShouldBuildBatch(1));
        Assert.False(policy.ShouldBuildBatch(0));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    public void InvalidPolicyBoundsAreRejected(
        int pressureStreamCount,
        int requiredConsecutivePressureTurns)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new QuicAdaptiveApplicationDatagramBatchPolicy(
                pressureStreamCount,
                requiredConsecutivePressureTurns));
    }

    [Fact]
    public void RepeatedWritesForOneStreamRemainSparsePressure()
    {
        QuicApplicationSendQueue queue = new();
        try
        {
            for (int index = 0; index < 32; index++)
            {
                queue.Enqueue(
                    streamId: 4,
                    priority: 0,
                    QuicBufferPool.RentBytes(1),
                    streamPayloadLength: 1);
            }

            Span<ulong> distinctStreamIds = stackalloc ulong[4];
            Assert.Equal(1, queue.CountDistinctStreamIdsUpTo(distinctStreamIds));

            QuicAdaptiveApplicationDatagramBatchPolicy policy = new(
                pressureStreamCount: 4,
                requiredConsecutivePressureTurns: 2);
            Assert.True(policy.ShouldBuildBatch(1));
            Assert.True(policy.ShouldBuildBatch(1));
            Assert.False(policy.IsPromoted);
        }
        finally
        {
            queue.Clear();
        }
    }

    [Fact]
    public void DistinctStreamCountingStopsAtThePressureBound()
    {
        QuicApplicationSendQueue queue = new();
        try
        {
            for (ulong streamId = 0; streamId < 16; streamId++)
            {
                queue.Enqueue(
                    streamId,
                    priority: 0,
                    QuicBufferPool.RentBytes(1),
                    streamPayloadLength: 1);
            }

            Span<ulong> distinctStreamIds = stackalloc ulong[4];
            Assert.Equal(4, queue.CountDistinctStreamIdsUpTo(distinctStreamIds));
            Assert.Equal([0UL, 1UL, 2UL, 3UL], distinctStreamIds.ToArray());
        }
        finally
        {
            queue.Clear();
        }
    }
}
