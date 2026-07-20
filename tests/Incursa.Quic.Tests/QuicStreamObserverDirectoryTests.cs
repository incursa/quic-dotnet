// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicStreamObserverDirectoryTests
{
    private static readonly Action<QuicStreamNotification> Observer = static _ => { };

    [Fact]
    public void DistinctStreamCount_ChangesOnlyWhenAStreamEntersOrLeavesTheDirectory()
    {
        QuicStreamObserverDirectory directory = new();

        Assert.True(directory.TryAdd(1, 10, Observer));
        Assert.True(directory.TryAdd(1, 11, Observer));
        Assert.True(directory.TryAdd(5, 12, Observer));
        Assert.Equal(2, directory.DistinctStreamCount);

        Assert.True(directory.TryRemove(1, 10));
        Assert.Equal(2, directory.DistinctStreamCount);
        Assert.True(directory.TryRemove(1, 11));
        Assert.Equal(1, directory.DistinctStreamCount);
        Assert.True(directory.TryRemove(5, 12));
        Assert.Equal(0, directory.DistinctStreamCount);
    }

    [Fact]
    public void DistinctStreamCount_RemainsExactDuringConcurrentStreamRegistrationAndRemoval()
    {
        const int StreamCount = 64;
        QuicStreamObserverDirectory directory = new();

        Parallel.For(0, StreamCount, index =>
        {
            Assert.True(directory.TryAdd((ulong)index, index + 1, Observer));
        });
        Assert.Equal(StreamCount, directory.DistinctStreamCount);

        Parallel.For(0, StreamCount, index =>
        {
            Assert.True(directory.TryRemove((ulong)index, index + 1));
        });
        Assert.Equal(0, directory.DistinctStreamCount);
    }
}
