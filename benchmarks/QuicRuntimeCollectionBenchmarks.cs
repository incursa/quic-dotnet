// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks connection-runtime collection choices used by stream acceptance and public stream observers.
/// </summary>
[MemoryDiagnoser]
public class QuicRuntimeCollectionBenchmarks
{
    private readonly QuicStreamNotification notification = new(QuicStreamNotificationKind.DataAvailable, Exception: null);
    private ulong[] streamIds = [];
    private int observed;

    /// <summary>
    /// Gets or sets the number of distinct stream IDs processed by each operation.
    /// </summary>
    [Params(64, 256)]
    public int StreamCount { get; set; }

    /// <summary>
    /// Generates deterministic peer stream IDs for the collection operations.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        streamIds = new ulong[StreamCount];
        for (int index = 0; index < streamIds.Length; index++)
        {
            streamIds[index] = (ulong)(index * 4);
        }
    }

    /// <summary>
    /// Measures the former concurrent-dictionary shape used as a stream-ID set.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ConcurrentDictionaryInboundStreamIds()
    {
        ConcurrentDictionary<ulong, byte> queued = new();
        for (int index = 0; index < streamIds.Length; index++)
        {
            queued.TryAdd(streamIds[index], 0);
        }

        return queued.Count;
    }

    /// <summary>
    /// Measures the connection-owned hash-set shape used for stream-ID de-duplication.
    /// </summary>
    [Benchmark]
    public int HashSetInboundStreamIds()
    {
        HashSet<ulong> queued = [];
        for (int index = 0; index < streamIds.Length; index++)
        {
            queued.Add(streamIds[index]);
        }

        return queued.Count;
    }

    /// <summary>
    /// Measures the former concurrent observer directory shape under one observer per stream.
    /// </summary>
    [Benchmark]
    public int ConcurrentDictionaryObserverDirectoryLifecycle()
    {
        observed = 0;
        ConcurrentDictionary<ulong, CopyOnWriteArrayObserverSet> observersByStreamId = new();
        for (int index = 0; index < streamIds.Length; index++)
        {
            ulong streamId = streamIds[index];
            CopyOnWriteArrayObserverSet observers = observersByStreamId.GetOrAdd(streamId, static _ => new CopyOnWriteArrayObserverSet());
            observers.TryAdd(index + 1, Observe);
            observers.Notify(notification);
            observers.TryRemove(index + 1);
            if (observers.IsEmpty)
            {
                observersByStreamId.TryRemove(streamId, out _);
            }
        }

        return observed + observersByStreamId.Count;
    }

    /// <summary>
    /// Measures the connection-owned observer directory under one observer per stream.
    /// </summary>
    [Benchmark]
    public int LockedDictionaryObserverDirectoryLifecycle()
    {
        observed = 0;
        QuicStreamObserverDirectory observersByStreamId = new();
        for (int index = 0; index < streamIds.Length; index++)
        {
            ulong streamId = streamIds[index];
            long observerId = index + 1;
            observersByStreamId.TryAdd(streamId, observerId, Observe);
            observersByStreamId.Notify(streamId, notification);
            observersByStreamId.TryRemove(streamId, observerId);
        }

        return observed + (observersByStreamId.IsEmpty ? 0 : 1);
    }

    /// <summary>
    /// Measures the former copy-on-write observer set shape for the common single-observer lifecycle.
    /// </summary>
    [Benchmark]
    public int CopyOnWriteArrayObserverSetSingleLifecycle()
    {
        observed = 0;
        for (int index = 0; index < streamIds.Length; index++)
        {
            CopyOnWriteArrayObserverSet observers = new();
            observers.TryAdd(index + 1, Observe);
            observers.Notify(notification);
            observers.TryRemove(index + 1);
        }

        return observed;
    }

    /// <summary>
    /// Measures the single-observer fast path in the current observer set.
    /// </summary>
    [Benchmark]
    public int SingleObserverFastPathLifecycle()
    {
        observed = 0;
        for (int index = 0; index < streamIds.Length; index++)
        {
            QuicStreamObserverDirectory observers = new();
            ulong streamId = streamIds[index];
            long observerId = index + 1;
            observers.TryAdd(streamId, observerId, Observe);
            observers.Notify(streamId, notification);
            observers.TryRemove(streamId, observerId);
        }

        return observed;
    }

    private void Observe(QuicStreamNotification _)
        => observed++;

    private sealed class CopyOnWriteArrayObserverSet
    {
        private static readonly ObserverEntry[] EmptyObservers = [];

        private readonly object sync = new();
        private ObserverEntry[] observers = EmptyObservers;

        internal bool IsEmpty => observers.Length == 0;

        internal bool TryAdd(long observerId, Action<QuicStreamNotification> observer)
        {
            lock (sync)
            {
                ObserverEntry[] snapshot = observers;
                for (int index = 0; index < snapshot.Length; index++)
                {
                    if (snapshot[index].ObserverId == observerId)
                    {
                        return false;
                    }
                }

                ObserverEntry[] updated = new ObserverEntry[snapshot.Length + 1];
                Array.Copy(snapshot, updated, snapshot.Length);
                updated[^1] = new ObserverEntry(observerId, observer);
                observers = updated;
                return true;
            }
        }

        internal bool TryRemove(long observerId)
        {
            lock (sync)
            {
                ObserverEntry[] snapshot = observers;
                int removedIndex = -1;
                for (int index = 0; index < snapshot.Length; index++)
                {
                    if (snapshot[index].ObserverId == observerId)
                    {
                        removedIndex = index;
                        break;
                    }
                }

                if (removedIndex < 0)
                {
                    return false;
                }

                if (snapshot.Length == 1)
                {
                    observers = EmptyObservers;
                    return true;
                }

                ObserverEntry[] updated = new ObserverEntry[snapshot.Length - 1];
                if (removedIndex > 0)
                {
                    Array.Copy(snapshot, 0, updated, 0, removedIndex);
                }

                int remainingAfterRemoved = snapshot.Length - removedIndex - 1;
                if (remainingAfterRemoved > 0)
                {
                    Array.Copy(snapshot, removedIndex + 1, updated, removedIndex, remainingAfterRemoved);
                }

                observers = updated;
                return true;
            }
        }

        internal void Notify(QuicStreamNotification notification)
        {
            ObserverEntry[] snapshot = observers;
            for (int index = 0; index < snapshot.Length; index++)
            {
                snapshot[index].Observer(notification);
            }
        }

        private readonly record struct ObserverEntry(
            long ObserverId,
            Action<QuicStreamNotification> Observer);
    }
}
