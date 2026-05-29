// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks stream observer notification fan-out on the receive notification path.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamObserverSetBenchmarks
{
    private readonly QuicStreamNotification notification = new(QuicStreamNotificationKind.DataAvailable, Exception: null);
    private LockedSnapshotObserverSet lockedObservers = new();
    private QuicStreamObserverSet copyOnWriteObservers = new();
    private int observed;

    /// <summary>
    /// Gets or sets the number of observers registered for the stream.
    /// </summary>
    [Params(1, 4, 16)]
    public int ObserverCount { get; set; }

    /// <summary>
    /// Prepares equivalent observer sets for the old lock-and-snapshot shape and current copy-on-write shape.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        observed = 0;
        lockedObservers = new LockedSnapshotObserverSet();
        copyOnWriteObservers = new QuicStreamObserverSet();

        Action<QuicStreamNotification> observer = Observe;
        for (int index = 0; index < ObserverCount; index++)
        {
            long observerId = index + 1;
            _ = lockedObservers.TryAdd(observerId, observer);
            _ = copyOnWriteObservers.TryAdd(observerId, observer);
        }
    }

    /// <summary>
    /// Measures the prior notification path that acquired a monitor and materialized a multi-observer array snapshot.
    /// </summary>
    [Benchmark(Baseline = true)]
    public void LockedSnapshotNotify()
        => lockedObservers.Notify(notification);

    /// <summary>
    /// Measures the copy-on-write notification path that reads a stable observer array without locking.
    /// </summary>
    [Benchmark]
    public void CopyOnWriteNotify()
        => copyOnWriteObservers.Notify(notification);

    private void Observe(QuicStreamNotification _)
        => observed++;

    private sealed class LockedSnapshotObserverSet
    {
        private readonly object sync = new();
        private long singleObserverId;
        private Action<QuicStreamNotification>? singleObserver;
        private Dictionary<long, Action<QuicStreamNotification>>? observers;

        internal bool TryAdd(long observerId, Action<QuicStreamNotification> observer)
        {
            lock (sync)
            {
                if (singleObserver is null && observers is null)
                {
                    singleObserverId = observerId;
                    singleObserver = observer;
                    return true;
                }

                if (observers is null)
                {
                    observers = new Dictionary<long, Action<QuicStreamNotification>>(capacity: 2)
                    {
                        [singleObserverId] = singleObserver!,
                    };
                    singleObserverId = 0;
                    singleObserver = null;
                }

                return observers.TryAdd(observerId, observer);
            }
        }

        internal void Notify(QuicStreamNotification notification)
        {
            Action<QuicStreamNotification>? single;
            Action<QuicStreamNotification>[]? snapshot;
            lock (sync)
            {
                single = singleObserver;
                snapshot = observers?.Values.ToArray();
            }

            if (single is not null)
            {
                InvokeObserver(single, notification);
                return;
            }

            if (snapshot is null)
            {
                return;
            }

            foreach (Action<QuicStreamNotification> observer in snapshot)
            {
                InvokeObserver(observer, notification);
            }
        }

        private static void InvokeObserver(
            Action<QuicStreamNotification> observer,
            QuicStreamNotification notification)
        {
            try
            {
                observer(notification);
            }
            catch
            {
                // Keep the baseline behavior aligned with the prior implementation.
            }
        }
    }
}
