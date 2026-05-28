// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicStreamObserverSet
{
    private readonly object sync = new();
    private long singleObserverId;
    private Action<QuicStreamNotification>? singleObserver;
    private Dictionary<long, Action<QuicStreamNotification>>? observers;

    internal bool IsEmpty
    {
        get
        {
            lock (sync)
            {
                return singleObserver is null && (observers is null || observers.Count == 0);
            }
        }
    }

    internal bool TryAdd(long observerId, Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

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

    internal bool TryRemove(long observerId)
    {
        lock (sync)
        {
            if (observers is null)
            {
                if (singleObserver is null || singleObserverId != observerId)
                {
                    return false;
                }

                singleObserverId = 0;
                singleObserver = null;
                return true;
            }

            bool removed = observers.Remove(observerId);
            if (observers.Count == 1)
            {
                using Dictionary<long, Action<QuicStreamNotification>>.Enumerator enumerator = observers.GetEnumerator();
                if (enumerator.MoveNext())
                {
                    KeyValuePair<long, Action<QuicStreamNotification>> remaining = enumerator.Current;
                    singleObserverId = remaining.Key;
                    singleObserver = remaining.Value;
                    observers = null;
                }
            }
            else if (observers.Count == 0)
            {
                observers = null;
            }

            return removed;
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
            // Stream observer failures remain local to the public facade boundary.
        }
    }
}
