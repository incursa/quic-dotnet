// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicStreamObserverSet
{
    // CONTEXT: observer storage is optimized for the one-observer case
    // SEE: code:src/Incursa.Quic/QuicStreamObserverSet.cs#TryAdd
    // SEE: code:src/Incursa.Quic/QuicStreamObserverSet.cs#TryRemove
    // Most streams never have many observers, so the set keeps a dedicated
    // single-observer fast path and only allocates an array after the second
    // registration. Keep the upgrade/downgrade behavior because it avoids
    // arrays and keeps notifications cheap on the hot path.
    private static readonly ObserverEntry[] EmptyObservers = [];

    private readonly object sync = new();
    private long singleObserverId;
    private Action<QuicStreamNotification>? singleObserver;
    private ObserverEntry[] observers = EmptyObservers;

    internal bool IsEmpty
        => System.Threading.Volatile.Read(ref singleObserver) is null
            && System.Threading.Volatile.Read(ref observers).Length == 0;

    internal bool TryAdd(long observerId, Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        lock (sync)
        {
            Action<QuicStreamNotification>? single = singleObserver;
            if (single is null && observers.Length == 0)
            {
                singleObserverId = observerId;
                System.Threading.Volatile.Write(ref singleObserver, observer);
                return true;
            }

            if (single is not null)
            {
                if (singleObserverId == observerId)
                {
                    return false;
                }

                ObserverEntry[] upgraded =
                [
                    new ObserverEntry(singleObserverId, single),
                    new ObserverEntry(observerId, observer),
                ];
                System.Threading.Volatile.Write(ref observers, upgraded);
                singleObserverId = 0;
                System.Threading.Volatile.Write(ref singleObserver, null);
                return true;
            }

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
            System.Threading.Volatile.Write(ref observers, updated);
            return true;
        }
    }

    internal bool TryRemove(long observerId)
    {
        lock (sync)
        {
            Action<QuicStreamNotification>? single = singleObserver;
            if (single is not null)
            {
                if (singleObserverId != observerId)
                {
                    return false;
                }

                singleObserverId = 0;
                System.Threading.Volatile.Write(ref singleObserver, null);
                return true;
            }

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
                System.Threading.Volatile.Write(ref observers, EmptyObservers);
                return true;
            }

            if (snapshot.Length == 2)
            {
                ObserverEntry remaining = snapshot[1 - removedIndex];
                System.Threading.Volatile.Write(ref observers, EmptyObservers);
                singleObserverId = remaining.ObserverId;
                System.Threading.Volatile.Write(ref singleObserver, remaining.Observer);
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

            System.Threading.Volatile.Write(ref observers, updated);
            return true;
        }
    }

    internal void Notify(QuicStreamNotification notification)
    {
        Action<QuicStreamNotification>? single = System.Threading.Volatile.Read(ref singleObserver);
        if (single is not null)
        {
            InvokeObserver(single, notification);
            return;
        }

        ObserverEntry[] snapshot = System.Threading.Volatile.Read(ref observers);
        for (int index = 0; index < snapshot.Length; index++)
        {
            InvokeObserver(snapshot[index].Observer, notification);
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

    private readonly record struct ObserverEntry(
        long ObserverId,
        Action<QuicStreamNotification> Observer);
}
