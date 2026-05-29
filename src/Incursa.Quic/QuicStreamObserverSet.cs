// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicStreamObserverSet
{
    private static readonly ObserverEntry[] EmptyObservers = [];

    private readonly object sync = new();
    private ObserverEntry[] observers = EmptyObservers;

    internal bool IsEmpty
        => System.Threading.Volatile.Read(ref observers).Length == 0;

    internal bool TryAdd(long observerId, Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

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
            System.Threading.Volatile.Write(ref observers, updated);
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
                System.Threading.Volatile.Write(ref observers, EmptyObservers);
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
