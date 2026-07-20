// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicStreamObserverDirectory
{
    private static readonly ObserverEntry[] EmptyObservers = [];

    private readonly object sync = new();
    private readonly Dictionary<ulong, ObserverSlot> observersByStreamId = [];
    private int distinctStreamCount;

    internal bool IsEmpty
    {
        get
        {
            lock (sync)
            {
                return observersByStreamId.Count == 0;
            }
        }
    }

    internal int DistinctStreamCount
    {
        get => Volatile.Read(ref distinctStreamCount);
    }

    // CONTEXT: observer storage is optimized for the one-observer case.
    // Most stream facades register exactly one runtime observer, so the
    // directory stores that observer inline and only allocates an array after a
    // second observer attaches to the same stream ID.
    internal bool TryAdd(
        ulong streamId,
        long observerId,
        Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        return TryAdd(streamId, observerId, observer, observerTarget: null);
    }

    internal bool TryAdd(
        ulong streamId,
        long observerId,
        IQuicStreamNotificationObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        return TryAdd(streamId, observerId, observerAction: null, observerTarget: observer);
    }

    private bool TryAdd(
        ulong streamId,
        long observerId,
        Action<QuicStreamNotification>? observerAction,
        IQuicStreamNotificationObserver? observerTarget)
    {
        lock (sync)
        {
            if (!observersByStreamId.TryGetValue(streamId, out ObserverSlot slot))
            {
                observersByStreamId.Add(
                    streamId,
                    new ObserverSlot(observerId, observerAction, observerTarget, EmptyObservers));
                Interlocked.Increment(ref distinctStreamCount);
                return true;
            }

            if (slot.HasSingleObserver)
            {
                if (slot.SingleObserverId == observerId)
                {
                    return false;
                }

                ObserverEntry[] upgraded =
                [
                    new ObserverEntry(slot.SingleObserverId, slot.SingleObserverAction, slot.SingleObserverTarget),
                    new ObserverEntry(observerId, observerAction, observerTarget),
                ];

                observersByStreamId[streamId] = new ObserverSlot(0, null, null, upgraded);
                return true;
            }

            ObserverEntry[] snapshot = slot.Observers;
            for (int index = 0; index < snapshot.Length; index++)
            {
                if (snapshot[index].ObserverId == observerId)
                {
                    return false;
                }
            }

            ObserverEntry[] updated = new ObserverEntry[snapshot.Length + 1];
            Array.Copy(snapshot, updated, snapshot.Length);
            updated[^1] = new ObserverEntry(observerId, observerAction, observerTarget);
            observersByStreamId[streamId] = new ObserverSlot(0, null, null, updated);
            return true;
        }
    }

    internal bool TryRemove(ulong streamId, long observerId)
    {
        lock (sync)
        {
            if (!observersByStreamId.TryGetValue(streamId, out ObserverSlot slot))
            {
                return false;
            }

            if (slot.HasSingleObserver)
            {
                if (slot.SingleObserverId != observerId)
                {
                    return false;
                }

                observersByStreamId.Remove(streamId);
                Interlocked.Decrement(ref distinctStreamCount);
                return true;
            }

            ObserverEntry[] snapshot = slot.Observers;
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
                observersByStreamId.Remove(streamId);
                Interlocked.Decrement(ref distinctStreamCount);
                return true;
            }

            if (snapshot.Length == 2)
            {
                ObserverEntry remaining = snapshot[1 - removedIndex];
                observersByStreamId[streamId] = new ObserverSlot(
                    remaining.ObserverId,
                    remaining.ObserverAction,
                    remaining.ObserverTarget,
                    EmptyObservers);
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

            observersByStreamId[streamId] = new ObserverSlot(0, null, null, updated);
            return true;
        }
    }

    internal bool Notify(ulong streamId, QuicStreamNotification notification)
    {
        Action<QuicStreamNotification>? singleAction;
        IQuicStreamNotificationObserver? singleTarget;
        ObserverEntry[] snapshot;

        lock (sync)
        {
            if (!observersByStreamId.TryGetValue(streamId, out ObserverSlot slot))
            {
                return false;
            }

            singleAction = slot.SingleObserverAction;
            singleTarget = slot.SingleObserverTarget;
            snapshot = slot.Observers;
        }

        if (singleAction is not null || singleTarget is not null)
        {
            InvokeObserver(singleAction, singleTarget, notification);
            return true;
        }

        for (int index = 0; index < snapshot.Length; index++)
        {
            InvokeObserver(snapshot[index].ObserverAction, snapshot[index].ObserverTarget, notification);
        }

        return true;
    }

    internal void NotifyAll(QuicStreamNotification notification)
    {
        ObserverSlot[] snapshot;

        lock (sync)
        {
            snapshot = new ObserverSlot[observersByStreamId.Count];
            observersByStreamId.Values.CopyTo(snapshot, 0);
        }

        for (int slotIndex = 0; slotIndex < snapshot.Length; slotIndex++)
        {
            Action<QuicStreamNotification>? singleAction = snapshot[slotIndex].SingleObserverAction;
            IQuicStreamNotificationObserver? singleTarget = snapshot[slotIndex].SingleObserverTarget;
            if (singleAction is not null || singleTarget is not null)
            {
                InvokeObserver(singleAction, singleTarget, notification);
                continue;
            }

            ObserverEntry[] observers = snapshot[slotIndex].Observers;
            for (int observerIndex = 0; observerIndex < observers.Length; observerIndex++)
            {
                InvokeObserver(observers[observerIndex].ObserverAction, observers[observerIndex].ObserverTarget, notification);
            }
        }
    }

    private static void InvokeObserver(
        Action<QuicStreamNotification>? observerAction,
        IQuicStreamNotificationObserver? observerTarget,
        QuicStreamNotification notification)
    {
        try
        {
            if (observerAction is not null)
            {
                observerAction(notification);
            }
            else
            {
                observerTarget!.OnStreamNotification(notification);
            }
        }
        catch
        {
            // Stream observer failures remain local to the public facade boundary.
        }
    }

    private readonly record struct ObserverSlot(
        long SingleObserverId,
        Action<QuicStreamNotification>? SingleObserverAction,
        IQuicStreamNotificationObserver? SingleObserverTarget,
        ObserverEntry[] Observers)
    {
        internal bool HasSingleObserver => SingleObserverAction is not null || SingleObserverTarget is not null;
    }

    private readonly record struct ObserverEntry(
        long ObserverId,
        Action<QuicStreamNotification>? ObserverAction,
        IQuicStreamNotificationObserver? ObserverTarget);
}
