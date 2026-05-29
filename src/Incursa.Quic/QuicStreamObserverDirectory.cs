// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal sealed class QuicStreamObserverDirectory
{
    private readonly object sync = new();
    private readonly Dictionary<ulong, QuicStreamObserverSet> observersByStreamId = [];

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

    internal QuicStreamObserverSet GetOrAdd(ulong streamId)
    {
        lock (sync)
        {
            if (observersByStreamId.TryGetValue(streamId, out QuicStreamObserverSet? existing))
            {
                return existing;
            }

            QuicStreamObserverSet created = new();
            observersByStreamId.Add(streamId, created);
            return created;
        }
    }

    internal bool TryGetValue(ulong streamId, out QuicStreamObserverSet observers)
    {
        lock (sync)
        {
            bool found = observersByStreamId.TryGetValue(streamId, out QuicStreamObserverSet? candidate);
            observers = candidate!;
            return found;
        }
    }

    internal void TryRemoveIfEmpty(ulong streamId, QuicStreamObserverSet observers)
    {
        if (!observers.IsEmpty)
        {
            return;
        }

        lock (sync)
        {
            if (!observersByStreamId.TryGetValue(streamId, out QuicStreamObserverSet? current)
                || !ReferenceEquals(current, observers)
                || !current.IsEmpty)
            {
                return;
            }

            observersByStreamId.Remove(streamId);
        }
    }

    internal KeyValuePair<ulong, QuicStreamObserverSet>[] Snapshot()
    {
        lock (sync)
        {
            return observersByStreamId.ToArray();
        }
    }
}
