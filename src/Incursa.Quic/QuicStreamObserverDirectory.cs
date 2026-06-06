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

    // CONTEXT: observer sets are removed only if the same instance is still empty
    // SEE: code:src/Incursa.Quic/QuicStreamObserverDirectory.cs#TryRemoveIfEmpty
    // The directory re-checks reference identity under the lock because a
    // stream can detach the old set while another thread has already attached a
    // replacement for the same stream ID. Removing by key alone would race and
    // drop the newer set.
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
