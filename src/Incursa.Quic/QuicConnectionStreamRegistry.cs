// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;

namespace Incursa.Quic;

/// <summary>
/// Owns the connection-scoped stream registry shell while layering over the existing stream bookkeeping helper.
/// </summary>
// CONTEXT: The registry is intentionally separate from the lower-level bookkeeping so the runtime can
// keep connection-owned stream records, last-activity timestamps, and observer-facing state without
// entangling them with the protocol limits that live in QuicConnectionStreamState.
// SEE: code:src/Incursa.Quic/QuicConnectionStreamRegistry.cs#TryTrackStream
// SEE: code:src/Incursa.Quic/QuicConnectionStreamRegistry.cs#TryUpdateLastActivity
internal sealed class QuicConnectionStreamRegistry
{
    private readonly QuicConnectionStreamState bookkeeping;
    private readonly Dictionary<ulong, QuicConnectionStreamRecord> streams = [];

    public QuicConnectionStreamRegistry(QuicConnectionStreamState bookkeeping)
    {
        this.bookkeeping = bookkeeping ?? throw new ArgumentNullException(nameof(bookkeeping));
    }

    public QuicConnectionStreamState Bookkeeping => bookkeeping;

    public IReadOnlyDictionary<ulong, QuicConnectionStreamRecord> Streams => streams;

    public int Count => streams.Count;

    public bool TryTrackStream(QuicConnectionStreamRecord stream)
    {
        if (streams.ContainsKey(stream.StreamId))
        {
            return false;
        }

        streams.Add(stream.StreamId, stream);
        return true;
    }

    public bool TryTrackStream(
        ulong streamId,
        QuicConnectionStreamOwnership ownership,
        QuicConnectionStreamDirection direction,
        long lastActivityTicks)
    {
        return TryTrackStream(new QuicConnectionStreamRecord(streamId, ownership, direction, lastActivityTicks));
    }

    public bool TryUpdateLastActivity(ulong streamId, long lastActivityTicks)
    {
        if (!streams.TryGetValue(streamId, out QuicConnectionStreamRecord stream))
        {
            return false;
        }

        streams[streamId] = stream with { LastActivityTicks = lastActivityTicks };
        return true;
    }

    public bool TryRemoveStream(ulong streamId)
    {
        return streams.Remove(streamId);
    }

    public bool TryGetStream(ulong streamId, out QuicConnectionStreamRecord stream)
    {
        return streams.TryGetValue(streamId, out stream);
    }
}
