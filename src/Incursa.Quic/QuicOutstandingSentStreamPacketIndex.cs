// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Tracks the number of retained sent packets that carry non-empty STREAM data for each stream.
/// </summary>
internal struct QuicOutstandingSentStreamPacketIndex
{
    private Dictionary<ulong, int>? counts;

    internal readonly int GetCount(ulong streamId)
        => counts is not null && counts.TryGetValue(streamId, out int count)
            ? count
            : 0;

    internal void Add(in QuicConnectionSentPacket packet)
        => Update(packet, increment: true);

    internal void Remove(in QuicConnectionSentPacket packet)
        => Update(packet, increment: false);

    private void Update(in QuicConnectionSentPacket packet, bool increment)
    {
        Span<ulong> inlineStreamIds = stackalloc ulong[4];
        int streamIdCount = QuicFramePayloadInspector.CopyStreamDataStreamIds(
            packet.PlaintextPayload.Span,
            inlineStreamIds,
            out ulong[]? overflowStreamIds);
        if (streamIdCount == 0)
        {
            return;
        }

        if (overflowStreamIds is not null)
        {
            foreach (ulong streamId in overflowStreamIds)
            {
                UpdateCount(streamId, increment);
            }

            return;
        }

        for (int index = 0; index < streamIdCount; index++)
        {
            UpdateCount(inlineStreamIds[index], increment);
        }
    }

    private void UpdateCount(ulong streamId, bool increment)
    {
        if (increment)
        {
            Dictionary<ulong, int> currentCounts = counts ??= [];
            currentCounts[streamId] = currentCounts.TryGetValue(streamId, out int count)
                ? checked(count + 1)
                : 1;
            return;
        }

        if (counts is null || !counts.TryGetValue(streamId, out int existingCount))
        {
            throw new InvalidOperationException("The outstanding sent stream-packet index is inconsistent.");
        }

        if (existingCount == 1)
        {
            counts.Remove(streamId);
        }
        else
        {
            counts[streamId] = existingCount - 1;
        }
    }
}
