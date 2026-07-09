// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The inspector preserves the common one-stream case without allocating a collection; it
// only materializes a list after a second distinct stream ID appears in the payload.
// SEE: GetStreamDataStreamIds
/// <summary>
/// Inspects packet payloads for frame presence without owning send bookkeeping.
/// </summary>
internal static class QuicFramePayloadInspector
{
    internal static bool ContainsStopSendingFrameForStream(ReadOnlySpan<byte> payload, ulong streamId)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseStopSendingFrame(
                remaining,
                out QuicStopSendingFrame stopSendingFrame,
                out int stopSendingBytesConsumed))
            {
                if (stopSendingFrame.StreamId == streamId)
                {
                    return true;
                }

                offset += stopSendingBytesConsumed;
                continue;
            }

            return false;
        }

        return false;
    }

    internal static ulong[] GetStreamDataStreamIds(ReadOnlySpan<byte> payload)
    {
        Span<ulong> inlineStreamIds = stackalloc ulong[1];
        int streamIdCount = CopyStreamDataStreamIds(payload, inlineStreamIds, out ulong[]? overflowStreamIds);
        if (overflowStreamIds is not null)
        {
            return overflowStreamIds;
        }

        return streamIdCount == 0 ? [] : [inlineStreamIds[0]];
    }

    internal static int CopyStreamDataStreamIds(
        ReadOnlySpan<byte> payload,
        Span<ulong> streamIds,
        out ulong[]? overflowStreamIds)
    {
        overflowStreamIds = null;
        int streamIdCount = 0;
        List<ulong>? overflowStreamIdList = null;
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (streamFrame.StreamDataLength > 0)
                {
                    AddDistinctStreamId(
                        streamFrame.StreamId.Value,
                        streamIds,
                        ref streamIdCount,
                        ref overflowStreamIdList);
                }

                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (TryConsumeNonStreamDataFrame(remaining, out int bytesConsumed))
            {
                offset += bytesConsumed;
                continue;
            }

            break;
        }

        overflowStreamIds = overflowStreamIdList?.ToArray();
        return streamIdCount;
    }

    internal static bool ContainsStreamDataForStream(ReadOnlySpan<byte> payload, ulong streamId)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (streamFrame.StreamId.Value == streamId && streamFrame.StreamDataLength > 0)
                {
                    return true;
                }

                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (TryConsumeNonStreamDataFrame(remaining, out int bytesConsumed))
            {
                offset += bytesConsumed;
                continue;
            }

            return false;
        }

        return false;
    }

    internal static bool ContainsResetStreamFrameForStream(ReadOnlySpan<byte> payload, ulong streamId)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParseResetStreamFrame(
                remaining,
                out QuicResetStreamFrame resetStreamFrame,
                out int resetStreamBytesConsumed))
            {
                if (resetStreamFrame.StreamId == streamId)
                {
                    return true;
                }

                offset += resetStreamBytesConsumed;
                continue;
            }

            if (TryConsumeNonStreamDataFrame(remaining, out int bytesConsumed))
            {
                offset += bytesConsumed;
                continue;
            }

            return false;
        }

        return false;
    }

    private static bool TryConsumeNonStreamDataFrame(ReadOnlySpan<byte> remaining, out int bytesConsumed)
    {
        if (QuicFrameCodec.TryParsePaddingFrame(remaining, out bytesConsumed)
            || QuicFrameCodec.TryConsumeAckFrame(remaining, out bytesConsumed)
            || QuicFrameCodec.TryParsePingFrame(remaining, out bytesConsumed)
            || QuicFrameCodec.TryParseStopSendingFrame(remaining, out _, out bytesConsumed)
            || QuicFrameCodec.TryParseResetStreamFrame(remaining, out _, out bytesConsumed))
        {
            return true;
        }

        bytesConsumed = 0;
        return false;
    }

    private static void AddDistinctStreamId(
        ulong streamId,
        Span<ulong> inlineStreamIds,
        ref int streamIdCount,
        ref List<ulong>? overflowStreamIdList)
    {
        if (overflowStreamIdList is not null)
        {
            if (!overflowStreamIdList.Contains(streamId))
            {
                overflowStreamIdList.Add(streamId);
                streamIdCount++;
            }

            return;
        }

        for (int index = 0; index < streamIdCount; index++)
        {
            if (inlineStreamIds[index] == streamId)
            {
                return;
            }
        }

        if (overflowStreamIdList is null && streamIdCount < inlineStreamIds.Length)
        {
            inlineStreamIds[streamIdCount++] = streamId;
            return;
        }

        overflowStreamIdList = [.. inlineStreamIds[..streamIdCount], streamId];
        streamIdCount++;
    }
}
