namespace Incursa.Quic;

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

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
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
        List<ulong>? streamIds = null;
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (streamFrame.StreamDataLength > 0)
                {
                    AddDistinctStreamId(ref streamIds, streamFrame.StreamId.Value);
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

        return streamIds?.ToArray() ?? [];
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
            || QuicFrameCodec.TryParseAckFrame(remaining, out _, out bytesConsumed)
            || QuicFrameCodec.TryParsePingFrame(remaining, out bytesConsumed)
            || QuicFrameCodec.TryParseStopSendingFrame(remaining, out _, out bytesConsumed)
            || QuicFrameCodec.TryParseResetStreamFrame(remaining, out _, out bytesConsumed))
        {
            return true;
        }

        bytesConsumed = 0;
        return false;
    }

    private static void AddDistinctStreamId(ref List<ulong>? streamIds, ulong streamId)
    {
        streamIds ??= [];
        if (!streamIds.Contains(streamId))
        {
            streamIds.Add(streamId);
        }
    }
}
