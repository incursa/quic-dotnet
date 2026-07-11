// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The application-send queue needs a packet-size-aware split point for a single queued
// STREAM payload so the runtime can keep large writes moving without reordering later writes.
// SEE: QuicApplicationSendQueue and QuicConnectionRuntime.Streams.cs
internal static class QuicStreamPayloadSizer
{
    internal static bool TryGetFragmentDataLength(
        ReadOnlySpan<byte> queuedStreamPayload,
        int maximumPayloadBytes,
        out int fragmentDataLength)
    {
        if (!QuicStreamParser.TryParseStreamFrame(queuedStreamPayload, out QuicStreamFrame frame))
        {
            fragmentDataLength = default;
            return false;
        }

        return TryGetFragmentDataLength(frame, maximumPayloadBytes, out fragmentDataLength);
    }

    internal static bool TryGetFragmentDataLength(
        QuicStreamFrame frame,
        int maximumPayloadBytes,
        out int fragmentDataLength)
    {
        fragmentDataLength = default;

        if (maximumPayloadBytes <= 0)
        {
            return false;
        }

        byte fragmentFrameType = (byte)(frame.FrameType & ~QuicStreamFrameBits.FinBitMask);
        if (TryGetOutboundStreamFrameLength(
                fragmentFrameType,
                frame.StreamId.Value,
                frame.Offset,
                frame.StreamDataLength,
                out int fullFrameLength)
            && fullFrameLength <= maximumPayloadBytes)
        {
            fragmentDataLength = frame.StreamDataLength;
            return true;
        }

        int low = 1;
        int high = frame.StreamDataLength - 1;
        int best = 0;

        while (low <= high)
        {
            int candidate = low + ((high - low) >> 1);
            if (TryGetOutboundStreamFrameLength(
                    fragmentFrameType,
                    frame.StreamId.Value,
                    frame.Offset,
                    candidate,
                    out int frameLength)
                && frameLength <= maximumPayloadBytes)
            {
                best = candidate;
                low = candidate + 1;
            }
            else
            {
                high = candidate - 1;
            }
        }

        fragmentDataLength = best;
        return best > 0;
    }

    private static bool TryGetOutboundStreamFrameLength(
        byte frameType,
        ulong streamId,
        ulong offset,
        int streamDataLength,
        out int frameLength)
    {
        frameLength = default;
        if (streamDataLength < 0)
        {
            return false;
        }

        bool hasOffset = (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;
        bool hasLength = (frameType & QuicStreamFrameBits.LengthBitMask) != 0;
        ulong streamDataLengthValue = checked((ulong)streamDataLength);
        if (offset > QuicVariableLengthInteger.MaxValue - streamDataLengthValue
            || !QuicVariableLengthInteger.TryGetEncodedLength(frameType, out int frameTypeLength)
            || !QuicVariableLengthInteger.TryGetEncodedLength(streamId, out int streamIdLength))
        {
            return false;
        }

        int length = checked(frameTypeLength + streamIdLength);
        if (hasOffset)
        {
            if (!QuicVariableLengthInteger.TryGetEncodedLength(offset, out int offsetLength))
            {
                return false;
            }

            length = checked(length + offsetLength);
        }

        if (hasLength)
        {
            if (!QuicVariableLengthInteger.TryGetEncodedLength(streamDataLengthValue, out int streamDataLengthFieldLength))
            {
                return false;
            }

            length = checked(length + streamDataLengthFieldLength);
        }

        frameLength = checked(length + streamDataLength);
        return true;
    }
}
