// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicStreamPayloadRemainderLayout(
    byte FrameType,
    ulong StreamId,
    ulong StreamOffset,
    int StreamDataOffset,
    int StreamDataLength,
    int HeaderLength,
    int PayloadOffset,
    int FrameLength,
    int PayloadLength);

// CONTEXT: The application-send queue needs a packet-size-aware split point for a single queued
// STREAM payload so the runtime can keep large writes moving without reordering later writes.
// SEE: QuicApplicationSendQueue and QuicConnectionRuntime.Streams.cs
internal static class QuicStreamPayloadSizer
{
    internal static bool TryCreateRemainderLayout(
        QuicStreamFrame frame,
        int currentPayloadOffset,
        int fragmentDataLength,
        int minimumPayloadLength,
        int bufferCapacity,
        out QuicStreamPayloadRemainderLayout layout)
    {
        layout = default;
        if (currentPayloadOffset < 0
            || fragmentDataLength <= 0
            || fragmentDataLength >= frame.StreamDataLength
            || minimumPayloadLength < 0
            || bufferCapacity < 0)
        {
            return false;
        }

        ulong fragmentDataLengthValue = checked((ulong)fragmentDataLength);
        if (frame.Offset > QuicVariableLengthInteger.MaxValue - fragmentDataLengthValue)
        {
            return false;
        }

        ulong streamOffset = frame.Offset + fragmentDataLengthValue;
        int streamDataLength = frame.StreamDataLength - fragmentDataLength;
        byte frameType = (byte)(frame.FrameType
            | QuicStreamFrameBits.OffsetBitMask
            | QuicStreamFrameBits.LengthBitMask);
        if (!TryGetOutboundStreamFrameLength(
                frameType,
                frame.StreamId.Value,
                streamOffset,
                streamDataLength,
                out int frameLength))
        {
            return false;
        }

        int currentHeaderLength = frame.ConsumedLength - frame.StreamDataLength;
        long streamDataOffsetValue = (long)currentPayloadOffset + currentHeaderLength + fragmentDataLength;
        if (currentHeaderLength < 0
            || streamDataOffsetValue < 0
            || streamDataOffsetValue > bufferCapacity)
        {
            return false;
        }

        int streamDataOffset = (int)streamDataOffsetValue;
        int headerLength = frameLength - streamDataLength;
        int payloadOffset = streamDataOffset - headerLength;
        int payloadLength = Math.Max(minimumPayloadLength, frameLength);
        if (payloadOffset < 0
            || payloadOffset > bufferCapacity - payloadLength)
        {
            return false;
        }

        layout = new QuicStreamPayloadRemainderLayout(
            frameType,
            frame.StreamId.Value,
            streamOffset,
            streamDataOffset,
            streamDataLength,
            headerLength,
            payloadOffset,
            frameLength,
            payloadLength);
        return true;
    }

    internal static void ApplyRemainderLayout(
        Span<byte> payload,
        QuicStreamPayloadRemainderLayout layout)
    {
        if (layout.HeaderLength < 0
            || layout.StreamDataLength < 0
            || layout.FrameLength < 0
            || layout.PayloadOffset < 0
            || layout.PayloadLength < layout.FrameLength
            || layout.PayloadOffset > payload.Length - layout.PayloadLength
            || layout.StreamDataOffset != layout.PayloadOffset + layout.HeaderLength
            || layout.StreamDataLength != layout.FrameLength - layout.HeaderLength)
        {
            throw new ArgumentOutOfRangeException(nameof(layout));
        }

        ReadOnlySpan<byte> streamData = payload.Slice(layout.StreamDataOffset, layout.StreamDataLength);
        Span<byte> destination = payload.Slice(layout.PayloadOffset, layout.PayloadLength);
        if (!QuicFrameCodec.TryFormatStreamFrame(
                layout.FrameType,
                layout.StreamId,
                layout.StreamOffset,
                streamData,
                destination,
                out int frameBytesWritten)
            || frameBytesWritten != layout.FrameLength)
        {
            throw new InvalidOperationException("The queued stream remainder layout could not be applied.");
        }

        destination[frameBytesWritten..].Clear();
    }

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
