// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS19P3AckFrameTestSupport
{
    internal static QuicAckFrame CreateSinglePacketAckFrame(ulong packetNumber, byte frameType = 0x02)
    {
        return new QuicAckFrame
        {
            FrameType = frameType,
            LargestAcknowledged = packetNumber,
            AckDelay = 0,
            FirstAckRange = 0,
        };
    }

    internal static QuicAckFrame CreateContiguousAckFrame(ulong largestAcknowledged, ulong firstAckRange)
    {
        return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = firstAckRange,
        };
    }

    internal static QuicAckFrame CreateAckFrameWithAdditionalRange(
        ulong largestAcknowledged,
        ulong firstAckRange,
        ulong gap,
        ulong ackRangeLength)
    {
        ulong firstSmallestAcknowledged = largestAcknowledged - firstAckRange;
        return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = firstAckRange,
            AdditionalRanges =
            [
                QuicFrameTestData.BuildAckRange(firstSmallestAcknowledged, gap, ackRangeLength),
            ],
        };
    }

    internal static byte[] FormatAckFrame(QuicAckFrame frame)
    {
        byte[] destination = new byte[512];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, destination, out int bytesWritten));
        return destination[..bytesWritten];
    }

    internal static QuicAckFrame ParseAckFrame(byte[] encoded)
    {
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        return parsed;
    }

    internal static void AssertRejects(byte[] encoded)
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded, out _, out _));
    }

    internal static byte[] BuildPayload(params byte[][] fields)
    {
        int length = fields.Sum(field => field.Length);
        byte[] payload = new byte[length];
        int offset = 0;
        foreach (byte[] field in fields)
        {
            field.CopyTo(payload.AsSpan(offset));
            offset += field.Length;
        }

        return payload;
    }

    internal static byte[] Varint(ulong value)
    {
        return QuicVarintTestData.EncodeMinimal(value);
    }

    internal static byte[] VarintWithLength(ulong value, int encodedLength)
    {
        return QuicVarintTestData.EncodeWithLength(value, encodedLength);
    }

    internal static byte[] MinimalAckFramePayload(ulong largestAcknowledged = 4, ulong ackDelay = 0, ulong firstAckRange = 0)
    {
        return BuildPayload(
            [0x02],
            Varint(largestAcknowledged),
            Varint(ackDelay),
            Varint(0),
            Varint(firstAckRange));
    }

    internal static QuicAckFrame AckFrameFromRanges(ulong largestAcknowledged, ulong firstAckRange, params QuicAckRange[] additionalRanges)
    {
        return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges,
        };
    }

    internal static void RecordSentPackets(QuicSenderFlowController sender, QuicPacketNumberSpace packetNumberSpace, ulong first, ulong last)
    {
        for (ulong packetNumber = first; packetNumber <= last; packetNumber++)
        {
            sender.RecordPacketSent(
                packetNumberSpace,
                packetNumber,
                sentBytes: 1_200,
                sentAtMicros: packetNumber * 1_000,
                ackEliciting: true);
        }
    }
}
