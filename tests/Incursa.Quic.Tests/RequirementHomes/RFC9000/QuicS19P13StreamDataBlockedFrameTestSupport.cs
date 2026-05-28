// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS19P13StreamDataBlockedFrameTestSupport
{
    internal const byte StreamDataBlockedFrameType = 0x15;

    internal static byte[] BuildStreamDataBlockedFrame(ulong streamId = 4, ulong maximumStreamData = 16)
        => QuicFrameTestData.BuildStreamDataBlockedFrame(new QuicStreamDataBlockedFrame(streamId, maximumStreamData));

    internal static byte[] BuildStreamDataBlockedFrameWithEncodedType(ReadOnlySpan<byte> encodedType)
    {
        List<byte> bytes = [.. encodedType.ToArray()];
        bytes.AddRange(EncodeVarint(4));
        bytes.AddRange(EncodeVarint(16));
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamDataBlockedFrameWithEncodedStreamId(
        ReadOnlySpan<byte> encodedStreamId,
        ulong maximumStreamData = 16)
    {
        List<byte> bytes = [StreamDataBlockedFrameType];
        bytes.AddRange(encodedStreamId.ToArray());
        bytes.AddRange(EncodeVarint(maximumStreamData));
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamDataBlockedFrameWithTruncatedEncodedStreamId(ReadOnlySpan<byte> encodedStreamId)
    {
        List<byte> bytes = [StreamDataBlockedFrameType];
        bytes.AddRange(encodedStreamId.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamDataBlockedFrameWithEncodedMaximumStreamData(
        ReadOnlySpan<byte> encodedMaximumStreamData,
        ulong streamId = 4)
    {
        List<byte> bytes = [StreamDataBlockedFrameType];
        bytes.AddRange(EncodeVarint(streamId));
        bytes.AddRange(encodedMaximumStreamData.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamDataBlockedFrameWithTrailingFrame(
        ulong streamId = 4,
        ulong maximumStreamData = 16,
        byte trailingFrameType = 0x01)
    {
        byte[] frame = BuildStreamDataBlockedFrame(streamId, maximumStreamData);
        return [.. frame, trailingFrameType];
    }

    internal static byte[] EncodeVarint(ulong value)
    {
        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, destination, out int bytesWritten));
        return destination[..bytesWritten].ToArray();
    }

    internal static void AssertParses(byte[] encoded, ulong expectedStreamId, ulong expectedMaximumStreamData)
    {
        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(
            encoded,
            out QuicStreamDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(expectedStreamId, frame.StreamId);
        Assert.Equal(expectedMaximumStreamData, frame.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    internal static void AssertRejects(byte[] encoded)
    {
        Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(encoded, out _, out _));
    }

    internal static void AssertFormats(QuicStreamDataBlockedFrame frame, byte[] expected)
    {
        Span<byte> destination = stackalloc byte[24];

        Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, destination, out int bytesWritten));
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
