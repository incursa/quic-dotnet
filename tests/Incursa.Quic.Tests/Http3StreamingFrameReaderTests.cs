// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

public sealed class Http3StreamingFrameReaderTests
{
    [Fact]
    public void FragmentedDataFrame_EmitsOwnedSegmentsWithoutWholeFrameReassembly()
    {
        byte[] payload = CreatePayload(128 * 1024);
        byte[] encoded = Http3FrameWriter.WriteData(payload);
        using Http3StreamingFrameReader reader = new();
        Queue<Http3StreamingFramePart> parts = [];

        int offset = 0;
        while (offset < encoded.Length)
        {
            int count = Math.Min(997, encoded.Length - offset);
            reader.Read(encoded.AsMemory(offset, count), parts);
            offset += count;
        }

        reader.Complete();
        Assert.Equal(2, parts.Count);
        Assert.All(parts, static part => Assert.True(part.IsData));
        Assert.All(parts, static part => Assert.Equal(64 * 1024, part.Data.Length));
        Assert.Single(parts, static part => part.EndsFrame);
        Assert.True(parts.Last().EndsFrame);
        Assert.All(parts, part => Assert.Equal(payload.Length, part.FramePayloadLength));

        byte[] actual = parts.SelectMany(static part => part.Data.ToArray()).ToArray();
        encoded.AsSpan().Fill(0xFF);
        Assert.Equal(payload, actual);
        Assert.Equal(payload, parts.SelectMany(static part => part.Data.ToArray()).ToArray());
    }

    [Fact]
    public void FragmentedNonDataFrame_ProducesOneOwnedFrame()
    {
        const ulong frameType = 0x21;
        byte[] payload = CreatePayload(4096);
        byte[] encoded = Http3FrameWriter.WriteFrame(frameType, payload);
        using Http3StreamingFrameReader reader = new();
        Queue<Http3StreamingFramePart> parts = [];

        foreach (byte value in encoded)
        {
            reader.Read(new[] { value }, parts);
        }

        reader.Complete();
        Http3StreamingFramePart part = Assert.Single(parts);
        Assert.False(part.IsData);
        Http3UnknownFrame frame = Assert.IsType<Http3UnknownFrame>(part.Frame);
        encoded.AsSpan().Fill(0xFF);
        Assert.Equal(frameType, frame.Type);
        Assert.Equal(payload, frame.Payload);
    }

    [Fact]
    public void EmptyAndFragmentedDataFrames_PreserveFrameBoundariesAndOrdering()
    {
        byte[] first = Http3FrameWriter.WriteData([]);
        byte[] secondPayload = "second"u8.ToArray();
        byte[] second = Http3FrameWriter.WriteData(secondPayload);
        byte[] encoded = [.. first, .. second];
        using Http3StreamingFrameReader reader = new();
        Queue<Http3StreamingFramePart> parts = [];

        reader.Read(encoded.AsMemory(0, 3), parts);
        reader.Read(encoded.AsMemory(3), parts);
        reader.Complete();

        Assert.Equal(2, parts.Count);
        Http3StreamingFramePart empty = parts.Dequeue();
        Assert.True(empty.IsData);
        Assert.True(empty.EndsFrame);
        Assert.Empty(empty.Data.ToArray());
        Assert.Equal(0, empty.FramePayloadLength);
        Http3StreamingFramePart data = parts.Dequeue();
        Assert.True(data.IsData);
        Assert.True(data.EndsFrame);
        Assert.Equal(secondPayload, data.Data.ToArray());
        Assert.Equal(secondPayload.Length, data.FramePayloadLength);
    }

    [Fact]
    public void ReleasedDataSegment_IsNotReturnedAgainDuringDispose()
    {
        byte[] payload = CreatePayload(777);
        byte[] encoded = Http3FrameWriter.WriteData(payload);
        using Http3StreamingFrameReader reader = new();
        Queue<Http3StreamingFramePart> parts = [];
        reader.Read(encoded, parts);

        Http3StreamingFramePart part = Assert.Single(parts);
        reader.ReleaseData(part.Data);

        Assert.Throws<InvalidOperationException>(() => reader.ReleaseData(part.Data));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Complete_RejectsTruncatedFrame(int retainedBytes)
    {
        byte[] encoded = Http3FrameWriter.WriteData(CreatePayload(32));
        using Http3StreamingFrameReader reader = new();
        Queue<Http3StreamingFramePart> parts = [];
        reader.Read(encoded.AsMemory(0, retainedBytes), parts);

        Http3Exception exception = Assert.Throws<Http3Exception>(reader.Complete);

        Assert.Equal(Http3ErrorCode.FrameError, exception.ErrorCode);
    }

    private static byte[] CreatePayload(int length)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index % 251);
        }

        return payload;
    }
}
