// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the previous STREAM receive buffering shape with pooled segment buffers and reusable merge scratch.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamBufferedSegmentBenchmarks
{
    private byte[] payload = [];

    /// <summary>
    /// Gets or sets the number of STREAM payload chunks buffered before reading.
    /// </summary>
    [Params(64, 1000)]
    public int SegmentCount { get; set; }

    /// <summary>
    /// Gets or sets the payload size for each buffered STREAM chunk.
    /// </summary>
    [Params(1024)]
    public int SegmentLength { get; set; }

    /// <summary>
    /// Prepares a representative STREAM payload chunk.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        payload = new byte[SegmentLength];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index + 1);
        }
    }

    /// <summary>
    /// Baseline equivalent of the previous shape: per-segment byte array plus per-insert list rebuild.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PreviousToArrayAndListRebuild()
    {
        List<PreviousSegment> segments = [];
        int readableBytes = 0;
        for (int index = 0; index < SegmentCount; index++)
        {
            InsertPrevious(segments, (ulong)(index * SegmentLength), payload, ref readableBytes);
        }

        return ReadPrevious(segments) ^ readableBytes;
    }

    /// <summary>
    /// Isolates the previous per-insert list rebuild while keeping the pooled segment buffers.
    /// </summary>
    [Benchmark]
    public int PooledBuffersAndListRebuild()
    {
        List<PooledSegment> segments = [];
        int readableBytes = 0;
        for (int index = 0; index < SegmentCount; index++)
        {
            InsertPooledWithListRebuild(segments, (ulong)(index * SegmentLength), payload, ref readableBytes);
        }

        try
        {
            return ReadPooled(segments) ^ readableBytes;
        }
        finally
        {
            ReleasePooled(segments);
        }
    }

    /// <summary>
    /// Measures the patched shape: pooled segment bytes plus reusable merge scratch.
    /// </summary>
    [Benchmark]
    public int PooledBuffersAndReusableScratch()
    {
        List<PooledSegment> segments = [];
        List<PooledSegment>? scratch = null;
        int readableBytes = 0;
        for (int index = 0; index < SegmentCount; index++)
        {
            InsertPooled(segments, ref scratch, (ulong)(index * SegmentLength), payload, ref readableBytes);
        }

        try
        {
            return ReadPooled(segments) ^ readableBytes;
        }
        finally
        {
            ReleasePooled(segments);
        }
    }

    private static void InsertPrevious(
        List<PreviousSegment> segments,
        ulong offset,
        ReadOnlySpan<byte> data,
        ref int readableBytes)
    {
        ulong currentOffset = offset;
        ulong endOffset = offset + (ulong)data.Length;
        int dataIndex = 0;
        int currentIndex = 0;
        List<PreviousSegment> updated = new(segments.Count + 2);

        while (currentIndex < segments.Count && segments[currentIndex].End <= currentOffset)
        {
            updated.Add(segments[currentIndex++]);
        }

        while (currentIndex < segments.Count && currentOffset < endOffset)
        {
            PreviousSegment existing = segments[currentIndex];
            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(CreatePreviousSegment(currentOffset, data, dataIndex, gapLength));
                    readableBytes += gapLength;
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.Offset < currentOffset)
            {
                ulong skipEnd = Math.Min(existing.End, endOffset);
                if (skipEnd > currentOffset)
                {
                    dataIndex += (int)(skipEnd - currentOffset);
                    currentOffset = skipEnd;
                }
            }

            updated.Add(existing);
            currentIndex++;
        }

        if (currentOffset < endOffset)
        {
            int tailLength = (int)(endOffset - currentOffset);
            updated.Add(CreatePreviousSegment(currentOffset, data, dataIndex, tailLength));
            readableBytes += tailLength;
        }

        while (currentIndex < segments.Count)
        {
            updated.Add(segments[currentIndex++]);
        }

        segments.Clear();
        segments.AddRange(updated);
    }

    private static void InsertPooledWithListRebuild(
        List<PooledSegment> segments,
        ulong offset,
        ReadOnlySpan<byte> data,
        ref int readableBytes)
    {
        ulong currentOffset = offset;
        ulong endOffset = offset + (ulong)data.Length;
        int dataIndex = 0;
        int currentIndex = 0;
        List<PooledSegment> updated = new(segments.Count + 2);

        while (currentIndex < segments.Count && segments[currentIndex].End <= currentOffset)
        {
            updated.Add(segments[currentIndex++]);
        }

        while (currentIndex < segments.Count && currentOffset < endOffset)
        {
            PooledSegment existing = segments[currentIndex];
            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(CreatePooledSegment(currentOffset, data, dataIndex, gapLength));
                    readableBytes += gapLength;
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.Offset < currentOffset)
            {
                ulong skipEnd = Math.Min(existing.End, endOffset);
                if (skipEnd > currentOffset)
                {
                    dataIndex += (int)(skipEnd - currentOffset);
                    currentOffset = skipEnd;
                }
            }

            updated.Add(existing);
            currentIndex++;
        }

        if (currentOffset < endOffset)
        {
            int tailLength = (int)(endOffset - currentOffset);
            updated.Add(CreatePooledSegment(currentOffset, data, dataIndex, tailLength));
            readableBytes += tailLength;
        }

        while (currentIndex < segments.Count)
        {
            updated.Add(segments[currentIndex++]);
        }

        segments.Clear();
        segments.AddRange(updated);
    }

    private static void InsertPooled(
        List<PooledSegment> segments,
        ref List<PooledSegment>? scratch,
        ulong offset,
        ReadOnlySpan<byte> data,
        ref int readableBytes)
    {
        ulong currentOffset = offset;
        ulong endOffset = offset + (ulong)data.Length;
        int dataIndex = 0;
        int currentIndex = 0;
        List<PooledSegment> updated = scratch ??= new List<PooledSegment>(segments.Count + 2);
        updated.Clear();
        int expectedUpdatedCount = segments.Count + 2;
        if (updated.Capacity < expectedUpdatedCount)
        {
            updated.Capacity = expectedUpdatedCount;
        }

        while (currentIndex < segments.Count && segments[currentIndex].End <= currentOffset)
        {
            updated.Add(segments[currentIndex++]);
        }

        while (currentIndex < segments.Count && currentOffset < endOffset)
        {
            PooledSegment existing = segments[currentIndex];
            if (existing.Offset > currentOffset)
            {
                ulong gapEnd = Math.Min(existing.Offset, endOffset);
                int gapLength = (int)(gapEnd - currentOffset);
                if (gapLength > 0)
                {
                    updated.Add(CreatePooledSegment(currentOffset, data, dataIndex, gapLength));
                    readableBytes += gapLength;
                    dataIndex += gapLength;
                    currentOffset += (ulong)gapLength;
                }
            }

            if (currentOffset >= endOffset)
            {
                break;
            }

            if (existing.Offset < currentOffset)
            {
                ulong skipEnd = Math.Min(existing.End, endOffset);
                if (skipEnd > currentOffset)
                {
                    dataIndex += (int)(skipEnd - currentOffset);
                    currentOffset = skipEnd;
                }
            }

            updated.Add(existing);
            currentIndex++;
        }

        if (currentOffset < endOffset)
        {
            int tailLength = (int)(endOffset - currentOffset);
            updated.Add(CreatePooledSegment(currentOffset, data, dataIndex, tailLength));
            readableBytes += tailLength;
        }

        while (currentIndex < segments.Count)
        {
            updated.Add(segments[currentIndex++]);
        }

        segments.Clear();
        segments.AddRange(updated);
        updated.Clear();
    }

    private static PreviousSegment CreatePreviousSegment(ulong offset, ReadOnlySpan<byte> data, int dataIndex, int length)
    {
        return new PreviousSegment(offset, data.Slice(dataIndex, length).ToArray());
    }

    private static PooledSegment CreatePooledSegment(ulong offset, ReadOnlySpan<byte> data, int dataIndex, int length)
    {
        byte[] segmentData = QuicBufferPool.RentBytes(length);
        data.Slice(dataIndex, length).CopyTo(segmentData);
        return new PooledSegment(offset, segmentData, length);
    }

    private static int ReadPrevious(List<PreviousSegment> segments)
    {
        int checksum = 0;
        for (int index = 0; index < segments.Count; index++)
        {
            PreviousSegment segment = segments[index];
            checksum ^= segment.Data[segment.DataOffset];
            checksum ^= segment.Data[segment.DataOffset + segment.Length - 1];
        }

        return checksum;
    }

    private static int ReadPooled(List<PooledSegment> segments)
    {
        int checksum = 0;
        for (int index = 0; index < segments.Count; index++)
        {
            PooledSegment segment = segments[index];
            checksum ^= segment.Data[0];
            checksum ^= segment.Data[segment.Length - 1];
        }

        return checksum;
    }

    private static void ReleasePooled(List<PooledSegment> segments)
    {
        for (int index = 0; index < segments.Count; index++)
        {
            segments[index].Release();
        }
    }

    private readonly record struct PreviousSegment(ulong Offset, byte[] Data, int DataOffset, int Length)
    {
        public PreviousSegment(ulong offset, byte[] data)
            : this(offset, data, 0, data.Length)
        {
        }

        public ulong End => Offset + (ulong)Length;
    }

    private readonly record struct PooledSegment(ulong Offset, byte[] Data, int Length)
    {
        public ulong End => Offset + (ulong)Length;

        public void Release()
        {
            QuicBufferPool.ReturnBytes(Data);
        }
    }
}
