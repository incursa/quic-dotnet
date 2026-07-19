// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares rebuilding an oversized queued STREAM remainder with advancing its header in the existing owner.
/// </summary>
[MemoryDiagnoser]
public class QuicStreamRemainderLayoutBenchmarks
{
    private const int FragmentDataLength = 1_140;
    private const int MinimumPayloadLength = 20;
    private byte[] streamData = [];
    private byte[] queuedPayload = [];
    private QuicStreamPayloadRemainderLayout remainderLayout;

    /// <summary>
    /// Gets or sets the original STREAM data length.
    /// </summary>
    [Params(32 * 1024, 64 * 1024)]
    public int StreamDataLength { get; set; }

    /// <summary>
    /// Creates the stable source data and reusable queued owner.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        streamData = GC.AllocateUninitializedArray<byte>(StreamDataLength);
        for (int index = 0; index < streamData.Length; index++)
        {
            streamData[index] = (byte)index;
        }

        queuedPayload = GC.AllocateUninitializedArray<byte>(StreamDataLength + 64);
        if (!QuicFrameCodec.TryFormatStreamFrame(
                (byte)(QuicStreamFrameBits.StreamFrameTypeMinimum
                    | QuicStreamFrameBits.LengthBitMask
                    | QuicStreamFrameBits.FinBitMask),
                streamId: 7,
                offset: 0,
                streamData,
                queuedPayload,
                out int queuedPayloadLength)
            || !QuicStreamParser.TryParseStreamFrame(
                queuedPayload.AsSpan(0, queuedPayloadLength),
                out QuicStreamFrame frame)
            || !QuicStreamPayloadSizer.TryCreateRemainderLayout(
                frame,
                currentPayloadOffset: 0,
                FragmentDataLength,
                MinimumPayloadLength,
                queuedPayload.Length,
                out remainderLayout))
        {
            throw new InvalidOperationException("The benchmark STREAM remainder layout could not be created.");
        }
    }

    /// <summary>
    /// Measures the previous path that rented an owner and copied the full unsent tail.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int RentAndRebuildRemainder()
    {
        byte[] remainderPayload = QuicBufferPool.RentBytes(remainderLayout.PayloadLength);
        try
        {
            if (!QuicFrameCodec.TryFormatStreamFrame(
                    remainderLayout.FrameType,
                    remainderLayout.StreamId,
                    remainderLayout.StreamOffset,
                    queuedPayload.AsSpan(
                        remainderLayout.StreamDataOffset,
                        remainderLayout.StreamDataLength),
                    remainderPayload.AsSpan(0, remainderLayout.PayloadLength),
                    out int frameBytesWritten))
            {
                throw new InvalidOperationException("The benchmark STREAM remainder could not be formatted.");
            }

            remainderPayload.AsSpan(
                frameBytesWritten,
                remainderLayout.PayloadLength - frameBytesWritten).Clear();
            return frameBytesWritten ^ remainderPayload[0] ^ remainderPayload[frameBytesWritten - 1];
        }
        finally
        {
            QuicBufferPool.ReturnBytes(remainderPayload);
        }
    }

    /// <summary>
    /// Measures the current path that writes a new header immediately before the existing unsent data.
    /// </summary>
    [Benchmark]
    public int AdvanceHeaderInExistingOwner()
    {
        QuicStreamPayloadSizer.ApplyRemainderLayout(queuedPayload, remainderLayout);
        return remainderLayout.FrameLength
            ^ queuedPayload[remainderLayout.PayloadOffset]
            ^ queuedPayload[remainderLayout.PayloadOffset + remainderLayout.FrameLength - 1];
    }
}
