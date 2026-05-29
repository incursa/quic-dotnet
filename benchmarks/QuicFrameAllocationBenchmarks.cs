// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks allocation-sensitive QUIC ACK/frame parse and format shapes observed in Incursa H3 traces.
/// </summary>
[MemoryDiagnoser]
public class QuicFrameAllocationBenchmarks
{
    private byte[] ackNoAdditionalRanges = [];
    private byte[] ackMultipleRanges = [];
    private byte[] ackEcnNoAdditionalRanges = [];
    private byte[] ackThenStream = [];
    private byte[] singleStream = [];
    private byte[] streamData = [];
    private byte[] destination = [];
    private ulong[]? inspectedStreamIds;
    private QuicAckFrame ackNoAdditionalRangesTemplate = new();
    private QuicAckFrame ackMultipleRangesTemplate = new();
    private QuicAckFrame ackEcnNoAdditionalRangesTemplate = new();

    /// <summary>
    /// Prepares representative ACK payloads and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        ackNoAdditionalRangesTemplate = new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
        };

        ackMultipleRangesTemplate = new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
            AdditionalRanges =
            [
                new QuicAckRange(1, 3, 115, 118),
                new QuicAckRange(0, 1, 112, 113),
                new QuicAckRange(2, 0, 108, 108),
            ],
        };

        ackEcnNoAdditionalRangesTemplate = new QuicAckFrame
        {
            FrameType = 0x03,
            LargestAcknowledged = 128,
            AckDelay = 16,
            FirstAckRange = 7,
            EcnCounts = new QuicEcnCounts(32, 0, 1),
        };

        ackNoAdditionalRanges = FormatAckFrame(ackNoAdditionalRangesTemplate);
        ackMultipleRanges = FormatAckFrame(ackMultipleRangesTemplate);
        ackEcnNoAdditionalRanges = FormatAckFrame(ackEcnNoAdditionalRangesTemplate);

        streamData = [0x48, 0x65, 0x6C, 0x6C, 0x6F];
        byte[] streamDestination = new byte[32];
        if (!QuicFrameCodec.TryFormatStreamFrame(0x0F, 0, 0, streamData, streamDestination, out int streamBytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare STREAM frame benchmark payload.");
        }

        singleStream = streamDestination[..streamBytesWritten].ToArray();

        ackThenStream = new byte[ackNoAdditionalRanges.Length + streamBytesWritten];
        ackNoAdditionalRanges.CopyTo(ackThenStream.AsSpan());
        streamDestination.AsSpan(0, streamBytesWritten).CopyTo(ackThenStream.AsSpan(ackNoAdditionalRanges.Length));

        destination = new byte[128];
    }

    /// <summary>
    /// Measures the common ACK parse path with no additional ACK ranges.
    /// </summary>
    [Benchmark]
    public int ParseAckNoAdditionalRanges()
    {
        return QuicFrameCodec.TryParseAckFrame(ackNoAdditionalRanges, out QuicAckFrame frame, out int bytesConsumed)
            ? bytesConsumed
                ^ unchecked((int)frame.LargestAcknowledged)
                ^ unchecked((int)frame.AckDelay)
                ^ unchecked((int)frame.FirstAckRange)
                ^ frame.AdditionalRanges.Length
            : -1;
    }

    /// <summary>
    /// Measures ACK parse with multiple additional ACK ranges.
    /// </summary>
    [Benchmark]
    public int ParseAckMultipleRanges()
    {
        return QuicFrameCodec.TryParseAckFrame(ackMultipleRanges, out QuicAckFrame frame, out int bytesConsumed)
            ? bytesConsumed
                ^ unchecked((int)frame.LargestAcknowledged)
                ^ unchecked((int)frame.AckDelay)
                ^ unchecked((int)frame.FirstAckRange)
                ^ frame.AdditionalRanges.Length
                ^ unchecked((int)frame.AdditionalRanges[0].SmallestAcknowledged)
            : -1;
    }

    /// <summary>
    /// Measures ACK_ECN parse with no additional ACK ranges.
    /// </summary>
    [Benchmark]
    public int ParseAckEcnNoAdditionalRanges()
    {
        return QuicFrameCodec.TryParseAckFrame(ackEcnNoAdditionalRanges, out QuicAckFrame frame, out int bytesConsumed)
            ? bytesConsumed
                ^ unchecked((int)frame.LargestAcknowledged)
                ^ unchecked((int)(frame.EcnCounts?.Ect0Count ?? 0))
                ^ unchecked((int)(frame.EcnCounts?.EcnCeCount ?? 0))
            : -1;
    }

    /// <summary>
    /// Measures ACK length-only consumption for skip paths that do not need ACK fields.
    /// </summary>
    [Benchmark]
    public int ConsumeAckNoAdditionalRanges()
    {
        return QuicFrameCodec.TryConsumeAckFrame(ackNoAdditionalRanges, out int bytesConsumed)
            ? bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures ACK_ECN length-only consumption for skip paths that do not need ACK fields.
    /// </summary>
    [Benchmark]
    public int ConsumeAckEcnNoAdditionalRanges()
    {
        return QuicFrameCodec.TryConsumeAckFrame(ackEcnNoAdditionalRanges, out int bytesConsumed)
            ? bytesConsumed
            : -1;
    }

    /// <summary>
    /// Measures a representative ACK + STREAM sequence parse handoff.
    /// </summary>
    [Benchmark]
    public int ParseAckThenStreamSequence()
    {
        ReadOnlySpan<byte> remaining = ackThenStream;
        if (!QuicFrameCodec.TryParseAckFrame(remaining, out QuicAckFrame ackFrame, out int ackBytesConsumed))
        {
            return -1;
        }

        remaining = remaining[ackBytesConsumed..];
        if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
        {
            return -1;
        }

        return ackBytesConsumed
            ^ unchecked((int)ackFrame.LargestAcknowledged)
            ^ streamFrame.ConsumedLength
            ^ streamFrame.StreamDataLength;
    }

    /// <summary>
    /// Measures STREAM payload inspection without preceding ACK parsing.
    /// </summary>
    [Benchmark]
    public int InspectSingleStreamDataIds()
    {
        inspectedStreamIds = QuicFramePayloadInspector.GetStreamDataStreamIds(singleStream);
        return inspectedStreamIds.Length == 0
            ? -1
            : inspectedStreamIds.Length ^ unchecked((int)inspectedStreamIds[0]);
    }

    /// <summary>
    /// Measures ACKed STREAM payload inspection for the common one-stream retransmission bookkeeping case.
    /// </summary>
    [Benchmark]
    public int InspectAckThenSingleStreamDataIds()
    {
        inspectedStreamIds = QuicFramePayloadInspector.GetStreamDataStreamIds(ackThenStream);
        return inspectedStreamIds.Length == 0
            ? -1
            : inspectedStreamIds.Length ^ unchecked((int)inspectedStreamIds[0]);
    }

    /// <summary>
    /// Measures ACK frame formatting for the common no-additional-range shape.
    /// </summary>
    [Benchmark]
    public int FormatAckNoAdditionalRanges()
    {
        return QuicFrameCodec.TryFormatAckFrame(ackNoAdditionalRangesTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures ACK frame formatting with multiple additional ranges.
    /// </summary>
    [Benchmark]
    public int FormatAckMultipleRanges()
    {
        return QuicFrameCodec.TryFormatAckFrame(ackMultipleRangesTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static byte[] FormatAckFrame(QuicAckFrame frame)
    {
        byte[] buffer = new byte[128];
        if (!QuicFrameCodec.TryFormatAckFrame(frame, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare ACK frame benchmark payload.");
        }

        return buffer[..bytesWritten].ToArray();
    }
}
