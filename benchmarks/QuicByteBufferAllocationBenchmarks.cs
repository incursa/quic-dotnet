// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks byte-array-heavy QUIC packet and stream buffer shapes observed in Incursa H3 allocation traces.
/// </summary>
[MemoryDiagnoser]
public class QuicByteBufferAllocationBenchmarks
{
    private byte[] singleStreamFrame = [];
    private byte[] firstStreamFrame = [];
    private byte[] secondStreamFrame = [];
    private byte[] readBuffer = [];
    private byte[][] oneKilobyteStreamFrames = [];
    private byte[] fourKilobyteReadBuffer = [];

    /// <summary>
    /// Prepares representative STREAM payloads and read buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        byte[] firstPayload = [0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x53];
        byte[] secondPayload = [0x44, 0x41, 0x54, 0x41];

        singleStreamFrame = FormatStreamFrame(streamId: 0, offset: 0, firstPayload, fin: false);
        firstStreamFrame = FormatStreamFrame(streamId: 0, offset: 0, firstPayload, fin: false);
        secondStreamFrame = FormatStreamFrame(streamId: 0, offset: (ulong)firstPayload.Length, secondPayload, fin: false);
        readBuffer = new byte[firstPayload.Length + secondPayload.Length];

        byte[] oneKilobytePayload = new byte[1024];
        oneKilobyteStreamFrames = new byte[4][];
        for (int index = 0; index < oneKilobyteStreamFrames.Length; index++)
        {
            oneKilobytePayload.AsSpan().Fill((byte)(index + 1));
            oneKilobyteStreamFrames[index] = FormatStreamFrame(
                streamId: 0,
                offset: (ulong)(index * oneKilobytePayload.Length),
                oneKilobytePayload,
                fin: index == oneKilobyteStreamFrames.Length - 1);
        }

        fourKilobyteReadBuffer = new byte[oneKilobytePayload.Length * oneKilobyteStreamFrames.Length];
    }

    /// <summary>
    /// Measures receiving one STREAM payload into the connection stream buffer.
    /// </summary>
    [Benchmark]
    public int StreamReceive_SinglePayloadFrame()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        if (!QuicStreamParser.TryParseStreamFrame(singleStreamFrame, out QuicStreamFrame frame)
            || !state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode)
            || errorCode != default)
        {
            return -1;
        }

        Span<byte> destination = readBuffer.AsSpan(0, frame.StreamDataLength);
        if (!state.TryReadStreamData(
                frame.StreamId.Value,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        return bytesWritten ^ (completed ? 1 : 0) ^ destination[0];
    }

    /// <summary>
    /// Measures receiving two contiguous STREAM payloads into the connection stream buffer.
    /// </summary>
    [Benchmark]
    public int StreamReceive_TwoContiguousPayloadFrames()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        if (!QuicStreamParser.TryParseStreamFrame(firstStreamFrame, out QuicStreamFrame firstFrame)
            || !state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode)
            || errorCode != default
            || !QuicStreamParser.TryParseStreamFrame(secondStreamFrame, out QuicStreamFrame secondFrame)
            || !state.TryReceiveStreamFrame(secondFrame, out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        Span<byte> destination = readBuffer;
        if (!state.TryReadStreamData(
                firstFrame.StreamId.Value,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        return bytesWritten ^ (completed ? 1 : 0) ^ destination[0] ^ destination[^1];
    }

    /// <summary>
    /// Measures four contiguous 1KB STREAM frames, matching packet-sized receive chunks.
    /// </summary>
    [Benchmark]
    public int StreamReceive_FourContiguousOneKilobyteFrames()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        for (int index = 0; index < oneKilobyteStreamFrames.Length; index++)
        {
            if (!QuicStreamParser.TryParseStreamFrame(oneKilobyteStreamFrames[index], out QuicStreamFrame frame)
                || !state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode)
                || errorCode != default)
            {
                return -1;
            }
        }

        Span<byte> destination = fourKilobyteReadBuffer;
        if (!state.TryReadStreamData(
                streamIdValue: 0,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode readErrorCode)
            || readErrorCode != default)
        {
            return -1;
        }

        return bytesWritten ^ (completed ? 1 : 0) ^ destination[0] ^ destination[^1];
    }

    /// <summary>
    /// Measures receiving a duplicate STREAM payload that should not be buffered again.
    /// </summary>
    [Benchmark]
    public int StreamReceive_DuplicatePayloadFrame()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        if (!QuicStreamParser.TryParseStreamFrame(singleStreamFrame, out QuicStreamFrame frame)
            || !state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode)
            || errorCode != default
            || !state.TryReceiveStreamFrame(frame, out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        Span<byte> destination = readBuffer.AsSpan(0, frame.StreamDataLength);
        if (!state.TryReadStreamData(
                frame.StreamId.Value,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        return bytesWritten ^ (completed ? 1 : 0) ^ destination[0];
    }

    /// <summary>
    /// Measures partial reads from one buffered STREAM segment.
    /// </summary>
    [Benchmark]
    public int StreamRead_TwoPartialReads()
    {
        QuicConnectionStreamState state = CreateServerReceiveState();

        if (!QuicStreamParser.TryParseStreamFrame(singleStreamFrame, out QuicStreamFrame frame)
            || !state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode)
            || errorCode != default)
        {
            return -1;
        }

        Span<byte> firstDestination = readBuffer.AsSpan(0, 2);
        if (!state.TryReadStreamData(
                frame.StreamId.Value,
                firstDestination,
                out int firstBytesWritten,
                out bool firstCompleted,
                out _,
                out _,
                out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        Span<byte> secondDestination = readBuffer.AsSpan(2, frame.StreamDataLength - firstBytesWritten);
        if (!state.TryReadStreamData(
                frame.StreamId.Value,
                secondDestination,
                out int secondBytesWritten,
                out bool secondCompleted,
                out _,
                out _,
                out errorCode)
            || errorCode != default)
        {
            return -1;
        }

        return firstBytesWritten
            ^ secondBytesWritten
            ^ (firstCompleted ? 1 : 0)
            ^ (secondCompleted ? 1 : 0)
            ^ firstDestination[0]
            ^ secondDestination[^1];
    }

    private static QuicConnectionStreamState CreateServerReceiveState()
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: 4096,
            InitialConnectionSendLimit: 4096,
            InitialIncomingBidirectionalStreamLimit: 16,
            InitialIncomingUnidirectionalStreamLimit: 16,
            InitialPeerBidirectionalStreamLimit: 16,
            InitialPeerUnidirectionalStreamLimit: 16,
            InitialLocalBidirectionalReceiveLimit: 4096,
            InitialPeerBidirectionalReceiveLimit: 4096,
            InitialPeerUnidirectionalReceiveLimit: 4096,
            InitialLocalBidirectionalSendLimit: 4096,
            InitialLocalUnidirectionalSendLimit: 4096,
            InitialPeerBidirectionalSendLimit: 4096));
    }

    private static byte[] FormatStreamFrame(ulong streamId, ulong offset, ReadOnlySpan<byte> payload, bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        byte[] buffer = new byte[payload.Length + 32];
        if (!QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format STREAM frame benchmark payload.");
        }

        return buffer[..bytesWritten].ToArray();
    }
}
