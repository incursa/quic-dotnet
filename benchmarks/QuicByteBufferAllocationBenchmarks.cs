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

        byte[] buffer = new byte[64];
        if (!QuicFrameCodec.TryFormatStreamFrame(frameType, streamId, offset, payload, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format STREAM frame benchmark payload.");
        }

        return buffer[..bytesWritten].ToArray();
    }
}
