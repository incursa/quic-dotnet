// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

[MemoryDiagnoser]
public class QuicConnectionStreamStateBenchmarks
{
    private const int HoleSegmentLength = 32;
    private const int HoleSegmentCount = 16;
    private const int HoleFillLength = ((HoleSegmentCount * 2) + 1) * HoleSegmentLength;
    private const int BurstSegmentLength = 32;
    private const int BurstSegmentCount = 4;
    private const int BurstCount = 8;
    private const int BurstLength = BurstSegmentLength * BurstSegmentCount;

    private byte[] tailFrame = [];
    private byte[] streamData = [];
    private byte[] holeSegmentData = [];
    private byte[] holeFillingData = [];
    private byte[] burstSegmentData = [];

    [GlobalSetup]
    public void GlobalSetup()
    {
        tailFrame = QuicBenchmarkData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: 1,
            includeOffset: true,
            offset: 32,
            includeLength: true,
            streamData: new byte[32]);
        streamData = new byte[64];
        holeSegmentData = new byte[HoleSegmentLength];
        holeFillingData = new byte[HoleFillLength];
        burstSegmentData = new byte[BurstSegmentLength];
    }

    [Benchmark]
    public ulong ReceiveOutOfOrderTail()
    {
        QuicConnectionStreamState state = CreateState();
        QuicStreamParser.TryParseStreamFrame(tailFrame, out QuicStreamFrame frame);
        state.TryReceiveStreamFrame(frame, out _);
        state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot);
        return snapshot.UniqueBytesReceived;
    }

    [Benchmark]
    public ulong ReceiveHeadAndReadPublishesCredit()
    {
        QuicConnectionStreamState state = CreateState();
        ReadOnlySpan<byte> payload = streamData;
        QuicStreamFrame frame = new(
            0x0F,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: (ulong)payload.Length,
            fin: true,
            payload,
            payload.Length);
        state.TryReceiveStreamFrame(frame, out _);

        Span<byte> destination = stackalloc byte[64];
        state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out _);
        return (ulong)bytesWritten
            + maxDataFrame.MaximumData
            + maxStreamDataFrame.MaximumStreamData
            + (completed ? 1UL : 0UL);
    }

    [Benchmark]
    public ulong ReceiveInterleavedSegmentsThenFillHoles()
    {
        QuicConnectionStreamState state = CreateState(
            connectionReceiveLimit: HoleFillLength * 2,
            peerBidirectionalReceiveLimit: HoleFillLength * 2);

        for (int index = 0; index < HoleSegmentCount; index++)
        {
            ulong offset = (ulong)(((index * 2) + 1) * HoleSegmentLength);
            QuicStreamFrame frame = new(
                0x0E,
                new QuicStreamId(1),
                hasOffset: true,
                offset,
                hasLength: true,
                length: HoleSegmentLength,
                fin: false,
                holeSegmentData,
                HoleSegmentLength);
            if (!state.TryReceiveStreamFrame(frame, out _))
            {
                throw new InvalidOperationException("Failed to seed an interleaved STREAM segment.");
            }
        }

        QuicStreamFrame fillingFrame = new(
            0x0F,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: HoleFillLength,
            fin: true,
            holeFillingData,
            HoleFillLength);
        if (!state.TryReceiveStreamFrame(fillingFrame, out _))
        {
            throw new InvalidOperationException("Failed to fill the interleaved STREAM holes.");
        }

        Span<byte> destination = stackalloc byte[HoleFillLength];
        state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out _);
        state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot);
        return snapshot.UniqueBytesReceived
            + (ulong)snapshot.BufferedReadableBytes
            + (ulong)bytesWritten
            + (completed ? 1UL : 0UL);
    }

    [Benchmark]
    public ulong ReceiveAndDrainRepeatedFourSegmentBursts()
    {
        QuicConnectionStreamState state = CreateState(
            connectionReceiveLimit: BurstLength * BurstCount * 2,
            peerBidirectionalReceiveLimit: BurstLength * BurstCount * 2);
        ulong total = 0;
        Span<byte> destination = stackalloc byte[BurstLength];

        for (int burstIndex = 0; burstIndex < BurstCount; burstIndex++)
        {
            ulong burstOffset = (ulong)(burstIndex * BurstLength);
            for (int segmentIndex = 0; segmentIndex < BurstSegmentCount; segmentIndex++)
            {
                ulong offset = burstOffset + (ulong)(segmentIndex * BurstSegmentLength);
                QuicStreamFrame frame = new(
                    0x0E,
                    new QuicStreamId(1),
                    hasOffset: true,
                    offset,
                    hasLength: true,
                    length: BurstSegmentLength,
                    fin: false,
                    burstSegmentData,
                    BurstSegmentLength);
                if (!state.TryReceiveStreamFrame(frame, out _))
                {
                    throw new InvalidOperationException("Failed to receive a repeated STREAM burst segment.");
                }
            }

            if (!state.TryReadStreamData(
                    1,
                    destination,
                    out int bytesWritten,
                    out _,
                    out _,
                    out _,
                    out _)
                || bytesWritten != BurstLength)
            {
                throw new InvalidOperationException("Failed to drain a repeated STREAM burst.");
            }

            total += (ulong)bytesWritten;
        }

        state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot);
        return total + (ulong)snapshot.BufferedReadableBytes;
    }

    [Benchmark]
    public ulong ReceiveHeadAndEmptyReadDoesNotPublishCredit()
    {
        QuicConnectionStreamState state = CreateState();
        ReadOnlySpan<byte> payload = streamData;
        QuicStreamFrame frame = new(
            0x0E,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: (ulong)payload.Length,
            fin: false,
            payload,
            payload.Length);
        state.TryReceiveStreamFrame(frame, out _);

        state.TryReadStreamData(
            1,
            Span<byte>.Empty,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out _);
        return (ulong)bytesWritten
            + maxDataFrame.MaximumData
            + maxStreamDataFrame.MaximumStreamData
            + (completed ? 1UL : 0UL);
    }

    [Benchmark]
    public ulong ReceiveResetBufferedDataPublishesCredit()
    {
        QuicConnectionStreamState state = CreateState();
        ReadOnlySpan<byte> payload = streamData;
        QuicStreamFrame frame = new(
            0x0E,
            new QuicStreamId(1),
            hasOffset: true,
            offset: 0,
            hasLength: true,
            length: (ulong)payload.Length,
            fin: false,
            payload,
            payload.Length);
        state.TryReceiveStreamFrame(frame, out _);

        state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(1, 0x55, (ulong)payload.Length),
            out QuicMaxDataFrame maxDataFrame,
            out _);
        return maxDataFrame.MaximumData;
    }

    [Benchmark]
    public ulong OpenLocalStreamPublishesStreamsBlockedFrame()
    {
        QuicConnectionStreamState state = CreateState(peerBidirectionalStreamLimit: 1);
        state.TryOpenLocalStream(bidirectional: true, out _, out _);
        state.TryOpenLocalStream(bidirectional: true, out _, out QuicStreamsBlockedFrame blockedFrame);
        return blockedFrame.MaximumStreams;
    }

    [Benchmark]
    public ulong ReserveSendCapacityPublishesDataBlockedFrame()
    {
        QuicConnectionStreamState state = CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _);
        state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out _,
            out _);

        return dataBlockedFrame.MaximumData;
    }

    [Benchmark]
    public ulong ReserveSendCapacityPublishesStreamDataBlockedFrame()
    {
        QuicConnectionStreamState state = CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 1);

        state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _);
        state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out _,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out _);

        return streamDataBlockedFrame.StreamId + streamDataBlockedFrame.MaximumStreamData;
    }

    private static QuicConnectionStreamState CreateState(
        ulong connectionReceiveLimit = 512,
        ulong connectionSendLimit = 512,
        ulong incomingBidirectionalStreamLimit = 4,
        ulong incomingUnidirectionalStreamLimit = 4,
        ulong peerBidirectionalStreamLimit = 4,
        ulong peerUnidirectionalStreamLimit = 4,
        ulong localBidirectionalReceiveLimit = 128,
        ulong peerBidirectionalReceiveLimit = 128,
        ulong peerUnidirectionalReceiveLimit = 128,
        ulong localBidirectionalSendLimit = 128,
        ulong localUnidirectionalSendLimit = 128,
        ulong peerBidirectionalSendLimit = 128)
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: connectionReceiveLimit,
                InitialConnectionSendLimit: connectionSendLimit,
                InitialIncomingBidirectionalStreamLimit: incomingBidirectionalStreamLimit,
                InitialIncomingUnidirectionalStreamLimit: incomingUnidirectionalStreamLimit,
                InitialPeerBidirectionalStreamLimit: peerBidirectionalStreamLimit,
                InitialPeerUnidirectionalStreamLimit: peerUnidirectionalStreamLimit,
                InitialLocalBidirectionalReceiveLimit: localBidirectionalReceiveLimit,
                InitialPeerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit,
                InitialPeerUnidirectionalReceiveLimit: peerUnidirectionalReceiveLimit,
                InitialLocalBidirectionalSendLimit: localBidirectionalSendLimit,
                InitialLocalUnidirectionalSendLimit: localUnidirectionalSendLimit,
                InitialPeerBidirectionalSendLimit: peerBidirectionalSendLimit));
    }
}
