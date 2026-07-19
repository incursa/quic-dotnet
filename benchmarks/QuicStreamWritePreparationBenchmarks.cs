// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

[MemoryDiagnoser]
public class QuicStreamWritePreparationBenchmarks
{
    private const ulong MaximumFlowControlLimit = (1UL << 62) - 1;
    private const int WriteLength = 1024;
    private QuicConnectionStreamState separateState = null!;
    private QuicConnectionStreamState atomicState = null!;
    private ulong separateStreamId;
    private ulong atomicStreamId;

    [Params(64, 256)]
    public int OperationCount { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        separateState = CreateState();
        atomicState = CreateState();
        if (!separateState.TryOpenLocalStream(bidirectional: true, out QuicStreamId separateOpenedStreamId, out _)
            || !atomicState.TryOpenLocalStream(bidirectional: true, out QuicStreamId atomicOpenedStreamId, out _))
        {
            throw new InvalidOperationException("Failed to open the benchmark streams.");
        }

        separateStreamId = separateOpenedStreamId.Value;
        atomicStreamId = atomicOpenedStreamId.Value;
    }

    [Benchmark(Baseline = true)]
    public ulong SeparateWritePreparationCalls()
    {
        ulong checksum = 0;
        for (int index = 0; index < OperationCount; index++)
        {
            if (!separateState.TryGetStreamSnapshot(separateStreamId, out QuicConnectionStreamSnapshot snapshot)
                || !separateState.TryCaptureSendState(separateStreamId, out QuicConnectionStreamSendStateSnapshot sendStateBeforeWrite)
                || !separateState.TryReserveSendCapacity(
                    separateStreamId,
                    snapshot.UniqueBytesSent,
                    WriteLength,
                    fin: false,
                    out _,
                    out _,
                    out _)
                || !separateState.TryGetStreamPriority(separateStreamId, out int priority)
                || !separateState.TryRestoreSendState(sendStateBeforeWrite))
            {
                throw new InvalidOperationException("The separate write preparation failed.");
            }

            checksum += snapshot.UniqueBytesSent + (ulong)(priority + 1) + sendStateBeforeWrite.ConnectionUniqueBytesSent;
        }

        return checksum;
    }

    [Benchmark]
    public ulong AtomicWritePreparation()
    {
        ulong checksum = 0;
        for (int index = 0; index < OperationCount; index++)
        {
            if (atomicState.PrepareStreamWrite(
                    atomicStreamId,
                    WriteLength,
                    fin: false,
                    out QuicConnectionStreamWritePreparation preparation,
                    out _,
                    out _,
                    out _) != QuicConnectionStreamWritePreparationStatus.Reserved
                || !atomicState.TryGetStreamPriority(atomicStreamId, out int priority)
                || !atomicState.TryRestoreSendState(preparation.SendStateBeforeWrite))
            {
                throw new InvalidOperationException("The atomic write preparation failed.");
            }

            checksum += preparation.WriteOffset
                + (ulong)(priority + 1)
                + preparation.SendStateBeforeWrite.ConnectionUniqueBytesSent;
        }

        return checksum;
    }

    private static QuicConnectionStreamState CreateState()
        => new(new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: 1,
            InitialConnectionSendLimit: MaximumFlowControlLimit,
            InitialIncomingBidirectionalStreamLimit: 1,
            InitialIncomingUnidirectionalStreamLimit: 1,
            InitialPeerBidirectionalStreamLimit: 1,
            InitialPeerUnidirectionalStreamLimit: 1,
            InitialLocalBidirectionalReceiveLimit: 1,
            InitialPeerBidirectionalReceiveLimit: 1,
            InitialPeerUnidirectionalReceiveLimit: 1,
            InitialLocalBidirectionalSendLimit: MaximumFlowControlLimit,
            InitialLocalUnidirectionalSendLimit: MaximumFlowControlLimit,
            InitialPeerBidirectionalSendLimit: MaximumFlowControlLimit));
}
