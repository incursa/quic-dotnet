// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures the dispatch cost of the connection-local application-send turn-planner seam.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendTurnPlannerBenchmarks
{
    private PendingApplicationSendRequest[] queuedWrites = [];
    private QuicQueuedApplicationSendBudget budget;
    private IQuicApplicationSendTurnPlanner explicitCurrentPlanner = null!;
    private QuicApplicationSendTurnContext turnContext;

    /// <summary>
    /// Gets or sets the number of queued writes visible to one selection decision.
    /// </summary>
    [Params(1, 16)]
    public int QueuedWriteCount { get; set; }

    /// <summary>
    /// Builds valid equal-priority STREAM frames outside the measured operation.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        queuedWrites = new PendingApplicationSendRequest[QueuedWriteCount];
        int totalPayloadBytes = 0;
        for (int index = 0; index < queuedWrites.Length; index++)
        {
            ulong streamId = checked((ulong)index * 4);
            byte[] payload = CreateQueuedWritePayload(streamId, dataLength: 16);
            queuedWrites[index] = new PendingApplicationSendRequest(
                Sequence: index,
                streamId,
                Priority: 0,
                payload,
                payload.Length);
            totalPayloadBytes += payload.Length;
        }

        budget = QuicQueuedApplicationSendBudget.AllowSingleDatagram(totalPayloadBytes);
        explicitCurrentPlanner = QuicCurrentApplicationSendTurnPlanner.Instance;
        turnContext = new QuicApplicationSendTurnContext(
            InitialQueuedWriteCount: QueuedWriteCount,
            RemainingQueuedWriteCount: QueuedWriteCount,
            FlushedDatagramCount: 0,
            Budget: budget);
    }

    /// <summary>
    /// Measures the existing static selector without the swappable seam.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int DirectCurrentScheduler()
    {
        QuicApplicationSendPlan plan = QuicApplicationSendScheduler.SelectQueuedApplicationSendPlan(
            queuedWrites,
            budget,
            out QuicStreamFrame frame,
            out _);
        return plan.SelectedWriteCount + frame.StreamDataLength;
    }

    /// <summary>
    /// Measures the shipped null-planner fast path.
    /// </summary>
    [Benchmark]
    public int NullPlannerDispatch()
    {
        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            planner: null,
            queuedWrites,
            budget,
            out QuicStreamFrame frame,
            out _);
        return plan.SelectedWriteCount + frame.StreamDataLength;
    }

    /// <summary>
    /// Measures explicit interface dispatch through the current control policy.
    /// </summary>
    [Benchmark]
    public int ExplicitCurrentPlannerDispatch()
    {
        QuicApplicationSendPlan plan = QuicApplicationSendTurnPlannerDispatch.SelectQueuedApplicationSendPlan(
            explicitCurrentPlanner,
            queuedWrites,
            budget,
            out QuicStreamFrame frame,
            out _);
        return plan.SelectedWriteCount + frame.StreamDataLength;
    }

    /// <summary>
    /// Measures continuation dispatch for the default legacy_current null-planner path.
    /// </summary>
    [Benchmark]
    public bool LegacyCurrentContinuationDispatch()
        => QuicApplicationSendTurnPlannerDispatch.ShouldScheduleNext(
            planner: null,
            turnContext);

    /// <summary>
    /// Measures continuation dispatch for the forceable conservative campaign identity.
    /// </summary>
    /// <remarks>
    /// Conservative currently delegates to the existing planner. This is a mechanism-cost
    /// comparison only and does not imply an active selection rule.
    /// </remarks>
    [Benchmark]
    public bool ForcedConservativeContinuationDispatch()
        => QuicApplicationSendTurnPlannerDispatch.ShouldScheduleNext(
            explicitCurrentPlanner,
            turnContext);

    private static byte[] CreateQueuedWritePayload(ulong streamId, int dataLength)
    {
        byte[] streamData = new byte[dataLength];
        byte[] streamPayload = new byte[dataLength + 32];
        if (!QuicFrameCodec.TryFormatStreamFrame(
                QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
                streamId,
                offset: 0,
                streamData,
                streamPayload,
                out int streamPayloadLength))
        {
            throw new InvalidOperationException("Could not format the benchmark STREAM frame.");
        }

        return streamPayload[..streamPayloadLength];
    }
}
