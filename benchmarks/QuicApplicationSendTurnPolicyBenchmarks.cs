// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures deterministic application-send turn shadow evaluation and fallback snapshot construction.
/// </summary>
[MemoryDiagnoser(displayGenColumns: false)]
public class QuicApplicationSendTurnControllerBenchmarks
{
    private QuicApplicationSendTurnShadowController nominalController;
    private QuicApplicationSendTurnShadowController missingController;
    private QuicApplicationSendTurnShadowController staleController;
    private QuicApplicationSendTurnShadowController saturatedController;
    private QuicApplicationSendTurnShadowController outOfDomainController;
    private QuicApplicationSendTurnObservation nominalObservation;
    private QuicApplicationSendTurnObservation missingObservation;
    private QuicApplicationSendTurnObservation staleObservation;
    private QuicApplicationSendTurnObservation saturatedObservation;
    private QuicApplicationSendTurnObservation outOfDomainObservation;

    /// <summary>
    /// Creates stable controller inputs outside the measured operations.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        nominalObservation = CreateObservation();
        missingObservation = nominalObservation with
        {
            MissingSignalMask = QuicApplicationSendTurnSignalMask.QueueDelayEwma,
        };
        staleObservation = nominalObservation with
        {
            StaleSignalMask = QuicApplicationSendTurnSignalMask.ActorServiceTimeEwma,
        };
        saturatedObservation = nominalObservation with
        {
            Conditions = QuicApplicationSendTurnObservationCondition.ArithmeticSaturated,
        };
        outOfDomainObservation = nominalObservation with
        {
            Conditions = QuicApplicationSendTurnObservationCondition.OutOfDomain,
        };
    }

    /// <summary>
    /// Measures behavior-neutral controller evaluation and immutable snapshot construction.
    /// </summary>
    [Benchmark(Baseline = true)]
    public ulong EvaluateNominal()
        => Evaluate(ref nominalController, ref nominalObservation);

    /// <summary>
    /// Measures deterministic fallback when a required signal is missing.
    /// </summary>
    [Benchmark]
    public ulong EvaluateMissingSignalFallback()
        => Evaluate(ref missingController, ref missingObservation);

    /// <summary>
    /// Measures deterministic fallback when a required signal is stale.
    /// </summary>
    [Benchmark]
    public ulong EvaluateStaleSignalFallback()
        => Evaluate(ref staleController, ref staleObservation);

    /// <summary>
    /// Measures deterministic fallback after bounded arithmetic saturation.
    /// </summary>
    [Benchmark]
    public ulong EvaluateArithmeticSaturatedFallback()
        => Evaluate(ref saturatedController, ref saturatedObservation);

    /// <summary>
    /// Measures deterministic fallback for an out-of-domain observation.
    /// </summary>
    [Benchmark]
    public ulong EvaluateOutOfDomainFallback()
        => Evaluate(ref outOfDomainController, ref outOfDomainObservation);

    private static ulong Evaluate(
        ref QuicApplicationSendTurnShadowController controller,
        ref QuicApplicationSendTurnObservation observation)
    {
        observation = observation with
        {
            TurnSequence = observation.TurnSequence + 1,
        };
        _ = controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot);
        return snapshot.SnapshotSequence + (ulong)snapshot.Reason;
    }

    private static QuicApplicationSendTurnObservation CreateObservation()
        => new(
            TurnSequence: 0,
            CapturedAtTicks: 1,
            QuicApplicationSendTurnObservation.CurrentObservationContractVersion,
            QuicApplicationSendTurnObservation.CurrentPolicyRuleVersion,
            MissingSignalMask: QuicApplicationSendTurnSignalMask.None,
            StaleSignalMask: QuicApplicationSendTurnSignalMask.None,
            Conditions: QuicApplicationSendTurnObservationCondition.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            QueuedApplicationWrites: 16,
            OutboundBacklogBytes: 64 * 1024,
            DistinctQueuedStreams: 12,
            OldestQueuedSendAgeMicros: 1_000,
            QueueDelayEwmaMicros: 250,
            ActorServiceTimeEwmaMicros: 100,
            BurstLimitHits: 0,
            BytesInFlight: 32 * 1024,
            CongestionWindowBytes: 128 * 1024,
            RetainedSendBuffers: 16,
            RetainedSendBytes: 64 * 1024);
}

/// <summary>
/// Measures the bounded queue snapshot used at the application-send turn decision boundary.
/// </summary>
[MemoryDiagnoser(displayGenColumns: false)]
public class QuicApplicationSendTurnObservationBenchmarks
{
    private QuicApplicationSendQueue queue = null!;

    /// <summary>
    /// Gets or sets the number of queued writes visible to the observation boundary.
    /// </summary>
    [Params(1, 16, 64)]
    public int QueuedWriteCount { get; set; }

    /// <summary>
    /// Builds valid queued STREAM frames outside the measured operation.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        queue = new QuicApplicationSendQueue();
        for (int index = 0; index < QueuedWriteCount; index++)
        {
            ulong streamId = checked((ulong)(index % 12) * 4);
            byte[] payload = CreateQueuedWritePayload(streamId, dataLength: 16);
            queue.Enqueue(
                streamId,
                priority: 0,
                payload,
                payload.Length,
                firstEnqueuedAtMicros: checked(1_000UL + (ulong)index));
        }
    }

    /// <summary>
    /// Measures bounded, allocation-free snapshot construction at the maximum runtime limits.
    /// </summary>
    [Benchmark]
    public ulong CaptureBoundedQueueSnapshot()
    {
        QuicApplicationSendTurnQueueSnapshot snapshot = queue.CaptureBoundedTurnSnapshot(
            nowMicros: 10_000,
            maximumObservedWrites: 64,
            maximumObservedDistinctStreams: 12);
        return snapshot.OutboundBacklogBytes
            + snapshot.RetainedSendBytes
            + snapshot.DistinctQueuedStreams;
    }

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

/// <summary>
/// Measures steady-state reads of the independently forced application-send turn policy identity.
/// </summary>
[MemoryDiagnoser(displayGenColumns: false)]
public class QuicApplicationSendTurnPolicyReadBenchmarks
{
    private QuicConnectionRuntime legacyRuntime = null!;
    private QuicConnectionRuntime conservativeRuntime = null!;

    /// <summary>
    /// Creates connection-local policy snapshots outside the measured operations.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        legacyRuntime = new QuicConnectionRuntime(CreateState());
        conservativeRuntime = new QuicConnectionRuntime(CreateState());
        legacyRuntime.ConfigureApplicationSendTurnPolicyMode(
            QuicApplicationSendTurnPolicyMode.LegacyCurrent);
        conservativeRuntime.ConfigureApplicationSendTurnPolicyMode(
            QuicApplicationSendTurnPolicyMode.Conservative);
    }

    /// <summary>
    /// Disposes the connection-local benchmark state.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        legacyRuntime.Dispose();
        conservativeRuntime.Dispose();
    }

    /// <summary>
    /// Measures the forced legacy policy read.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ReadForcedLegacyCurrent()
        => (int)legacyRuntime.ApplicationSendTurnPolicyMode;

    /// <summary>
    /// Measures the forced conservative policy read.
    /// </summary>
    [Benchmark]
    public int ReadForcedConservative()
        => (int)conservativeRuntime.ApplicationSendTurnPolicyMode;

    private static QuicConnectionStreamState CreateState()
        => new(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
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
