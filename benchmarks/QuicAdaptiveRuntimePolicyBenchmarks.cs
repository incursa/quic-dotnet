// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures the bounded receive-credit decision, observation, and shadow paths.
/// </summary>
[MemoryDiagnoser(displayGenColumns: false)]
public class QuicAdaptiveRuntimePolicyBenchmarks
{
    private QuicConnectionRuntime legacyRuntime = null!;
    private QuicConnectionRuntime observationRuntime = null!;
    private QuicConnectionRuntime shadowRuntime = null!;
    private QuicReceiveCreditShadowController standaloneController;
    private QuicAdaptiveRuntimeConnectionObservation standaloneObservation;
    private long observationEndTicks;
    private long shadowEndTicks;
    private ulong standaloneEpochSequence;

    /// <summary>
    /// Creates stable connection-local benchmark inputs outside measured operations.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        FixedMonotonicClock clock = new(1);
        legacyRuntime = CreateRuntime(clock);
        observationRuntime = CreateRuntime(clock);
        shadowRuntime = CreateRuntime(clock);
        RegisterDistinctStreamObservers(legacyRuntime, count: 16);
        RegisterDistinctStreamObservers(observationRuntime, count: 16);
        RegisterDistinctStreamObservers(shadowRuntime, count: 16);
        observationRuntime.EnableAdaptiveRuntimeObservation();
        shadowRuntime.EnableAdaptiveRuntimeShadow();
        observationEndTicks = clock.Ticks;
        shadowEndTicks = clock.Ticks;
        standaloneEpochSequence = 1;
        standaloneObservation = new QuicAdaptiveRuntimeConnectionObservation(
            standaloneEpochSequence,
            EpochStartTicks: 1,
            EpochEndTicks: 2,
            ActiveDurationMicros: 1,
            QuicAdaptiveRuntimeConnectionObservation.CurrentObservationContractVersion,
            QuicAdaptiveRuntimeConnectionObservation.CurrentPolicyRuleVersion,
            AdvisorAgeMicros: null,
            MissingSignalMask: QuicAdaptiveRuntimeSignalMask.QueueDelayEwma,
            StaleSignalMask: QuicAdaptiveRuntimeSignalMask.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            HasIssuedApplicationData: false,
            OpenStreams: 16,
            LiveObserverStreams: 16,
            QueuedApplicationWrites: 0,
            QueueDelayEwmaMicros: 0);
    }

    /// <summary>
    /// Disposes connection-local state after each benchmark case.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        legacyRuntime.Dispose();
        observationRuntime.Dispose();
        shadowRuntime.Dispose();
    }

    /// <summary>
    /// Measures the frozen legacy receive-credit selector.
    /// </summary>
    [Benchmark(Baseline = true)]
    public bool LegacyReceiveCreditDecision()
        => legacyRuntime.ShouldUseBatchedReceiveCreditPath();

    /// <summary>
    /// Measures one bounded connection observation capture.
    /// </summary>
    [Benchmark]
    public ulong CaptureConnectionObservation()
    {
        observationEndTicks++;
        _ = observationRuntime.TryCaptureAdaptiveRuntimeObservationAtActorBoundary(
            observationEndTicks,
            out QuicAdaptiveRuntimeConnectionObservation observation);
        return observation.ConnectionEpochSequence;
    }

    /// <summary>
    /// Measures the standalone deterministic shadow rule.
    /// </summary>
    [Benchmark]
    public ulong EvaluateReceiveCreditShadow()
    {
        standaloneEpochSequence++;
        standaloneObservation = standaloneObservation with
        {
            ConnectionEpochSequence = standaloneEpochSequence,
        };
        _ = standaloneController.TryEvaluate(
            in standaloneObservation,
            out QuicReceiveCreditPolicySnapshot snapshot);
        return snapshot.SnapshotVersion;
    }

    /// <summary>
    /// Measures combined connection observation and shadow evaluation.
    /// </summary>
    [Benchmark]
    public ulong CaptureAndEvaluateReceiveCreditShadow()
    {
        shadowEndTicks++;
        _ = shadowRuntime.TryCaptureReceiveCreditShadowAtActorBoundary(
            shadowEndTicks,
            out _,
            out QuicReceiveCreditPolicySnapshot snapshot);
        return snapshot.SnapshotVersion;
    }

    private static QuicConnectionRuntime CreateRuntime(IMonotonicClock clock)
        => new(CreateState(), clock);

    private static QuicConnectionStreamState CreateState()
    {
        return new QuicConnectionStreamState(
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

    private static void RegisterDistinctStreamObservers(QuicConnectionRuntime runtime, int count)
    {
        for (int index = 0; index < count; index++)
        {
            _ = runtime.RegisterStreamObserver((ulong)(index * 4), static _ => { });
        }
    }

    private sealed class FixedMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)System.Diagnostics.Stopwatch.Frequency;
    }
}
