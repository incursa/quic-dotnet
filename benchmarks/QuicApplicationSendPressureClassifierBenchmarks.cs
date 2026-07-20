// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures steady-state shadow pressure observations without runtime metric dispatch.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendPressureClassifierBenchmarks
{
    private QuicApplicationSendPressureClassifier sparse;
    private QuicApplicationSendPressureClassifier cooperative;
    private QuicApplicationSendPressureClassifier saturated;

    /// <summary>
    /// Establishes each steady-state classifier mode outside the measured operation.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sparse.ObserveQueueDelay(0.5);

        cooperative.ObserveQueueDelay(5);
        _ = cooperative.ObserveTurn(1, burstLimitReached: true);
        _ = cooperative.ObserveTurn(1, burstLimitReached: true);

        saturated.ObserveQueueDelay(24);
        _ = saturated.ObserveTurn(1, burstLimitReached: true);
        _ = saturated.ObserveTurn(1, burstLimitReached: true);
    }

    /// <summary>
    /// Measures a sparse observation with no runnable pressure.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int SparseObservation()
        => (int)sparse.ObserveTurn(1, burstLimitReached: false).Mode;

    /// <summary>
    /// Measures a cooperative observation driven by burst pressure.
    /// </summary>
    [Benchmark]
    public int CooperativeObservation()
        => (int)cooperative.ObserveTurn(1, burstLimitReached: true).Mode;

    /// <summary>
    /// Measures a saturated observation under sustained high queue delay.
    /// </summary>
    [Benchmark]
    public int SaturatedObservation()
        => (int)saturated.ObserveTurn(1, burstLimitReached: true).Mode;
}
