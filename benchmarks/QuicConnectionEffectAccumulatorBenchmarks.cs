// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks transition-effect accumulation without forcing public effect-array materialization.
/// </summary>
[MemoryDiagnoser]
public class QuicConnectionEffectAccumulatorBenchmarks
{
    private QuicConnectionEffect[] effects = [];

    /// <summary>
    /// Number of effects appended during a transition.
    /// </summary>
    [Params(0, 1, 2, 4)]
    public int EffectCount { get; set; }

    /// <summary>
    /// Creates reusable effect instances for the append-path measurement.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        effects = new QuicConnectionEffect[Math.Max(EffectCount, 1)];
        for (int index = 0; index < effects.Length; index++)
        {
            effects[index] = new QuicConnectionArmTimerEffect(
                QuicConnectionTimerKind.IdleTimeout,
                (ulong)index,
                new QuicConnectionTimerPriority(index, (ulong)index));
        }
    }

    /// <summary>
    /// Measures the prior lazy List&lt;T&gt; accumulation shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int LazyList()
    {
        List<QuicConnectionEffect>? list = null;
        for (int index = 0; index < EffectCount; index++)
        {
            (list ??= []).Add(effects[index]);
        }

        return list?.Count ?? 0;
    }

    /// <summary>
    /// Measures the single-effect accumulator shape.
    /// </summary>
    [Benchmark]
    public int Accumulator()
    {
        QuicConnectionEffectAccumulator accumulator = default;
        for (int index = 0; index < EffectCount; index++)
        {
            accumulator.Add(effects[index]);
        }

        return accumulator.Count;
    }
}
