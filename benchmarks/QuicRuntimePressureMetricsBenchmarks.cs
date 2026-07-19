// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures runtime-pressure diagnostic overhead while the standard metrics surface is observed.
/// </summary>
[MemoryDiagnoser]
public class QuicRuntimePressureMetricsBenchmarks
{
    private const int SnapshotBurstCount = 64;
    private MeterListener? listener;
    private QuicConnectionRuntime? runtime;
    private long measurementCount;

    /// <summary>
    /// Enables runtime-pressure instruments and creates one representative runtime.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        runtime = CreateRuntime();
        listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == QuicMetrics.MeterName
                    && instrument.Name.StartsWith("incursa.quic.runtime.", StringComparison.Ordinal))
                {
                    meterListener.EnableMeasurementEvents(instrument, this);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(static (_, _, _, state) =>
            Interlocked.Increment(ref ((QuicRuntimePressureMetricsBenchmarks)state!).measurementCount));
        listener.SetMeasurementEventCallback<double>(static (_, _, _, state) =>
            Interlocked.Increment(ref ((QuicRuntimePressureMetricsBenchmarks)state!).measurementCount));
        listener.Start();
        QuicMetrics.RecordRuntimePressureSnapshot(shardIndex: 0, runtime);
    }

    /// <summary>
    /// Disposes the metrics listener and representative runtime.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        if (measurementCount <= 0)
        {
            throw new InvalidOperationException("The benchmark listener did not observe runtime-pressure metrics.");
        }

        listener?.Dispose();
        runtime?.Dispose();
    }

    /// <summary>
    /// Records a representative burst of pressure-snapshot attempts.
    /// </summary>
    [Benchmark(OperationsPerInvoke = SnapshotBurstCount)]
    public long RecordRuntimePressureSnapshotBurst()
    {
        QuicConnectionRuntime activeRuntime = runtime!;
        for (int index = 0; index < SnapshotBurstCount; index++)
        {
            QuicMetrics.RecordRuntimePressureSnapshot(shardIndex: 0, activeRuntime);
        }

        return Volatile.Read(ref measurementCount);
    }

    private static QuicConnectionRuntime CreateRuntime()
        => new(new QuicConnectionStreamState(
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
                InitialPeerBidirectionalSendLimit: 4096)));
}
