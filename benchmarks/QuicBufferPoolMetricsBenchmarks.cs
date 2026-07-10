// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures buffer-pool rent/return overhead while the standard metrics surface is observed.
/// </summary>
[MemoryDiagnoser]
public class QuicBufferPoolMetricsBenchmarks
{
    private MeterListener? listener;

    /// <summary>
    /// Enables the buffer-pool instruments and warms the shared array pool.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        listener = new MeterListener
        {
            InstrumentPublished = static (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == QuicMetrics.MeterName
                    && instrument.Name.StartsWith("incursa.quic.buffer_pool.", StringComparison.Ordinal))
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(static (_, _, _, _) => { });
        listener.Start();

        byte[] buffer = QuicBufferPool.RentBytes(1_200);
        QuicBufferPool.ReturnBytes(buffer);
    }

    /// <summary>
    /// Disposes the benchmark listener.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        listener?.Dispose();
    }

    /// <summary>
    /// Rents and returns one representative packet buffer with metrics enabled.
    /// </summary>
    [Benchmark]
    public int RentAndReturnPacketBuffer()
    {
        byte[] buffer = QuicBufferPool.RentBytes(1_200);
        int length = buffer.Length;
        QuicBufferPool.ReturnBytes(buffer);
        return length;
    }
}
