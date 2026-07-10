// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures datagram metric overhead while the standard metrics surface is observed.
/// </summary>
[MemoryDiagnoser]
public class QuicDatagramMetricsBenchmarks
{
    private MeterListener? listener;
    private long measurementTotal;

    /// <summary>
    /// Enables the datagram and byte counters.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        QuicMetrics.RecordDatagramReceived(QuicTlsRole.Server, 0);
        listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == QuicMetrics.MeterName
                    && (instrument.Name.StartsWith("incursa.quic.datagrams.", StringComparison.Ordinal)
                        || instrument.Name.StartsWith("incursa.quic.bytes.", StringComparison.Ordinal)))
                {
                    meterListener.EnableMeasurementEvents(instrument, this);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>(static (_, measurement, _, state) =>
        {
            ((QuicDatagramMetricsBenchmarks)state!).measurementTotal += measurement;
        });
        listener.Start();
    }

    /// <summary>
    /// Disposes the benchmark listener.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        listener?.RecordObservableInstruments();
        if (measurementTotal <= 0)
        {
            throw new InvalidOperationException("The benchmark listener did not observe datagram metrics.");
        }

        listener?.Dispose();
    }

    /// <summary>
    /// Records one received and one sent packet for representative server traffic.
    /// </summary>
    [Benchmark]
    public long RecordReceivedAndSentDatagrams()
    {
        QuicMetrics.RecordDatagramReceived(QuicTlsRole.Server, 1_200);
        QuicMetrics.RecordDatagramSent(QuicTlsRole.Server, 1_200);
        return measurementTotal;
    }
}
