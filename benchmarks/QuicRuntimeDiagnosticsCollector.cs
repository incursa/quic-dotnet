// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using System.Globalization;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Captures bounded runtime and buffer-pool meter series for diagnostic benchmark samples.
/// </summary>
internal sealed class QuicRuntimeDiagnosticsCollector : IAsyncDisposable
{
    private const string QuicMeterName = "Incursa.Quic";
    private const int MaximumSamplesPerSeries = 4096;
    private static readonly TimeSpan ObservablePollInterval = TimeSpan.FromMilliseconds(100);
    private readonly MeterListener listener = new();
    private readonly CancellationTokenSource shutdown = new();
    private readonly object observablePollSync = new();
    private readonly object sync = new();
    private readonly Dictionary<MetricSeriesKey, MetricSeriesAccumulator> series = [];
    private readonly Task pollTask;
    private bool capturing;

    private QuicRuntimeDiagnosticsCollector()
    {
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == QuicMeterName
                && (instrument.Name.StartsWith("incursa.quic.runtime.", StringComparison.Ordinal)
                    || instrument.Name.StartsWith("incursa.quic.buffer_pool.", StringComparison.Ordinal)
                    || instrument.Name is "incursa.quic.datagrams.received"
                        or "incursa.quic.datagrams.sent"
                        or "incursa.quic.bytes.received"
                        or "incursa.quic.bytes.sent"
                        or "incursa.quic.packets.dropped"
                        or "incursa.quic.udp.errors"
                        or "incursa.quic.pto.count"
                        or "incursa.quic.flow_control.blocked"))
            {
                meterListener.EnableMeasurementEvents(instrument, this);
            }
        };
        listener.SetMeasurementEventCallback<long>(static (instrument, value, tags, state) =>
            ((QuicRuntimeDiagnosticsCollector)state!).Record(instrument, value, tags));
        listener.SetMeasurementEventCallback<double>(static (instrument, value, tags, state) =>
            ((QuicRuntimeDiagnosticsCollector)state!).Record(instrument, value, tags));
        listener.Start();
        pollTask = PollObservableInstrumentsAsync();
    }

    internal static QuicRuntimeDiagnosticsCollector Start() => new();

    internal void BeginSample()
    {
        lock (sync)
        {
            series.Clear();
            capturing = true;
        }

        lock (observablePollSync)
        {
            listener.RecordObservableInstruments();
        }
    }

    internal QuicRuntimeDiagnosticsResult CompleteSample()
    {
        lock (observablePollSync)
        {
            listener.RecordObservableInstruments();
            lock (sync)
            {
                capturing = false;
                QuicMetricSeriesResult[] results = series.Values
                    .Select(static item => item.ToResult())
                    .OrderBy(static item => item.Name, StringComparer.Ordinal)
                    .ThenBy(
                        static item => string.Join(
                            '|',
                            item.Tags.Select(static tag => $"{tag.Key}={tag.Value}")),
                        StringComparer.Ordinal)
                    .ToArray();
                return new QuicRuntimeDiagnosticsResult(
                    DiagnosticOnly: true,
                    ObservablePollIntervalMilliseconds: ObservablePollInterval.TotalMilliseconds,
                    Series: results);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel();
        try
        {
            await pollTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
        {
        }

        listener.Dispose();
        shutdown.Dispose();
    }

    private async Task PollObservableInstrumentsAsync()
    {
        using PeriodicTimer timer = new(ObservablePollInterval);
        while (await timer.WaitForNextTickAsync(shutdown.Token).ConfigureAwait(false))
        {
            lock (observablePollSync)
            {
                listener.RecordObservableInstruments();
            }
        }
    }

    private void Record(
        Instrument instrument,
        double value,
        ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        MetricSeriesKey key = MetricSeriesKey.Create(instrument, tags);
        lock (sync)
        {
            if (!capturing)
            {
                return;
            }

            if (!series.TryGetValue(key, out MetricSeriesAccumulator? accumulator))
            {
                accumulator = new MetricSeriesAccumulator(key, MaximumSamplesPerSeries);
                series.Add(key, accumulator);
            }

            accumulator.Record(value);
        }
    }

    private sealed class MetricSeriesAccumulator
    {
        private readonly int maximumSamples;
        private readonly List<double> samples;
        private long sampleStride = 1;

        internal MetricSeriesAccumulator(MetricSeriesKey key, int maximumSamples)
        {
            Key = key;
            this.maximumSamples = maximumSamples;
            samples = new List<double>(maximumSamples);
        }

        internal MetricSeriesKey Key { get; }

        internal long Count { get; private set; }

        internal double Sum { get; private set; }

        internal double Minimum { get; private set; } = double.PositiveInfinity;

        internal double Maximum { get; private set; } = double.NegativeInfinity;

        internal double First { get; private set; }

        internal double Last { get; private set; }

        internal void Record(double value)
        {
            if (Count == 0)
            {
                First = value;
            }

            Count++;
            Last = value;
            Sum += value;
            Minimum = Math.Min(Minimum, value);
            Maximum = Math.Max(Maximum, value);

            if (Count % sampleStride != 0)
            {
                return;
            }

            if (samples.Count == maximumSamples)
            {
                int retainedCount = 0;
                for (int index = 1; index < samples.Count; index += 2)
                {
                    samples[retainedCount++] = samples[index];
                }

                samples.RemoveRange(retainedCount, samples.Count - retainedCount);
                sampleStride *= 2;
                if (Count % sampleStride != 0)
                {
                    return;
                }
            }

            samples.Add(value);
        }

        internal QuicMetricSeriesResult ToResult()
        {
            double[] sortedSamples = samples.Order().ToArray();
            bool isObservableCounter = Key.InstrumentType.StartsWith("ObservableCounter", StringComparison.Ordinal)
                || Key.InstrumentType.StartsWith("ObservableUpDownCounter", StringComparison.Ordinal);
            bool isEventCounter = Key.InstrumentType.StartsWith("Counter", StringComparison.Ordinal)
                || Key.InstrumentType.StartsWith("UpDownCounter", StringComparison.Ordinal);
            return new QuicMetricSeriesResult(
                Name: Key.InstrumentName,
                InstrumentType: Key.InstrumentType,
                Tags: Key.GetTags(),
                Count: Count,
                SummaryKind: isObservableCounter
                    ? "cumulative_delta"
                    : isEventCounter
                        ? "event_sum"
                        : "distribution",
                IntervalValue: isObservableCounter
                    ? Last - First
                    : isEventCounter
                        ? Sum
                        : null,
                First: Count == 0 ? 0 : First,
                Last: Count == 0 ? 0 : Last,
                Delta: Count == 0 ? 0 : Last - First,
                Sum: Sum,
                Mean: Count == 0 ? 0 : Sum / Count,
                Minimum: Count == 0 ? 0 : Minimum,
                Percentile50: Percentile(sortedSamples, 0.50),
                Percentile95: Percentile(sortedSamples, 0.95),
                Percentile99: Percentile(sortedSamples, 0.99),
                Maximum: Count == 0 ? 0 : Maximum,
                RetainedSampleCount: sortedSamples.Length,
                SampleStride: sampleStride);
        }
    }

    private readonly record struct MetricSeriesKey(
        string InstrumentName,
        string InstrumentType,
        int TagCount,
        string? Tag1Name,
        object? Tag1Value,
        string? Tag2Name,
        object? Tag2Value,
        string? Tag3Name,
        object? Tag3Value,
        string? Tag4Name,
        object? Tag4Value)
    {
        internal static MetricSeriesKey Create(
            Instrument instrument,
            ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            if (tags.Length > 4)
            {
                throw new InvalidOperationException(
                    $"Runtime diagnostic instrument '{instrument.Name}' emitted {tags.Length} tags; the bounded collector supports four.");
            }

            return new MetricSeriesKey(
                instrument.Name,
                instrument.GetType().Name,
                tags.Length,
                tags.Length > 0 ? tags[0].Key : null,
                tags.Length > 0 ? tags[0].Value : null,
                tags.Length > 1 ? tags[1].Key : null,
                tags.Length > 1 ? tags[1].Value : null,
                tags.Length > 2 ? tags[2].Key : null,
                tags.Length > 2 ? tags[2].Value : null,
                tags.Length > 3 ? tags[3].Key : null,
                tags.Length > 3 ? tags[3].Value : null);
        }

        internal IReadOnlyDictionary<string, string> GetTags()
        {
            Dictionary<string, string> tags = new(TagCount, StringComparer.Ordinal);
            AddTag(tags, Tag1Name, Tag1Value);
            AddTag(tags, Tag2Name, Tag2Value);
            AddTag(tags, Tag3Name, Tag3Value);
            AddTag(tags, Tag4Name, Tag4Value);
            return tags;
        }

        private static void AddTag(Dictionary<string, string> tags, string? name, object? value)
        {
            if (name is not null)
            {
                tags.Add(name, Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty);
            }
        }
    }

    private static double Percentile(double[] sortedValues, double percentile)
    {
        if (sortedValues.Length == 0)
        {
            return 0;
        }

        int index = (int)Math.Ceiling(percentile * sortedValues.Length) - 1;
        return sortedValues[Math.Clamp(index, 0, sortedValues.Length - 1)];
    }
}

internal sealed record QuicRuntimeDiagnosticsResult(
    bool DiagnosticOnly,
    double ObservablePollIntervalMilliseconds,
    IReadOnlyList<QuicMetricSeriesResult> Series);

internal sealed record QuicMetricSeriesResult(
    string Name,
    string InstrumentType,
    IReadOnlyDictionary<string, string> Tags,
    long Count,
    string SummaryKind,
    double? IntervalValue,
    double First,
    double Last,
    double Delta,
    double Sum,
    double Mean,
    double Minimum,
    double Percentile50,
    double Percentile95,
    double Percentile99,
    double Maximum,
    int RetainedSampleCount,
    long SampleStride);
