// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using System.Net.Sockets;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

public class MetricsTests
{
    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task QuicConnectionAndStreamPathsEmitActiveCounterDeltas()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        QuicConnectionStreamState streamState = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);

        await using QuicConnectionRuntime runtime = new(streamState, tlsRole: QuicTlsRole.Client);
        Assert.True(streamState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame _));

        QuicMetrics.RecordStreamOpened(QuicTlsRole.Client, streamId.Value, QuicStreamType.Bidirectional);
        QuicMetrics.RecordStreamClosed(QuicTlsRole.Client, streamId.Value, QuicStreamType.Bidirectional);

        await runtime.DisposeAsync();

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.connections.started"
            && measurement.Value == 1
            && measurement.HasTag("role", "client"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.connections.active"
            && measurement.Value == 1
            && measurement.HasTag("role", "client"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.connections.active"
            && measurement.Value == -1
            && measurement.HasTag("role", "client"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.connections.closed"
            && measurement.Value == 1
            && measurement.HasTag("close_reason", "disposed"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.streams.opened"
            && measurement.Value == 1
            && measurement.HasTag("direction", "bidirectional")
            && measurement.HasTag("initiator", "local"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.streams.active"
            && measurement.Value == -1
            && measurement.HasTag("direction", "bidirectional")
            && measurement.HasTag("initiator", "local"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void QuicMetricTagsStayLowCardinality()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        QuicMetrics.RecordDatagramReceived(QuicTlsRole.Server, 1);
        recorder.RecordObservableInstruments();
        double datagramsReceivedBefore = recorder.GetLatestMeasurement("incursa.quic.datagrams.received", "role", "server");
        double datagramsSentBefore = recorder.GetLatestMeasurement("incursa.quic.datagrams.sent", "role", "server");
        double bytesReceivedBefore = recorder.GetLatestMeasurement("incursa.quic.bytes.received", "role", "server");
        double bytesSentBefore = recorder.GetLatestMeasurement("incursa.quic.bytes.sent", "role", "server");

        QuicMetrics.RecordDatagramReceived(QuicTlsRole.Server, 1200);
        QuicMetrics.RecordDatagramSent(QuicTlsRole.Server, 1180);
        QuicMetrics.RecordPacketDropped(QuicTlsRole.Client, "connection-id-42");
        QuicMetrics.RecordFlowControlBlocked(QuicTlsRole.Client);
        QuicMetrics.RecordStreamLimitBlocked(QuicTlsRole.Server, bidirectional: false);
        QuicMetrics.RecordAntiAmplificationBlocked(QuicTlsRole.Server);
        QuicMetrics.RecordProbeTimeout(QuicTlsRole.Client, QuicPacketNumberSpace.Initial);
        QuicMetrics.RecordAeadOpenFailure(QuicAeadAlgorithm.Aes128Gcm);
        QuicMetrics.RecordUdpError(QuicTlsRole.Server, "receive", SocketError.ConnectionReset);
        QuicMetrics.RecordRtt(QuicTlsRole.Client, 12_500);
        recorder.RecordObservableInstruments();
        double rentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.rents", "size_bucket", "le_1kb");
        double requestedRentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.requested_rents", "requested_size_bucket", "le_1kb");
        double returnsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.returns", "size_bucket", "le_1kb");
        double requestedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.requested", "requested_size_bucket", "le_1kb");
        double rentedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.rented", "size_bucket", "le_1kb");
        double returnedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.returned", "size_bucket", "le_1kb");
        double oversizedRentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.oversized_rents", "size_bucket", "le_1kb");
        byte[] rentedBuffer = QuicBufferPool.RentBytes(1);
        recorder.RecordObservableInstruments();
        QuicBufferPool.ReturnBytes(rentedBuffer);
        recorder.RecordObservableInstruments();

        Assert.DoesNotContain(recorder.Measurements, measurement => measurement.HasAnyForbiddenTag());
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.packets.dropped"
            && measurement.HasTag("packet_type", "unknown"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.stream_limit.blocked"
            && measurement.HasTag("direction", "unidirectional"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.pto.count"
            && measurement.HasTag("packet_type", "initial"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.aead.open_failures"
            && measurement.HasTag("algorithm", "aes-128-gcm"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.udp.errors"
            && measurement.HasTag("direction", "receive")
            && measurement.HasTag("socket_error", "connection_reset"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.datagrams.received"
            && measurement.Value == datagramsReceivedBefore + 1
            && measurement.HasTag("role", "server"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.datagrams.sent"
            && measurement.Value == datagramsSentBefore + 1
            && measurement.HasTag("role", "server"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.bytes.received"
            && measurement.Value == bytesReceivedBefore + 1200
            && measurement.HasTag("role", "server"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.bytes.sent"
            && measurement.Value == bytesSentBefore + 1180
            && measurement.HasTag("role", "server"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.rents"
            && measurement.Value == rentsBefore + 1
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.requested_rents"
            && measurement.Value == requestedRentsBefore + 1
            && measurement.HasTag("requested_size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.returns"
            && measurement.Value == returnsBefore + 1
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.requested"
            && measurement.Value == requestedBytesBefore + 1
            && measurement.HasTag("requested_size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.rented"
            && measurement.Value == rentedBytesBefore + rentedBuffer.Length
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.returned"
            && measurement.Value == returnedBytesBefore + rentedBuffer.Length
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.outstanding.buffers"
            && measurement.Value == 1
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.outstanding.buffers"
            && measurement.Value == 0
            && measurement.HasTag("size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.oversized_rents"
            && measurement.Value == oversizedRentsBefore + 1
            && measurement.HasTag("size_bucket", "le_1kb"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void Http3RequestMetricsEmitBoundedStatusAndFailureTags()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(Http3Metrics.MeterName);

        long completedStart = Http3Metrics.GetTimestamp();
        Http3Metrics.RecordRequestStarted("server");
        Http3Metrics.RecordRequestCompleted("server", 204, completedStart);

        long failedStart = Http3Metrics.GetTimestamp();
        Http3Metrics.RecordRequestStarted("client");
        Http3Metrics.RecordRequestFailed("client", "raw exception text that must not leak", failedStart);

        Assert.DoesNotContain(recorder.Measurements, measurement => measurement.HasAnyForbiddenTag());
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.http3.requests.completed"
            && measurement.HasTag("status_class", "2xx"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.http3.requests.failed"
            && measurement.HasTag("failure_reason", "exception"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.http3.request.duration.ms"
            && measurement.HasTag("role", "server"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void MetricsDisabledPathDoesNotRequireDiagnosticsOrQlogSinks()
    {
        QuicMetrics.RecordDatagramReceived(QuicTlsRole.Client, 1200);
        QuicMetrics.RecordDatagramSent(QuicTlsRole.Client, 1200);
        QuicMetrics.RecordPacketDropped(QuicTlsRole.Client);

        long started = Http3Metrics.GetTimestamp();
        Http3Metrics.RecordRequestStarted("server");
        Http3Metrics.RecordRequestCompleted("server", 200, started);
        Http3Metrics.RecordRequestFailed("server", "http3", started);

        Assert.False(QuicDiagnostics.ResolveConnectionSink().IsEnabled);
    }

    private sealed class MetricsRecorder : IDisposable
    {
        private static readonly HashSet<string> ForbiddenTagNames = new(StringComparer.Ordinal)
        {
            "connection_id",
            "stream_id",
            "endpoint",
            "peer_address",
            "url_path",
            "path",
            "exception_message",
            "error_text",
        };

        private readonly MeterListener listener = new();
        private readonly object sync = new();
        private readonly List<MeasurementRecord> measurements = [];

        private MetricsRecorder(string meterName)
        {
            listener.InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == meterName)
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            };
            listener.SetMeasurementEventCallback<long>(Record);
            listener.SetMeasurementEventCallback<double>(Record);
            listener.Start();
        }

        public IReadOnlyList<MeasurementRecord> Measurements
        {
            get
            {
                lock (sync)
                {
                    return measurements.ToArray();
                }
            }
        }

        public static MetricsRecorder Start(string meterName)
        {
            return new MetricsRecorder(meterName);
        }

        public void Dispose()
        {
            listener.Dispose();
        }

        public void RecordObservableInstruments()
        {
            listener.RecordObservableInstruments();
        }

        public double GetLatestMeasurement(string instrumentName, string tagName, string tagValue)
        {
            lock (sync)
            {
                return measurements.Last(measurement =>
                    measurement.InstrumentName == instrumentName
                    && measurement.HasTag(tagName, tagValue)).Value;
            }
        }

        private void Record(Instrument instrument, long measurement, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        {
            _ = state;
            RecordMeasurement(instrument, measurement, tags);
        }

        private void Record(Instrument instrument, double measurement, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        {
            _ = state;
            RecordMeasurement(instrument, measurement, tags);
        }

        private void RecordMeasurement(Instrument instrument, double measurement, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            Dictionary<string, string> capturedTags = new(StringComparer.Ordinal);
            foreach (KeyValuePair<string, object?> tag in tags)
            {
                capturedTags[tag.Key] = tag.Value?.ToString() ?? string.Empty;
            }

            lock (sync)
            {
                measurements.Add(new MeasurementRecord(instrument.Name, measurement, capturedTags));
            }
        }

        public sealed record MeasurementRecord(
            string InstrumentName,
            double Value,
            IReadOnlyDictionary<string, string> Tags)
        {
            public bool HasTag(string name, string value)
            {
                return Tags.TryGetValue(name, out string? actual)
                    && string.Equals(actual, value, StringComparison.Ordinal);
            }

            public bool HasAnyForbiddenTag()
            {
                return Tags.Keys.Any(ForbiddenTagNames.Contains);
            }
        }
    }
}
