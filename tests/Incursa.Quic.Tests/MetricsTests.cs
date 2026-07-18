// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using System.Net.Sockets;
using System.Threading;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

public class MetricsTests
{
    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task HostedSendReturnsDetachedOwnerWhenObserverThrows()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        await using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionRuntimeShard shard = new(
            shardIndex: 0,
            suppressHostedTimerEffectObjects: true);
        QuicConnectionStreamState state = runtime.StreamRegistry.Bookkeeping;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 1, streamData: []),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryAbortLocalStreamWrites(1, out _, out errorCode));
        Assert.Equal(default, errorCode);
        runtime.TryQueueStreamCapacityRelease(streamId: 1);

        recorder.RecordObservableInstruments();
        TaskCompletionSource<QuicConnectionSendDatagramUpdate> observed = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        InvalidOperationException observerFailure = new("send observer failure");
        Task consumer = shard.RunAsync(
            sendDatagramObserver: (_, update) =>
            {
                observed.TrySetResult(update);
                throw observerFailure;
            });

        Assert.True(shard.TryPostStreamCapacityRelease(new QuicConnectionHandle(1), runtime));

        QuicConnectionSendDatagramUpdate update = await observed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        byte[] detachedOwner = Assert.IsType<byte[]>(update.DatagramOwner);
        string sizeBucket = GetBufferSizeBucket(detachedOwner.Length);
        double returnsBefore = recorder.GetLatestMeasurement(
            "incursa.quic.buffer_pool.returns",
            "size_bucket",
            sizeBucket);

        InvalidOperationException actual = await Assert.ThrowsAsync<InvalidOperationException>(() => consumer);
        Assert.Same(observerFailure, actual);
        recorder.RecordObservableInstruments();
        Assert.True(
            recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.returns",
                "size_bucket",
                sizeBucket) >= returnsBefore + 1);

        InvalidOperationException disposeFailure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => shard.DisposeAsync().AsTask());
        Assert.Same(observerFailure, disposeFailure);
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void RemovingCombinedApplicationSendInputsReturnsTheirPayloadOwners()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        QuicApplicationSendQueue queue = new();
        byte[] firstPayload = QuicBufferPool.RentBytes(1);
        byte[] secondPayload = QuicBufferPool.RentBytes(2_000);
        string firstSizeBucket = GetBufferSizeBucket(firstPayload.Length);
        string secondSizeBucket = GetBufferSizeBucket(secondPayload.Length);
        Assert.NotEqual(firstSizeBucket, secondSizeBucket);

        queue.Enqueue(7, priority: 0, firstPayload, 1);
        queue.Enqueue(8, priority: 0, secondPayload, 2);
        PendingApplicationSendRequest[] selectedWrites = queue.RentSortedQueuedWrites(out int selectedWriteCount);
        bool removed = false;
        try
        {
            recorder.RecordObservableInstruments();
            double firstReturnsBefore = recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.returns",
                "size_bucket",
                firstSizeBucket);
            double secondReturnsBefore = recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.returns",
                "size_bucket",
                secondSizeBucket);

            removed = queue.TryRemoveQueuedWrites(
                selectedWrites.AsSpan(0, selectedWriteCount),
                returnPayloads: true);
            recorder.RecordObservableInstruments();

            Assert.True(removed);
            Assert.Equal(0, queue.Count);
            Assert.Equal(
                firstReturnsBefore + 1,
                recorder.GetLatestMeasurement(
                    "incursa.quic.buffer_pool.returns",
                    "size_bucket",
                    firstSizeBucket));
            Assert.Equal(
                secondReturnsBefore + 1,
                recorder.GetLatestMeasurement(
                    "incursa.quic.buffer_pool.returns",
                    "size_bucket",
                    secondSizeBucket));
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(selectedWrites);
            if (!removed)
            {
                queue.Clear();
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0098")]
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
        double requestedRentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.requested_rents", "requested_size_bucket", "le_1kb");
        double requestedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.requested", "requested_size_bucket", "le_1kb");
        byte[] rentedBuffer = QuicBufferPool.RentBytes(1);
        string rentedSizeBucket = GetBufferSizeBucket(rentedBuffer.Length);
        double rentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.rents", "size_bucket", rentedSizeBucket);
        double returnsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.returns", "size_bucket", rentedSizeBucket);
        double rentedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.rented", "size_bucket", rentedSizeBucket);
        double returnedBytesBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.bytes.returned", "size_bucket", rentedSizeBucket);
        double oversizedRentsBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.oversized_rents", "size_bucket", rentedSizeBucket);
        double outstandingBuffersBefore = recorder.GetLatestMeasurement("incursa.quic.buffer_pool.outstanding.buffers", "size_bucket", rentedSizeBucket);
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
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.requested_rents"
            && measurement.Value == requestedRentsBefore + 1
            && measurement.HasTag("requested_size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.returns"
            && measurement.Value == returnsBefore + 1
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.requested"
            && measurement.Value == requestedBytesBefore + 1
            && measurement.HasTag("requested_size_bucket", "le_1kb"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.rented"
            && measurement.Value == rentedBytesBefore + rentedBuffer.Length
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.bytes.returned"
            && measurement.Value == returnedBytesBefore + rentedBuffer.Length
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.outstanding.buffers"
            && measurement.Value == outstandingBuffersBefore + 1
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.outstanding.buffers"
            && measurement.Value == outstandingBuffersBefore
            && measurement.HasTag("size_bucket", rentedSizeBucket));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.buffer_pool.oversized_rents"
            && measurement.Value == oversizedRentsBefore + 1
            && measurement.HasTag("size_bucket", rentedSizeBucket));
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

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task QuicRuntimeShardMetricsEmitBoundedTagsForEnqueueAndDequeue()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        await using QuicConnectionRuntimeShard shard = new(2, clock);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        TaskCompletionSource firstTransitionProcessed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        Assert.True(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        recorder.RecordObservableInstruments();
        Assert.Equal(1d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.inbox.depth",
            "shard_index",
            "2"));
        Assert.Equal(1d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "2",
            "work_item_kind",
            "flow_control_credit_update"));

        Task consumer = shard.RunAsync(
            (_, _) => firstTransitionProcessed.TrySetResult(),
            cancellationToken: timeout.Token);

        await firstTransitionProcessed.Task.WaitAsync(timeout.Token);
        await WaitForMeasurementAsync(
            recorder,
            "incursa.quic.runtime.shard.work_items.dequeued",
            "work_item_kind",
            "flow_control_credit_update");

        recorder.RecordObservableInstruments();
        Assert.Equal(0d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.inbox.depth",
            "shard_index",
            "2"));
        Assert.Equal(0d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "2",
            "work_item_kind",
            "flow_control_credit_update"));

        await shard.DisposeAsync();
        await consumer;

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.work_items.enqueued"
            && measurement.Value == 1
            && measurement.HasTag("shard_index", "2")
            && measurement.HasTag("work_item_kind", "flow_control_credit_update"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.work_items.dequeued"
            && measurement.Value == 1
            && measurement.HasTag("shard_index", "2")
            && measurement.HasTag("work_item_kind", "flow_control_credit_update"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.queue_delay.ms"
            && measurement.Value >= 0
            && measurement.HasTag("shard_index", "2")
            && measurement.HasTag("work_item_kind", "flow_control_credit_update"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.service_time.ms"
            && measurement.Value >= 0
            && measurement.HasTag("shard_index", "2")
            && measurement.HasTag("work_item_kind", "flow_control_credit_update"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.delayed_application_sends"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.retained_bytes"
            && measurement.HasTag("shard_index", "2"));
        string[] queueCauses =
        [
            "pending_retransmission",
            "oversized_write",
            "small_write_delay",
            "direct_send_blocked",
        ];
        foreach (string queueCause in queueCauses)
        {
            Assert.Contains(recorder.Measurements, measurement =>
                measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.retained_buffers"
                && measurement.Value == 0
                && measurement.HasTag("shard_index", "2")
                && measurement.HasTag("queue_cause", queueCause));
            Assert.Contains(recorder.Measurements, measurement =>
                measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.retained_bytes"
                && measurement.Value == 0
                && measurement.HasTag("shard_index", "2")
                && measurement.HasTag("queue_cause", queueCause));
        }

        Assert.DoesNotContain(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.oldest_age.ms");
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.retained"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.retained_bytes"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.storage.capacity"
            && measurement.Value >= 64
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.retransmissions.pending"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.retransmissions.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.retransmissions.retained_bytes"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.receive.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.receive.retained_bytes"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.receive.buffered_bytes"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.receive.buffered_streams"
            && measurement.HasTag("shard_index", "2"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void SentPacketStorageMetricsReportApplicationDataSpanAndCapacity()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.sent_packets.application_packet_number_span",
            "incursa.quic.runtime.sent_packets.storage.capacity");
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.TrackApplicationPacket(10, new byte[1_200]);
        runtime.TrackApplicationPacket(14, new byte[1_200]);

        QuicMetrics.RecordRuntimePressureSnapshot(2, runtime);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.application_packet_number_span"
            && measurement.Value == 5
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.storage.capacity"
            && measurement.Value >= 64
            && measurement.HasTag("shard_index", "2"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void SentPacketRetentionMetricsCanBeCollectedWithoutStorageMetrics()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.sent_packets.retained_buffers");
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.TrackApplicationPacket(10, new byte[1_200]);

        QuicMetrics.RecordRuntimePressureSnapshot(2, runtime);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.DoesNotContain(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.storage.capacity");
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void SentPacketStorageCapacityCanBeCollectedWithoutSpanMetrics()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.sent_packets.storage.capacity");
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.TrackApplicationPacket(10, new byte[1_200]);

        QuicMetrics.RecordRuntimePressureSnapshot(2, runtime);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.storage.capacity"
            && measurement.Value >= 64
            && measurement.HasTag("shard_index", "2"));
        Assert.DoesNotContain(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.application_packet_number_span");
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void SentPacketRetentionAndSpanMetricsCanBeCollectedTogether()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.sent_packets.retained_buffers",
            "incursa.quic.runtime.sent_packets.application_packet_number_span");
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.TrackApplicationPacket(10, new byte[1_200]);
        runtime.TrackApplicationPacket(14, new byte[1_200]);

        QuicMetrics.RecordRuntimePressureSnapshot(2, runtime);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.retained_buffers"
            && measurement.HasTag("shard_index", "2"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.sent_packets.application_packet_number_span"
            && measurement.Value == 5
            && measurement.HasTag("shard_index", "2"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RuntimeShardDepthIsAbsoluteAcrossLateListenerAttachment()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        await using QuicConnectionRuntimeShard shard = new(73, clock);

        Assert.True(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        using (MetricsRecorder firstRecorder = MetricsRecorder.Start(QuicMetrics.MeterName))
        {
            firstRecorder.RecordObservableInstruments();
            Assert.Equal(1d, firstRecorder.GetLatestMeasurement(
                "incursa.quic.runtime.shard.work_item.depth",
                "shard_index",
                "73",
                "work_item_kind",
                "flow_control_credit_update"));
        }

        Assert.True(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        using MetricsRecorder secondRecorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        secondRecorder.RecordObservableInstruments();
        Assert.Equal(2d, secondRecorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.inbox.depth",
            "shard_index",
            "73"));
        Assert.Equal(2d, secondRecorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "73",
            "work_item_kind",
            "flow_control_credit_update"));

        TaskCompletionSource bothProcessed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var processed = 0;
        Task consumer = shard.RunAsync((_, _) =>
        {
            if (Interlocked.Increment(ref processed) == 2)
            {
                bothProcessed.TrySetResult();
            }
        });

        await bothProcessed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        secondRecorder.RecordObservableInstruments();
        Assert.Equal(0d, secondRecorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.inbox.depth",
            "shard_index",
            "73"));
        Assert.Equal(0d, secondRecorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "73",
            "work_item_kind",
            "flow_control_credit_update"));

        await shard.DisposeAsync();
        await consumer;
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RuntimeShardDepthStopsPublishingAfterShardDisposal()
    {
        QuicConnectionRuntimeShard shard = new(997);
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        recorder.RecordObservableInstruments();
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.inbox.depth"
            && measurement.HasTag("shard_index", "997"));

        await shard.DisposeAsync();
        int measurementCount = recorder.Measurements.Count;
        recorder.RecordObservableInstruments();

        Assert.DoesNotContain(recorder.Measurements.Skip(measurementCount), measurement =>
            measurement.HasTag("shard_index", "997"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RuntimeShardWorkItemDepthBalancesWhenFaultedConsumerDrainsQueuedWork()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionRuntimeShard shard = new(2, clock);
        TaskCompletionSource firstTransitionProcessed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using ManualResetEventSlim releaseObserver = new(initialState: false);

        Task consumer = shard.RunAsync((_, _) =>
        {
            firstTransitionProcessed.TrySetResult();
            Assert.True(releaseObserver.Wait(TimeSpan.FromSeconds(5)));
            throw new InvalidOperationException("Force the shard shutdown-drain path.");
        });

        Assert.True(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        await firstTransitionProcessed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        recorder.RecordObservableInstruments();
        Assert.Equal(1d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "2",
            "work_item_kind",
            "flow_control_credit_update"));
        releaseObserver.Set();

        await Assert.ThrowsAsync<InvalidOperationException>(() => consumer);
        recorder.RecordObservableInstruments();
        Assert.Equal(0d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.work_item.depth",
            "shard_index",
            "2",
            "work_item_kind",
            "flow_control_credit_update"));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await shard.DisposeAsync());
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ApplicationSendCauseRetentionRecordsPositiveAgeAndBoundedCause()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);

        QuicMetrics.RecordApplicationSendCauseRetention(
            shardIndex: 3,
            QuicApplicationSendQueueCause.OversizedWrite,
            new QuicRetentionSnapshot(
                RetainedBufferCount: 7,
                RetainedByteCount: 28_672,
                OldestAgeMilliseconds: 12.5));

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.retained_buffers"
            && measurement.Value == 7
            && measurement.HasTag("shard_index", "3")
            && measurement.HasTag("queue_cause", "oversized_write"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.retained_bytes"
            && measurement.Value == 28_672
            && measurement.HasTag("shard_index", "3")
            && measurement.HasTag("queue_cause", "oversized_write"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.cause.oldest_age.ms"
            && measurement.Value == 12.5
            && measurement.HasTag("shard_index", "3")
            && measurement.HasTag("queue_cause", "oversized_write"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void RuntimeFollowOnFlushMetricsUseBoundedWorkAndFlushKinds()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeShardWorkItem workItem = new(
            new QuicConnectionHandle(1),
            runtime,
            QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate);

        QuicMetrics.RecordRuntimeFollowOnFlushItems(
            3,
            in workItem,
            applicationSendCount: 4,
            flowControlCount: 2,
            streamCapacityCount: 1);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.follow_on_flush.items"
            && measurement.Value == 4
            && measurement.HasTag("shard_index", "3")
            && measurement.HasTag("work_item_kind", "flow_control_credit_update")
            && measurement.HasTag("flush_kind", "application_send"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.follow_on_flush.items"
            && measurement.Value == 2
            && measurement.HasTag("flush_kind", "flow_control"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.follow_on_flush.items"
            && measurement.Value == 1
            && measurement.HasTag("flush_kind", "stream_capacity"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void RuntimePressureSnapshotSamplingBoundsBurstsAndRetainsTimeFallback()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.TryBeginRuntimePressureSnapshot(
            timestamp: 100,
            minimumIntervalTicks: 1_000,
            maximumWorkItemsPerSnapshot: 4));
        Assert.False(runtime.TryBeginRuntimePressureSnapshot(200, 1_000, 4));
        Assert.False(runtime.TryBeginRuntimePressureSnapshot(300, 1_000, 4));
        Assert.False(runtime.TryBeginRuntimePressureSnapshot(400, 1_000, 4));
        Assert.True(runtime.TryBeginRuntimePressureSnapshot(500, 1_000, 4));
        Assert.False(runtime.TryBeginRuntimePressureSnapshot(600, 1_000, 4));
        Assert.True(runtime.TryBeginRuntimePressureSnapshot(1_500, 1_000, 4));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void RuntimePressureMetricsEmitTwiceForSixtyFourItemBurst()
    {
        const int shardIndex = 7_501;
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.delayed_application_sends");
        using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        for (int index = 0; index < 64; index++)
        {
            QuicMetrics.RecordRuntimePressureSnapshot(shardIndex, runtime);
        }

        Assert.Equal(2, recorder.Measurements.Count(measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.delayed_application_sends"
            && measurement.HasTag("shard_index", shardIndex.ToString())));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void BufferPoolOwnerMetricsAttributeRequestedAndRentedBytes()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.buffer_pool.owner.rents",
            "incursa.quic.buffer_pool.owner.bytes.requested",
            "incursa.quic.buffer_pool.owner.bytes.rented");
        recorder.RecordObservableInstruments();
        double rentsBefore = recorder.GetLatestMeasurement(
            "incursa.quic.buffer_pool.owner.rents",
            "owner",
            "receive_segment");
        double requestedBytesBefore = recorder.GetLatestMeasurement(
            "incursa.quic.buffer_pool.owner.bytes.requested",
            "owner",
            "receive_segment");
        double rentedBytesBefore = recorder.GetLatestMeasurement(
            "incursa.quic.buffer_pool.owner.bytes.rented",
            "owner",
            "receive_segment");

        byte[] buffer = QuicBufferPool.RentBytes(1_537, QuicBufferPoolOwner.ReceiveSegment);
        try
        {
            recorder.RecordObservableInstruments();
            Assert.True(recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.owner.rents",
                "owner",
                "receive_segment") >= rentsBefore + 1);
            Assert.True(recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.owner.bytes.requested",
                "owner",
                "receive_segment") >= requestedBytesBefore + 1_537);
            Assert.True(recorder.GetLatestMeasurement(
                "incursa.quic.buffer_pool.owner.bytes.rented",
                "owner",
                "receive_segment") >= rentedBytesBefore + buffer.Length);
        }
        finally
        {
            QuicBufferPool.ReturnBytes(buffer);
        }
    }

    [Theory]
    [InlineData((int)QuicBufferPoolOwner.InboundPacketProtection, "inbound_packet_protection")]
    [InlineData((int)QuicBufferPoolOwner.OutboundPacketProtection, "outbound_packet_protection")]
    public void BufferPoolOwnerNamesDistinguishApplicationPacketProtection(
        int owner,
        string expected)
    {
        Assert.Equal(expected, QuicMetrics.FormatBufferPoolOwner((QuicBufferPoolOwner)owner));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ApplicationSendBatchMetricsUseBoundedRoleAndKindTags()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);

        QuicMetrics.RecordApplicationSendBatchStreams(QuicTlsRole.Server, streamCount: 3, combinedWrite: true);
        QuicMetrics.RecordApplicationSendBatchStreams(QuicTlsRole.Client, streamCount: 1, combinedWrite: false);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.batch_streams"
            && measurement.Value == 3
            && measurement.HasTag("role", "server")
            && measurement.HasTag("batch_kind", "combined_write"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.batch_streams"
            && measurement.Value == 1
            && measurement.HasTag("role", "client")
            && measurement.HasTag("batch_kind", "single_write"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void ApplicationSendRecoveryMetricsCaptureDecisionBudgetAndBoundedOutcome()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        QuicSendPolicySnapshot snapshot = new(
            HasActivePath: true,
            CanSendOrdinaryPackets: true,
            MaximumDatagramSizeBytes: 1_200,
            MaximumApplicationPayloadBytes: 1_100,
            CongestionWindowBytes: 12_000,
            BytesInFlightBytes: 7_200,
            PendingRetransmissionCount: 0,
            HasApplicationDataRetransmission: false,
            AntiAmplificationAvailableBytes: 1_000,
            IsAddressValidated: false,
            HandshakeConfirmed: true,
            HasOneRttProtection: true,
            QueuedApplicationSendCount: 9);

        QuicMetrics.RecordApplicationSendRecoveryFlush(
            QuicTlsRole.Server,
            snapshot,
            QuicQueuedApplicationSendBudget.Allowed(maxDatagrams: 4, maxPayloadBytes: 1_000),
            queuedWritesBefore: 9,
            queuedWritesAfter: 5,
            flushedDatagrams: 4,
            QuicApplicationSendRecoveryFlushOutcome.BurstLimitReached,
            QuicSendPolicyBlockedReason.None);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.flushes"
            && measurement.Value == 1
            && measurement.HasTag("role", "server")
            && measurement.HasTag("outcome", "burst_limit_reached")
            && measurement.HasTag("blocked_reason", "none"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.congestion_window.bytes"
            && measurement.Value == 12_000);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.bytes_in_flight.bytes"
            && measurement.Value == 7_200);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.available_send.bytes"
            && measurement.Value == 1_000);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.budget.datagrams"
            && measurement.Value == 4);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.flushed.datagrams"
            && measurement.Value == 4);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.queue.before"
            && measurement.Value == 9);
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.queue.after"
            && measurement.Value == 5);
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void RuntimeDetectedPacketLossUsesBoundedRoleAndPacketSpaceTags()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.losses.detected");

        QuicMetrics.RecordRuntimeDetectedPacketLoss(
            QuicTlsRole.Client,
            QuicPacketNumberSpace.ApplicationData);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.losses.detected"
            && measurement.Value == 1
            && measurement.HasTag("role", "client")
            && measurement.HasTag("packet_number_space", "application_data"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RecoveryProgressEmitsApplicationSendRecoveryMetrics()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(
            QuicMetrics.MeterName,
            "incursa.quic.runtime.application_send.recovery.flushes");
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        if (congestion.BytesInFlightBytes < congestion.CongestionWindowBytes)
        {
            congestion.RegisterPacketSent(congestion.CongestionWindowBytes - congestion.BytesInFlightBytes);
        }

        await stream.WriteAsync(new byte[] { 0xD1 });
        _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1,
            largestAcknowledged: openPacket.Key.PacketNumber);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.application_send.recovery.flushes"
            && measurement.Value == 1
            && measurement.HasTag("role", "client")
            && measurement.HasTag("outcome", "queue_drained")
            && measurement.HasTag("blocked_reason", "none"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RuntimeFollowOnFlushMeasurementCoversDirectFlowControlFlush()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();

        runtime.BeginRuntimeWorkItemFlushMeasurement();
        _ = runtime.Transition(
            new QuicConnectionFlowControlCreditUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicMaxDataFrame(128),
                new QuicMaxStreamDataFrame(1, 64)),
            nowTicks: 10);
        runtime.TakeRuntimeWorkItemFlushMeasurement(
            out int applicationSendCount,
            out int flowControlCount,
            out int streamCapacityCount);

        Assert.Equal(0, applicationSendCount);
        Assert.Equal(2, flowControlCount);
        Assert.Equal(0, streamCapacityCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task RuntimeFollowOnFlushMeasurementCoversDirectStreamCapacityFlush()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        QuicConnectionStreamState state = runtime.StreamRegistry.Bookkeeping;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 1, streamData: []),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryAbortLocalStreamWrites(1, out _, out errorCode));
        Assert.Equal(default, errorCode);
        runtime.TryQueueStreamCapacityRelease(streamId: 1);

        runtime.BeginRuntimeWorkItemFlushMeasurement();
        _ = runtime.TransitionStreamCapacityRelease(nowTicks: 10);
        runtime.TakeRuntimeWorkItemFlushMeasurement(
            out int applicationSendCount,
            out int flowControlCount,
            out int streamCapacityCount);

        Assert.Equal(0, applicationSendCount);
        Assert.Equal(0, flowControlCount);
        Assert.Equal(1, streamCapacityCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task StreamWriteCompletionMetricCapturesBoundedActionAndOutcomeTags()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        await using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            _ = runtime.Transition(connectionEvent);
            return true;
        });

        await runtime.WriteStreamAsync(streamId.Value, new byte[] { 0x01 });

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.stream_write.completion.ms"
            && measurement.Value >= 0
            && measurement.HasTag("role", "client")
            && measurement.HasTag("action", "write")
            && measurement.HasTag("outcome", "succeeded"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task StreamWriteCompletionMetricReportsCompletionActionFailure()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        await using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            _ = runtime.Transition(connectionEvent);
            return true;
        });

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await runtime.WriteStreamAsync(
                streamId.Value,
                new byte[] { 0x01 },
                () => throw new InvalidOperationException("completion-action-fault")));

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.stream_write.completion.ms"
            && measurement.HasTag("outcome", "failed"));
        Assert.DoesNotContain(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.stream_write.completion.ms"
            && measurement.HasTag("outcome", "succeeded"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0098")]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task QuicRuntimeShardMetricsIgnoreDisposedEnqueueAttempts()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        await using QuicConnectionRuntimeShard shard = new(3, clock);

        await shard.DisposeAsync();

        Assert.False(shard.TryPostFlowControlCreditUpdate(new QuicConnectionHandle(1), runtime));
        Assert.DoesNotContain(
            recorder.Measurements,
            measurement => measurement.InstrumentName.StartsWith("incursa.quic.runtime.shard", StringComparison.Ordinal));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0098")]
    [Requirement("REQ-QUIC-CRT-0155")]
    public async Task QuicRuntimeShardMetricsAccountForActualDueTimerWork()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        await using QuicConnectionRuntimeShard shard = new(4, clock);
        QuicConnectionHandle handle = new(55);
        QuicConnectionArmTimerEffect arm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(runtime.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));
        shard.DeadlineScheduler.Apply(handle, runtime, arm);
        clock.Advance(10);

        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        Task consumer = shard.RunAsync(cancellationToken: timeout.Token);

        await WaitForMeasurementAsync(
            recorder,
            "incursa.quic.runtime.shard.work_items.dequeued",
            "work_item_kind",
            "event");
        recorder.RecordObservableInstruments();
        Assert.Equal(0d, recorder.GetLatestMeasurement(
            "incursa.quic.runtime.shard.inbox.depth",
            "shard_index",
            "4"));

        await shard.DisposeAsync();
        await consumer;

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.work_items.enqueued"
            && measurement.Value == 1
            && measurement.HasTag("shard_index", "4")
            && measurement.HasTag("work_item_kind", "event"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.work_items.dequeued"
            && measurement.Value == 1
            && measurement.HasTag("shard_index", "4")
            && measurement.HasTag("work_item_kind", "event"));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0098")]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void QuicRuntimeShardMetricsUseTheDocumentedBoundedWorkItemKinds()
    {
        FakeMonotonicClock clock = new(0);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionHandle handle = new(56);
        QuicConnectionRuntimeShardWorkItem[] workItems =
        [
            new(handle, runtime, new QuicConnectionTimerExpiredEvent(0, QuicConnectionTimerKind.IdleTimeout, 1)),
            new(
                handle,
                runtime,
                new QuicConnectionPacketReceivedContext(
                    0,
                    new QuicConnectionPathIdentity("127.0.0.1", "127.0.0.1", 443, 50000),
                    new byte[] { 0 }),
                ownedDatagramBuffer: null,
                ownedDatagramBufferOwnership: default),
            new(handle, runtime, QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease),
            new(handle, runtime, QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate),
            new(handle, runtime, requestId: 1, QuicStreamType.Bidirectional),
            new(handle, runtime, requestId: 2, QuicConnectionStreamActionKind.Write, streamId: 0, ReadOnlyMemory<byte>.Empty),
            default,
        ];

        Assert.Equal(
            [
                "event",
                "packet_received",
                "stream_capacity_release",
                "flow_control_credit_update",
                "stream_open",
                "stream_write",
                "deadline_wake",
            ],
            workItems.Select(workItem => QuicMetrics.NormalizeRuntimeShardWorkItemKind(in workItem)));
    }

    [Fact]
    [Requirement("REQ-QUIC-CRT-0155")]
    public void QuicRuntimeShardWakeCycleMetricsUseBoundedCompletionTags()
    {
        using MetricsRecorder recorder = MetricsRecorder.Start(QuicMetrics.MeterName);

        QuicMetrics.RecordRuntimeShardWakeCycle(shardIndex: 7, completedSynchronously: false, productiveWorkItems: 3);
        QuicMetrics.RecordRuntimeShardWakeCycle(shardIndex: 7, completedSynchronously: true, productiveWorkItems: 0);

        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.wakeups"
            && measurement.Value == 1
            && measurement.HasTag("shard_index", "7")
            && measurement.HasTag("completion", "async"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.work_items_per_wake"
            && measurement.Value == 3
            && measurement.HasTag("completion", "async"));
        Assert.Contains(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.empty_wakeups"
            && measurement.Value == 1
            && measurement.HasTag("completion", "sync"));
        Assert.DoesNotContain(recorder.Measurements, measurement =>
            measurement.InstrumentName == "incursa.quic.runtime.shard.empty_wakeups"
            && measurement.HasTag("completion", "async"));
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);
        return runtime;
    }

    private static string GetBufferSizeBucket(int length)
        => length switch
        {
            <= 1024 => "le_1kb",
            <= 4 * 1024 => "le_4kb",
            <= 16 * 1024 => "le_16kb",
            <= 64 * 1024 => "le_64kb",
            <= 256 * 1024 => "le_256kb",
            _ => "gt_256kb",
        };

    private static async Task WaitForMeasurementAsync(
        MetricsRecorder recorder,
        string instrumentName,
        string tagName,
        string tagValue)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while (!recorder.Measurements.Any(measurement =>
            measurement.InstrumentName == instrumentName
            && measurement.HasTag(tagName, tagValue)))
        {
            await Task.Delay(10, timeout.Token).ConfigureAwait(false);
        }
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

        private MetricsRecorder(string meterName, IReadOnlySet<string>? enabledInstrumentNames)
        {
            listener.InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == meterName
                    && (enabledInstrumentNames is null || enabledInstrumentNames.Contains(instrument.Name)))
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

        public static MetricsRecorder Start(string meterName, params string[] enabledInstrumentNames)
        {
            IReadOnlySet<string>? enabledInstrumentNameSet = enabledInstrumentNames.Length == 0
                ? null
                : enabledInstrumentNames.ToHashSet(StringComparer.Ordinal);
            return new MetricsRecorder(meterName, enabledInstrumentNameSet);
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

        public double GetLatestMeasurement(
            string instrumentName,
            string firstTagName,
            string firstTagValue,
            string secondTagName,
            string secondTagValue)
        {
            lock (sync)
            {
                return measurements.Last(measurement =>
                    measurement.InstrumentName == instrumentName
                    && measurement.HasTag(firstTagName, firstTagValue)
                    && measurement.HasTag(secondTagName, secondTagValue)).Value;
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
