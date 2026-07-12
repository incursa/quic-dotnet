// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net.Sockets;
using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Owns the standard QUIC metrics surface without coupling the transport to a collector.
/// </summary>
internal static class QuicMetrics
{
    // CONTEXT: The meter name and tag keys are externally visible metrics-contract surface, so
    // they must stay stable once emitted rather than being treated as local implementation detail.
    // SEE: RecordConnectionStarted and RecordStreamOpened
    internal const string MeterName = "Incursa.Quic";
    internal const string ClientRole = "client";
    internal const string ServerRole = "server";
    internal const string UnknownPacketType = "unknown";
    private const string RuntimeShardInboxDepthMetricName = "incursa.quic.runtime.shard.inbox.depth";
    private const string RuntimeShardWorkItemDepthMetricName = "incursa.quic.runtime.shard.work_item.depth";
    private const string RuntimeShardWorkItemsEnqueuedMetricName = "incursa.quic.runtime.shard.work_items.enqueued";
    private const string RuntimeShardWorkItemsDequeuedMetricName = "incursa.quic.runtime.shard.work_items.dequeued";
    private const string RuntimeShardQueueDelayMetricName = "incursa.quic.runtime.shard.queue_delay.ms";
    private const string RuntimeShardServiceTimeMetricName = "incursa.quic.runtime.shard.service_time.ms";
    private const string RuntimeFollowOnFlushItemsMetricName = "incursa.quic.runtime.follow_on_flush.items";
    private const string RuntimeShardIndexTagName = "shard_index";
    private const string RuntimeShardWorkItemKindTagName = "work_item_kind";
    private const double MicrosecondsPerMillisecond = 1000.0;
    private const int HttpStatusInformationalMin = 100;
    private const int HttpStatusInformationalMax = 199;
    private const int HttpStatusSuccessMin = 200;
    private const int HttpStatusSuccessMax = 299;
    private const int HttpStatusRedirectionMin = 300;
    private const int HttpStatusRedirectionMax = 399;
    private const int HttpStatusClientErrorMin = 400;
    private const int HttpStatusClientErrorMax = 499;
    private const int HttpStatusServerErrorMin = 500;
    private const int HttpStatusServerErrorMax = 599;
    private const int BytesPerKilobyte = 1024;
    private const int BufferPoolOneKilobyteBucket = BytesPerKilobyte;
    private const int BufferPoolFourKilobyteBucket = 4 * BytesPerKilobyte;
    private const int BufferPoolSixteenKilobyteBucket = 16 * BytesPerKilobyte;
    private const int BufferPoolSixtyFourKilobyteBucket = 64 * BytesPerKilobyte;
    private const int BufferPoolTwoHundredFiftySixKilobyteBucket = 256 * BytesPerKilobyte;
    private const int BufferPoolOneKilobyteBucketIndex = 0;
    private const int BufferPoolFourKilobyteBucketIndex = 1;
    private const int BufferPoolSixteenKilobyteBucketIndex = 2;
    private const int BufferPoolSixtyFourKilobyteBucketIndex = 3;
    private const int BufferPoolTwoHundredFiftySixKilobyteBucketIndex = 4;
    private const int BufferPoolGreaterThanTwoHundredFiftySixKilobyteBucketIndex = 5;
    private const int BufferPoolBucketCount = 6;
    private const int ClientRoleIndex = 0;
    private const int ServerRoleIndex = 1;
    private const int RoleCount = 2;

    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> ConnectionsStarted = Meter.CreateCounter<long>("incursa.quic.connections.started", unit: "connections");
    private static readonly UpDownCounter<long> ConnectionsActive = Meter.CreateUpDownCounter<long>("incursa.quic.connections.active", unit: "connections");
    private static readonly Counter<long> ConnectionsClosed = Meter.CreateCounter<long>("incursa.quic.connections.closed", unit: "connections");
    private static readonly Counter<long> StreamsOpened = Meter.CreateCounter<long>("incursa.quic.streams.opened", unit: "streams");
    private static readonly UpDownCounter<long> StreamsActive = Meter.CreateUpDownCounter<long>("incursa.quic.streams.active", unit: "streams");
    private static readonly Counter<long> StreamsClosed = Meter.CreateCounter<long>("incursa.quic.streams.closed", unit: "streams");
    private static readonly long[] DatagramReceivedCounts = new long[RoleCount];
    private static readonly long[] DatagramSentCounts = new long[RoleCount];
    private static readonly long[] ByteReceivedCounts = new long[RoleCount];
    private static readonly long[] ByteSentCounts = new long[RoleCount];
    private static readonly ObservableCounter<long> DatagramsReceived = Meter.CreateObservableCounter("incursa.quic.datagrams.received", () => ObserveRoleMetric(DatagramReceivedCounts), unit: "datagrams");
    private static readonly ObservableCounter<long> DatagramsSent = Meter.CreateObservableCounter("incursa.quic.datagrams.sent", () => ObserveRoleMetric(DatagramSentCounts), unit: "datagrams");
    private static readonly ObservableCounter<long> BytesReceived = Meter.CreateObservableCounter("incursa.quic.bytes.received", () => ObserveRoleMetric(ByteReceivedCounts), unit: "bytes");
    private static readonly ObservableCounter<long> BytesSent = Meter.CreateObservableCounter("incursa.quic.bytes.sent", () => ObserveRoleMetric(ByteSentCounts), unit: "bytes");
    private static readonly Counter<long> PacketsDropped = Meter.CreateCounter<long>("incursa.quic.packets.dropped", unit: "packets");
    private static readonly Counter<long> FlowControlBlocked = Meter.CreateCounter<long>("incursa.quic.flow_control.blocked", unit: "events");
    private static readonly Counter<long> StreamLimitBlocked = Meter.CreateCounter<long>("incursa.quic.stream_limit.blocked", unit: "events");
    private static readonly Counter<long> AntiAmplificationBlocked = Meter.CreateCounter<long>("incursa.quic.anti_amplification.blocked", unit: "events");
    private static readonly Counter<long> ProbeTimeoutCount = Meter.CreateCounter<long>("incursa.quic.pto.count", unit: "events");
    private static readonly Counter<long> AeadOpenFailures = Meter.CreateCounter<long>("incursa.quic.aead.open_failures", unit: "events");
    private static readonly Counter<long> UdpErrors = Meter.CreateCounter<long>("incursa.quic.udp.errors", unit: "events");
    private static readonly Histogram<double> Rtt = Meter.CreateHistogram<double>("incursa.quic.rtt.ms", unit: "ms");
    private static readonly UpDownCounter<long> RuntimeShardInboxDepth = Meter.CreateUpDownCounter<long>(RuntimeShardInboxDepthMetricName, unit: "work_items");
    private static readonly UpDownCounter<long> RuntimeShardWorkItemDepth = Meter.CreateUpDownCounter<long>(RuntimeShardWorkItemDepthMetricName, unit: "work_items");
    private static readonly Counter<long> RuntimeShardWorkItemsEnqueued = Meter.CreateCounter<long>(RuntimeShardWorkItemsEnqueuedMetricName, unit: "work_items");
    private static readonly Counter<long> RuntimeShardWorkItemsDequeued = Meter.CreateCounter<long>(RuntimeShardWorkItemsDequeuedMetricName, unit: "work_items");
    private static readonly Histogram<double> RuntimeShardQueueDelay = Meter.CreateHistogram<double>(RuntimeShardQueueDelayMetricName, unit: "ms");
    private static readonly Histogram<double> RuntimeShardServiceTime = Meter.CreateHistogram<double>(RuntimeShardServiceTimeMetricName, unit: "ms");
    private static readonly Counter<long> RuntimeFollowOnFlushItems = Meter.CreateCounter<long>(RuntimeFollowOnFlushItemsMetricName, unit: "items");
    private static readonly Histogram<long> DelayedApplicationSends = Meter.CreateHistogram<long>("incursa.quic.runtime.delayed_application_sends", unit: "writes");
    private static readonly Histogram<long> ApplicationSendRetainedBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> ApplicationSendRetainedBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.retained_bytes", unit: "bytes");
    private static readonly Histogram<long> RetainedSentPackets = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained", unit: "packets");
    private static readonly Histogram<long> RetainedSentPacketBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> RetainedSentPacketBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained_bytes", unit: "bytes");
    private static readonly Histogram<double> RetainedSentPacketOldestAge = Meter.CreateHistogram<double>("incursa.quic.runtime.sent_packets.oldest_age.ms", unit: "ms");
    private static readonly Histogram<long> PendingRetransmissions = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.pending", unit: "retransmissions");
    private static readonly Histogram<long> PendingRetransmissionBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> PendingRetransmissionBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.retained_bytes", unit: "bytes");
    private static readonly Histogram<double> PendingRetransmissionOldestAge = Meter.CreateHistogram<double>("incursa.quic.runtime.retransmissions.oldest_age.ms", unit: "ms");
    private static readonly Histogram<long> ApplicationSendBatchStreams = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.batch_streams", unit: "streams");
    private static readonly Histogram<double> StreamWriteCompletion = Meter.CreateHistogram<double>("incursa.quic.runtime.stream_write.completion.ms", unit: "ms");
    private static readonly long[] BufferPoolRentCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolRequestedRentCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolReturnCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolRequestedByteCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolRentedByteCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolReturnedByteCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolOversizedRentCounts = new long[BufferPoolBucketCount];
    private static readonly ObservableGauge<long> BufferPoolOutstandingBuffers = Meter.CreateObservableGauge("incursa.quic.buffer_pool.outstanding.buffers", ObserveBufferPoolOutstandingBuffers, unit: "buffers");
    private static readonly ObservableGauge<long> BufferPoolOutstandingBytes = Meter.CreateObservableGauge("incursa.quic.buffer_pool.outstanding.bytes", ObserveBufferPoolOutstandingBytes, unit: "bytes");
    private static readonly ObservableCounter<long> BufferPoolRents = Meter.CreateObservableCounter("incursa.quic.buffer_pool.rents", () => ObserveBufferPoolMetric(BufferPoolRentCounts, "size_bucket"), unit: "buffers");
    private static readonly ObservableCounter<long> BufferPoolRequestedRents = Meter.CreateObservableCounter("incursa.quic.buffer_pool.requested_rents", () => ObserveBufferPoolMetric(BufferPoolRequestedRentCounts, "requested_size_bucket"), unit: "buffers");
    private static readonly ObservableCounter<long> BufferPoolReturns = Meter.CreateObservableCounter("incursa.quic.buffer_pool.returns", () => ObserveBufferPoolMetric(BufferPoolReturnCounts, "size_bucket"), unit: "buffers");
    private static readonly ObservableCounter<long> BufferPoolBytesRequested = Meter.CreateObservableCounter("incursa.quic.buffer_pool.bytes.requested", () => ObserveBufferPoolMetric(BufferPoolRequestedByteCounts, "requested_size_bucket"), unit: "bytes");
    private static readonly ObservableCounter<long> BufferPoolBytesRented = Meter.CreateObservableCounter("incursa.quic.buffer_pool.bytes.rented", () => ObserveBufferPoolMetric(BufferPoolRentedByteCounts, "size_bucket"), unit: "bytes");
    private static readonly ObservableCounter<long> BufferPoolBytesReturned = Meter.CreateObservableCounter("incursa.quic.buffer_pool.bytes.returned", () => ObserveBufferPoolMetric(BufferPoolReturnedByteCounts, "size_bucket"), unit: "bytes");
    private static readonly ObservableCounter<long> BufferPoolOversizedRents = Meter.CreateObservableCounter("incursa.quic.buffer_pool.oversized_rents", () => ObserveBufferPoolMetric(BufferPoolOversizedRentCounts, "size_bucket"), unit: "buffers");
    private static readonly long[] BufferPoolOutstandingBufferCounts = new long[BufferPoolBucketCount];
    private static readonly long[] BufferPoolOutstandingByteCounts = new long[BufferPoolBucketCount];

    internal static void RecordConnectionStarted(QuicTlsRole role)
    {
        if (!ConnectionsStarted.Enabled && !ConnectionsActive.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        ConnectionsStarted.Add(1, in tags);
        ConnectionsActive.Add(1, in tags);
    }

    internal static void RecordConnectionClosed(QuicTlsRole role, QuicConnectionTerminalState? terminalState)
    {
        if (ConnectionsActive.Enabled)
        {
            TagList activeTags = default;
            activeTags.Add("role", GetRoleTag(role));
            ConnectionsActive.Add(-1, in activeTags);
        }

        if (!ConnectionsClosed.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("close_reason", terminalState.HasValue ? FormatCloseReason(terminalState.Value.Origin) : "disposed");
        ConnectionsClosed.Add(1, in tags);
    }

    internal static void RecordStreamOpened(QuicTlsRole role, ulong streamId, QuicStreamType streamType)
    {
        if (!StreamsOpened.Enabled && !StreamsActive.Enabled)
        {
            return;
        }

        TagList tags = CreateStreamTags(role, streamId, streamType);
        StreamsOpened.Add(1, in tags);
        StreamsActive.Add(1, in tags);
    }

    internal static void RecordStreamClosed(QuicTlsRole role, ulong streamId, QuicStreamType streamType)
    {
        if (StreamsActive.Enabled)
        {
            TagList activeTags = CreateStreamTags(role, streamId, streamType);
            StreamsActive.Add(-1, in activeTags);
        }

        if (!StreamsClosed.Enabled)
        {
            return;
        }

        TagList closedTags = CreateStreamTags(role, streamId, streamType);
        StreamsClosed.Add(1, in closedTags);
    }

    internal static void RecordDatagramReceived(QuicTlsRole role, int datagramLength)
    {
        if (datagramLength <= 0 || (!DatagramsReceived.Enabled && !BytesReceived.Enabled))
        {
            return;
        }

        var roleIndex = GetRoleIndex(role);
        Interlocked.Increment(ref DatagramReceivedCounts[roleIndex]);
        Interlocked.Add(ref ByteReceivedCounts[roleIndex], datagramLength);
    }

    internal static void RecordDatagramSent(QuicTlsRole role, int datagramLength)
    {
        if (datagramLength <= 0 || (!DatagramsSent.Enabled && !BytesSent.Enabled))
        {
            return;
        }

        var roleIndex = GetRoleIndex(role);
        Interlocked.Increment(ref DatagramSentCounts[roleIndex]);
        Interlocked.Add(ref ByteSentCounts[roleIndex], datagramLength);
    }

    internal static void RecordPacketDropped(QuicTlsRole role, string? packetType = null)
    {
        if (!PacketsDropped.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("packet_type", NormalizePacketType(packetType));
        PacketsDropped.Add(1, in tags);
    }

    internal static void RecordFlowControlBlocked(QuicTlsRole role)
    {
        if (!FlowControlBlocked.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        FlowControlBlocked.Add(1, in tags);
    }

    internal static void RecordStreamLimitBlocked(QuicTlsRole role, bool bidirectional)
    {
        if (!StreamLimitBlocked.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("direction", bidirectional ? "bidirectional" : "unidirectional");
        StreamLimitBlocked.Add(1, in tags);
    }

    internal static void RecordAntiAmplificationBlocked(QuicTlsRole role)
    {
        if (!AntiAmplificationBlocked.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        AntiAmplificationBlocked.Add(1, in tags);
    }

    internal static void RecordProbeTimeout(QuicTlsRole role, QuicPacketNumberSpace packetNumberSpace)
    {
        if (!ProbeTimeoutCount.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("packet_type", FormatPacketNumberSpace(packetNumberSpace));
        ProbeTimeoutCount.Add(1, in tags);
    }

    internal static void RecordAeadOpenFailure(QuicAeadAlgorithm algorithm)
    {
        if (!AeadOpenFailures.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("algorithm", FormatAeadAlgorithm(algorithm));
        AeadOpenFailures.Add(1, in tags);
    }

    internal static void RecordUdpError(QuicTlsRole role, string direction, SocketError socketError)
    {
        if (!UdpErrors.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("direction", NormalizeUdpDirection(direction));
        tags.Add("socket_error", NormalizeSocketError(socketError));
        UdpErrors.Add(1, in tags);
    }

    internal static void RecordRtt(QuicTlsRole role, ulong rttMicros)
    {
        if (!Rtt.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        Rtt.Record(rttMicros / MicrosecondsPerMillisecond, in tags);
    }

    internal static void RecordRuntimeShardWorkItemEnqueued(int shardIndex, in QuicConnectionRuntimeShardWorkItem workItem)
    {
        if (!RuntimeShardInboxDepth.Enabled
            && !RuntimeShardWorkItemDepth.Enabled
            && !RuntimeShardWorkItemsEnqueued.Enabled)
        {
            return;
        }

        if (RuntimeShardInboxDepth.Enabled)
        {
            TagList depthTags = default;
            depthTags.Add(RuntimeShardIndexTagName, shardIndex);
            RuntimeShardInboxDepth.Add(1, in depthTags);
        }

        if (RuntimeShardWorkItemDepth.Enabled)
        {
            TagList workItemDepthTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
            RuntimeShardWorkItemDepth.Add(1, in workItemDepthTags);
        }

        if (RuntimeShardWorkItemsEnqueued.Enabled)
        {
            TagList workItemTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
            RuntimeShardWorkItemsEnqueued.Add(1, in workItemTags);
        }
    }

    internal static void RecordRuntimeShardWorkItemDequeued(int shardIndex, in QuicConnectionRuntimeShardWorkItem workItem)
    {
        if (!RuntimeShardInboxDepth.Enabled
            && !RuntimeShardWorkItemDepth.Enabled
            && !RuntimeShardWorkItemsDequeued.Enabled
            && !RuntimeShardQueueDelay.Enabled)
        {
            return;
        }

        if (RuntimeShardInboxDepth.Enabled)
        {
            TagList depthTags = default;
            depthTags.Add(RuntimeShardIndexTagName, shardIndex);
            RuntimeShardInboxDepth.Add(-1, in depthTags);
        }

        if (RuntimeShardWorkItemDepth.Enabled)
        {
            TagList workItemDepthTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
            RuntimeShardWorkItemDepth.Add(-1, in workItemDepthTags);
        }

        if (RuntimeShardWorkItemsDequeued.Enabled)
        {
            TagList workItemTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
            RuntimeShardWorkItemsDequeued.Add(1, in workItemTags);
        }

        if (RuntimeShardQueueDelay.Enabled && workItem.EnqueuedTimestamp != 0)
        {
            TagList queueDelayTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
            RuntimeShardQueueDelay.Record(
                Stopwatch.GetElapsedTime(workItem.EnqueuedTimestamp).TotalMilliseconds,
                in queueDelayTags);
        }
    }

    internal static long GetRuntimeShardEnqueueTimestamp()
        => RuntimeShardQueueDelay.Enabled ? Stopwatch.GetTimestamp() : 0;

    internal static long GetRuntimeShardServiceStartTimestamp()
        => RuntimeShardServiceTime.Enabled ? Stopwatch.GetTimestamp() : 0;

    internal static void RecordRuntimeShardServiceTime(
        int shardIndex,
        in QuicConnectionRuntimeShardWorkItem workItem,
        long startedTimestamp)
    {
        if (!RuntimeShardServiceTime.Enabled || startedTimestamp == 0)
        {
            return;
        }

        TagList tags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
        RuntimeShardServiceTime.Record(Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds, in tags);
    }

    internal static bool RuntimeFollowOnFlushMetricsEnabled => RuntimeFollowOnFlushItems.Enabled;

    internal static void RecordApplicationSendBatchStreams(QuicTlsRole role, int streamCount, bool combinedWrite)
    {
        if (!ApplicationSendBatchStreams.Enabled || streamCount <= 0)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("batch_kind", combinedWrite ? "combined_write" : "single_write");
        ApplicationSendBatchStreams.Record(streamCount, in tags);
    }

    internal static void RecordRuntimeFollowOnFlushItems(
        int shardIndex,
        in QuicConnectionRuntimeShardWorkItem workItem,
        int applicationSendCount,
        int flowControlCount,
        int streamCapacityCount)
    {
        if (!RuntimeFollowOnFlushItems.Enabled)
        {
            return;
        }

        RecordRuntimeFollowOnFlushItems(shardIndex, in workItem, "application_send", applicationSendCount);
        RecordRuntimeFollowOnFlushItems(shardIndex, in workItem, "flow_control", flowControlCount);
        RecordRuntimeFollowOnFlushItems(shardIndex, in workItem, "stream_capacity", streamCapacityCount);
    }

    private static void RecordRuntimeFollowOnFlushItems(
        int shardIndex,
        in QuicConnectionRuntimeShardWorkItem workItem,
        string flushKind,
        int count)
    {
        if (count <= 0)
        {
            return;
        }

        TagList tags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
        tags.Add("flush_kind", flushKind);
        RuntimeFollowOnFlushItems.Add(count, in tags);
    }

    internal static void RecordRuntimePressureSnapshot(int shardIndex, QuicConnectionRuntime runtime)
    {
        bool applicationSendRetentionEnabled =
            ApplicationSendRetainedBuffers.Enabled || ApplicationSendRetainedBytes.Enabled;
        bool sentPacketRetentionEnabled =
            RetainedSentPacketBuffers.Enabled || RetainedSentPacketBytes.Enabled || RetainedSentPacketOldestAge.Enabled;
        bool retransmissionRetentionEnabled =
            PendingRetransmissionBuffers.Enabled || PendingRetransmissionBytes.Enabled || PendingRetransmissionOldestAge.Enabled;
        if (!DelayedApplicationSends.Enabled
            && !RetainedSentPackets.Enabled
            && !PendingRetransmissions.Enabled
            && !applicationSendRetentionEnabled
            && !sentPacketRetentionEnabled
            && !retransmissionRetentionEnabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add(RuntimeShardIndexTagName, shardIndex);
        if (DelayedApplicationSends.Enabled)
        {
            DelayedApplicationSends.Record(runtime.DelayedApplicationSendCount, in tags);
        }

        if (applicationSendRetentionEnabled)
        {
            QuicRetentionSnapshot snapshot = runtime.CaptureApplicationSendRetentionSnapshot();
            if (ApplicationSendRetainedBuffers.Enabled)
            {
                ApplicationSendRetainedBuffers.Record(snapshot.RetainedBufferCount, in tags);
            }

            if (ApplicationSendRetainedBytes.Enabled)
            {
                ApplicationSendRetainedBytes.Record(snapshot.RetainedByteCount, in tags);
            }
        }

        if (RetainedSentPackets.Enabled)
        {
            RetainedSentPackets.Record(runtime.RetainedSentPacketCount, in tags);
        }

        if (sentPacketRetentionEnabled)
        {
            QuicRetentionSnapshot snapshot = runtime.CaptureSentPacketRetentionSnapshot();
            if (RetainedSentPacketBuffers.Enabled)
            {
                RetainedSentPacketBuffers.Record(snapshot.RetainedBufferCount, in tags);
            }

            if (RetainedSentPacketBytes.Enabled)
            {
                RetainedSentPacketBytes.Record(snapshot.RetainedByteCount, in tags);
            }

            if (RetainedSentPacketOldestAge.Enabled && snapshot.OldestAgeMilliseconds.HasValue)
            {
                RetainedSentPacketOldestAge.Record(snapshot.OldestAgeMilliseconds.Value, in tags);
            }
        }

        if (PendingRetransmissions.Enabled)
        {
            PendingRetransmissions.Record(runtime.PendingRetransmissionCount, in tags);
        }

        if (retransmissionRetentionEnabled)
        {
            QuicRetentionSnapshot snapshot = runtime.CaptureRetransmissionRetentionSnapshot();
            if (PendingRetransmissionBuffers.Enabled)
            {
                PendingRetransmissionBuffers.Record(snapshot.RetainedBufferCount, in tags);
            }

            if (PendingRetransmissionBytes.Enabled)
            {
                PendingRetransmissionBytes.Record(snapshot.RetainedByteCount, in tags);
            }

            if (PendingRetransmissionOldestAge.Enabled && snapshot.OldestAgeMilliseconds.HasValue)
            {
                PendingRetransmissionOldestAge.Record(snapshot.OldestAgeMilliseconds.Value, in tags);
            }
        }
    }

    internal static long GetStreamWriteStartTimestamp()
        => StreamWriteCompletion.Enabled ? Stopwatch.GetTimestamp() : 0;

    internal static void RecordStreamWriteCompletion(
        long startedTimestamp,
        QuicTlsRole role,
        QuicConnectionStreamActionKind actionKind,
        string outcome)
    {
        if (!StreamWriteCompletion.Enabled || startedTimestamp == 0)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("action", actionKind == QuicConnectionStreamActionKind.Finish ? "finish" : "write");
        tags.Add("outcome", outcome);
        StreamWriteCompletion.Record(Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds, in tags);
    }

    private static TagList CreateRuntimeShardWorkItemTags(
        int shardIndex,
        in QuicConnectionRuntimeShardWorkItem workItem)
    {
        TagList tags = default;
        tags.Add(RuntimeShardIndexTagName, shardIndex);
        tags.Add(RuntimeShardWorkItemKindTagName, NormalizeRuntimeShardWorkItemKind(in workItem));
        return tags;
    }

    internal static void RecordBufferRent(int requestedLength, int rentedLength)
    {
        if (!BufferPoolRents.Enabled
            && !BufferPoolRequestedRents.Enabled
            && !BufferPoolBytesRequested.Enabled
            && !BufferPoolBytesRented.Enabled
            && !BufferPoolOutstandingBuffers.Enabled
            && !BufferPoolOutstandingBytes.Enabled
            && !BufferPoolOversizedRents.Enabled)
        {
            return;
        }

        var bucketIndex = GetBufferSizeBucketIndex(rentedLength);
        var requestedBucketIndex = GetBufferSizeBucketIndex(requestedLength);
        Interlocked.Increment(ref BufferPoolRequestedRentCounts[requestedBucketIndex]);
        Interlocked.Add(ref BufferPoolRequestedByteCounts[requestedBucketIndex], requestedLength);
        Interlocked.Increment(ref BufferPoolRentCounts[bucketIndex]);
        Interlocked.Add(ref BufferPoolRentedByteCounts[bucketIndex], rentedLength);
        Interlocked.Increment(ref BufferPoolOutstandingBufferCounts[bucketIndex]);
        Interlocked.Add(ref BufferPoolOutstandingByteCounts[bucketIndex], rentedLength);

        if (rentedLength > requestedLength)
        {
            Interlocked.Increment(ref BufferPoolOversizedRentCounts[bucketIndex]);
        }
    }

    internal static void RecordBufferReturn(int bufferLength)
    {
        if (!BufferPoolReturns.Enabled
            && !BufferPoolBytesReturned.Enabled
            && !BufferPoolOutstandingBuffers.Enabled
            && !BufferPoolOutstandingBytes.Enabled)
        {
            return;
        }

        var bucketIndex = GetBufferSizeBucketIndex(bufferLength);
        Interlocked.Increment(ref BufferPoolReturnCounts[bucketIndex]);
        Interlocked.Add(ref BufferPoolReturnedByteCounts[bucketIndex], bufferLength);
        DecrementBufferPoolOutstanding(bucketIndex, bufferLength);
    }

    internal static string GetRoleTag(QuicTlsRole role)
    {
        return role == QuicTlsRole.Server ? ServerRole : ClientRole;
    }

    internal static string GetDirectionTag(QuicStreamType streamType)
    {
        return streamType == QuicStreamType.Bidirectional ? "bidirectional" : "unidirectional";
    }

    internal static string GetInitiatorTag(QuicTlsRole role, ulong streamId)
    {
        bool clientInitiated = (streamId & 0x01) == 0;
        bool locallyInitiated = role == QuicTlsRole.Client ? clientInitiated : !clientInitiated;
        return locallyInitiated ? "local" : "remote";
    }

    internal static string GetStatusClass(int statusCode)
    {
        return statusCode switch
        {
            >= HttpStatusInformationalMin and <= HttpStatusInformationalMax => "1xx",
            >= HttpStatusSuccessMin and <= HttpStatusSuccessMax => "2xx",
            >= HttpStatusRedirectionMin and <= HttpStatusRedirectionMax => "3xx",
            >= HttpStatusClientErrorMin and <= HttpStatusClientErrorMax => "4xx",
            >= HttpStatusServerErrorMin and <= HttpStatusServerErrorMax => "5xx",
            _ => "unknown",
        };
    }

    internal static string NormalizePacketType(string? packetType)
    {
        return packetType switch
        {
            "initial" => "initial",
            "handshake" => "handshake",
            "1rtt" => "1rtt",
            "retry" => "retry",
            "version_negotiation" => "version_negotiation",
            _ => UnknownPacketType,
        };
    }

    private static string FormatAeadAlgorithm(QuicAeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            QuicAeadAlgorithm.Aes128Gcm => "aes-128-gcm",
            QuicAeadAlgorithm.Aes256Gcm => "aes-256-gcm",
            QuicAeadAlgorithm.Aes128Ccm => "aes-128-ccm",
            QuicAeadAlgorithm.Chacha20Poly1305 => "chacha20-poly1305",
            _ => "unknown",
        };
    }

    private static string NormalizeUdpDirection(string direction)
    {
        return direction switch
        {
            "receive" => "receive",
            "send" => "send",
            _ => "unknown",
        };
    }

    private static string NormalizeSocketError(SocketError socketError)
    {
        return socketError switch
        {
            SocketError.ConnectionReset => "connection_reset",
            SocketError.ConnectionAborted => "connection_aborted",
            SocketError.ConnectionRefused => "connection_refused",
            SocketError.TimedOut => "timed_out",
            SocketError.MessageSize => "message_size",
            SocketError.NetworkDown => "network_down",
            SocketError.NetworkUnreachable => "network_unreachable",
            SocketError.HostUnreachable => "host_unreachable",
            SocketError.NoBufferSpaceAvailable => "no_buffer_space",
            SocketError.Interrupted => "interrupted",
            SocketError.OperationAborted => "operation_aborted",
            SocketError.WouldBlock => "would_block",
            SocketError.AccessDenied => "access_denied",
            _ => "other",
        };
    }

    private static TagList CreateStreamTags(QuicTlsRole role, ulong streamId, QuicStreamType streamType)
    {
        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("direction", GetDirectionTag(streamType));
        tags.Add("initiator", GetInitiatorTag(role, streamId));
        return tags;
    }

    private static IEnumerable<Measurement<long>> ObserveBufferPoolOutstandingBuffers()
    {
        for (var i = 0; i < BufferPoolBucketCount; i++)
        {
            yield return new Measurement<long>(
                Volatile.Read(ref BufferPoolOutstandingBufferCounts[i]),
                new KeyValuePair<string, object?>("size_bucket", GetBufferSizeBucket(i)));
        }
    }

    private static IEnumerable<Measurement<long>> ObserveBufferPoolOutstandingBytes()
    {
        for (var i = 0; i < BufferPoolBucketCount; i++)
        {
            yield return new Measurement<long>(
                Volatile.Read(ref BufferPoolOutstandingByteCounts[i]),
                new KeyValuePair<string, object?>("size_bucket", GetBufferSizeBucket(i)));
        }
    }

    private static IEnumerable<Measurement<long>> ObserveBufferPoolMetric(long[] values, string tagName)
    {
        for (var i = 0; i < BufferPoolBucketCount; i++)
        {
            yield return new Measurement<long>(
                Volatile.Read(ref values[i]),
                new KeyValuePair<string, object?>(tagName, GetBufferSizeBucket(i)));
        }
    }

    private static IEnumerable<Measurement<long>> ObserveRoleMetric(long[] values)
    {
        for (var i = 0; i < RoleCount; i++)
        {
            yield return new Measurement<long>(
                Volatile.Read(ref values[i]),
                new KeyValuePair<string, object?>("role", GetRoleTag(i)));
        }
    }

    private static void DecrementBufferPoolOutstanding(int bucketIndex, int bufferLength)
    {
        var buffers = Interlocked.Decrement(ref BufferPoolOutstandingBufferCounts[bucketIndex]);
        if (buffers < 0)
        {
            Interlocked.Exchange(ref BufferPoolOutstandingBufferCounts[bucketIndex], 0);
        }

        var bytes = Interlocked.Add(ref BufferPoolOutstandingByteCounts[bucketIndex], -bufferLength);
        if (bytes < 0)
        {
            Interlocked.Exchange(ref BufferPoolOutstandingByteCounts[bucketIndex], 0);
        }
    }

    private static int GetBufferSizeBucketIndex(int bufferLength)
    {
        return bufferLength switch
        {
            <= BufferPoolOneKilobyteBucket => BufferPoolOneKilobyteBucketIndex,
            <= BufferPoolFourKilobyteBucket => BufferPoolFourKilobyteBucketIndex,
            <= BufferPoolSixteenKilobyteBucket => BufferPoolSixteenKilobyteBucketIndex,
            <= BufferPoolSixtyFourKilobyteBucket => BufferPoolSixtyFourKilobyteBucketIndex,
            <= BufferPoolTwoHundredFiftySixKilobyteBucket => BufferPoolTwoHundredFiftySixKilobyteBucketIndex,
            _ => BufferPoolGreaterThanTwoHundredFiftySixKilobyteBucketIndex,
        };
    }

    private static int GetRoleIndex(QuicTlsRole role)
    {
        return role == QuicTlsRole.Server ? ServerRoleIndex : ClientRoleIndex;
    }

    private static string GetRoleTag(int roleIndex)
    {
        return roleIndex == ServerRoleIndex ? ServerRole : ClientRole;
    }

    private static string GetBufferSizeBucket(int bucketIndex)
    {
        return bucketIndex switch
        {
            BufferPoolOneKilobyteBucketIndex => "le_1kb",
            BufferPoolFourKilobyteBucketIndex => "le_4kb",
            BufferPoolSixteenKilobyteBucketIndex => "le_16kb",
            BufferPoolSixtyFourKilobyteBucketIndex => "le_64kb",
            BufferPoolTwoHundredFiftySixKilobyteBucketIndex => "le_256kb",
            _ => "gt_256kb",
        };
    }

    private static string FormatPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        return packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => "initial",
            QuicPacketNumberSpace.Handshake => "handshake",
            QuicPacketNumberSpace.ApplicationData => "1rtt",
            _ => UnknownPacketType,
        };
    }

    internal static string NormalizeRuntimeShardWorkItemKind(in QuicConnectionRuntimeShardWorkItem workItem)
    {
        if (IsDeadlineWakeWorkItem(in workItem))
        {
            return "deadline_wake";
        }

        return workItem.Kind switch
        {
            QuicConnectionRuntimeShardWorkItemKind.Event => "event",
            QuicConnectionRuntimeShardWorkItemKind.PacketReceived => "packet_received",
            QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease => "stream_capacity_release",
            QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate => "flow_control_credit_update",
            QuicConnectionRuntimeShardWorkItemKind.StreamOpen => "stream_open",
            QuicConnectionRuntimeShardWorkItemKind.StreamWrite => "stream_write",
            _ => "unknown",
        };
    }

    private static bool IsDeadlineWakeWorkItem(in QuicConnectionRuntimeShardWorkItem workItem)
    {
        return workItem.Runtime is null
            && workItem.ConnectionEvent is null
            && workItem.Kind == QuicConnectionRuntimeShardWorkItemKind.Event;
    }

    private static string FormatCloseReason(QuicConnectionCloseOrigin closeOrigin)
    {
        return closeOrigin switch
        {
            QuicConnectionCloseOrigin.Local => "local",
            QuicConnectionCloseOrigin.Remote => "remote",
            QuicConnectionCloseOrigin.StatelessReset => "stateless_reset",
            QuicConnectionCloseOrigin.IdleTimeout => "idle_timeout",
            QuicConnectionCloseOrigin.ProtocolViolation => "protocol_violation",
            QuicConnectionCloseOrigin.Application => "application",
            QuicConnectionCloseOrigin.VersionNegotiation => "version_negotiation",
            _ => "unknown",
        };
    }
}
