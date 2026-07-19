// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;

namespace Incursa.Quic;

internal enum QuicApplicationSendRecoveryFlushOutcome
{
    QueueDrained,
    BurstLimitReached,
    BudgetBlocked,
    RetransmissionPending,
    FlushBlocked,
    FlushFailed,
}

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
    private const string RuntimeShardWakeupsMetricName = "incursa.quic.runtime.shard.wakeups";
    private const string RuntimeShardEmptyWakeupsMetricName = "incursa.quic.runtime.shard.empty_wakeups";
    private const string RuntimeShardWorkItemsPerWakeMetricName = "incursa.quic.runtime.shard.work_items_per_wake";
    private const string RuntimeFollowOnFlushItemsMetricName = "incursa.quic.runtime.follow_on_flush.items";
    private const string RuntimeShardIndexTagName = "shard_index";
    private const string RuntimeShardWorkItemKindTagName = "work_item_kind";
    private const string RuntimeShardWakeCompletionTagName = "completion";
    private const string QueueCauseTagName = "queue_cause";
    private const string BufferOwnerTagName = "owner";
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
    private const int RuntimeShardDeadlineWakeWorkItemKindIndex = (int)QuicConnectionRuntimeShardWorkItemKind.StreamWrite + 1;
    private const int RuntimeShardWorkItemKindCount = RuntimeShardDeadlineWakeWorkItemKindIndex + 1;
    private const int MaximumRuntimePressureWorkItemsPerSnapshot = 32;
    private static readonly long RuntimePressureSnapshotMinimumIntervalTicks = Stopwatch.Frequency / 4;

    internal sealed class RuntimeShardMetricsRegistration
    {
        private readonly ChannelReader<QuicConnectionRuntimeShardWorkItem> inbox;
        private readonly long[] workItemDepths = new long[RuntimeShardWorkItemKindCount];

        internal RuntimeShardMetricsRegistration(
            int shardIndex,
            ChannelReader<QuicConnectionRuntimeShardWorkItem> inbox)
        {
            ShardIndex = shardIndex;
            this.inbox = inbox;
        }

        internal int ShardIndex { get; }

        internal long InboxDepth => inbox.CanCount ? inbox.Count : GetTotalWorkItemDepth();

        internal void BeginEnqueue(in QuicConnectionRuntimeShardWorkItem workItem)
            => Interlocked.Increment(ref workItemDepths[GetRuntimeShardWorkItemKindIndex(in workItem)]);

        internal void CancelEnqueue(in QuicConnectionRuntimeShardWorkItem workItem)
            => Interlocked.Decrement(ref workItemDepths[GetRuntimeShardWorkItemKindIndex(in workItem)]);

        internal void RecordDequeue(in QuicConnectionRuntimeShardWorkItem workItem)
            => Interlocked.Decrement(ref workItemDepths[GetRuntimeShardWorkItemKindIndex(in workItem)]);

        internal long GetWorkItemDepth(int workItemKindIndex)
            => Volatile.Read(ref workItemDepths[workItemKindIndex]);

        private long GetTotalWorkItemDepth()
        {
            long total = 0;
            for (var i = 0; i < workItemDepths.Length; i++)
            {
                total += Volatile.Read(ref workItemDepths[i]);
            }

            return total;
        }

        private static int GetRuntimeShardWorkItemKindIndex(in QuicConnectionRuntimeShardWorkItem workItem)
        {
            if (IsDeadlineWakeWorkItem(in workItem))
            {
                return RuntimeShardDeadlineWakeWorkItemKindIndex;
            }

            return (int)workItem.Kind;
        }
    }

    private static readonly Meter Meter = new(MeterName);
    private static readonly QuicApplicationSendQueueCause[] ApplicationSendQueueCauses =
    [
        QuicApplicationSendQueueCause.PendingRetransmission,
        QuicApplicationSendQueueCause.OversizedWrite,
        QuicApplicationSendQueueCause.SmallWriteDelay,
        QuicApplicationSendQueueCause.DirectSendBlocked,
    ];
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
    internal static readonly ObservableGauge<long> RuntimeShardInboxDepth = Meter.CreateObservableGauge(RuntimeShardInboxDepthMetricName, ObserveRuntimeShardInboxDepth, unit: "work_items");
    internal static readonly ObservableGauge<long> RuntimeShardWorkItemDepth = Meter.CreateObservableGauge(RuntimeShardWorkItemDepthMetricName, ObserveRuntimeShardWorkItemDepth, unit: "work_items");
    private static readonly Counter<long> RuntimeShardWorkItemsEnqueued = Meter.CreateCounter<long>(RuntimeShardWorkItemsEnqueuedMetricName, unit: "work_items");
    private static readonly Counter<long> RuntimeShardWorkItemsDequeued = Meter.CreateCounter<long>(RuntimeShardWorkItemsDequeuedMetricName, unit: "work_items");
    private static readonly Histogram<double> RuntimeShardQueueDelay = Meter.CreateHistogram<double>(RuntimeShardQueueDelayMetricName, unit: "ms");
    private static readonly Histogram<double> RuntimeShardServiceTime = Meter.CreateHistogram<double>(RuntimeShardServiceTimeMetricName, unit: "ms");
    private static readonly Counter<long> RuntimeShardWakeups = Meter.CreateCounter<long>(RuntimeShardWakeupsMetricName, unit: "wakeups");
    private static readonly Counter<long> RuntimeShardEmptyWakeups = Meter.CreateCounter<long>(RuntimeShardEmptyWakeupsMetricName, unit: "wakeups");
    private static readonly Histogram<long> RuntimeShardWorkItemsPerWake = Meter.CreateHistogram<long>(RuntimeShardWorkItemsPerWakeMetricName, unit: "work_items");
    private static readonly Counter<long> RuntimeFollowOnFlushItems = Meter.CreateCounter<long>(RuntimeFollowOnFlushItemsMetricName, unit: "items");
    private static readonly Histogram<long> DelayedApplicationSends = Meter.CreateHistogram<long>("incursa.quic.runtime.delayed_application_sends", unit: "writes");
    private static readonly Histogram<long> ApplicationSendRetainedBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> ApplicationSendRetainedBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.retained_bytes", unit: "bytes");
    private static readonly Histogram<long> ApplicationSendCauseRetainedBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.cause.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> ApplicationSendCauseRetainedBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.cause.retained_bytes", unit: "bytes");
    private static readonly Histogram<double> ApplicationSendCauseOldestAge = Meter.CreateHistogram<double>("incursa.quic.runtime.application_send.cause.oldest_age.ms", unit: "ms");
    private static readonly Histogram<long> RetainedSentPackets = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained", unit: "packets");
    private static readonly Histogram<long> RetainedSentPacketBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> RetainedSentPacketBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.retained_bytes", unit: "bytes");
    private static readonly Histogram<double> RetainedSentPacketOldestAge = Meter.CreateHistogram<double>("incursa.quic.runtime.sent_packets.oldest_age.ms", unit: "ms");
    private static readonly Histogram<long> SentPacketNumberSpan = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.application_packet_number_span", unit: "packet_numbers");
    private static readonly Histogram<long> SentPacketStorageCapacity = Meter.CreateHistogram<long>("incursa.quic.runtime.sent_packets.storage.capacity", unit: "entries");
    private static readonly Histogram<long> PendingRetransmissions = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.pending", unit: "retransmissions");
    private static readonly Histogram<long> PendingRetransmissionBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> PendingRetransmissionBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.retransmissions.retained_bytes", unit: "bytes");
    private static readonly Histogram<double> PendingRetransmissionOldestAge = Meter.CreateHistogram<double>("incursa.quic.runtime.retransmissions.oldest_age.ms", unit: "ms");
    private static readonly Histogram<long> ReceiveRetainedBuffers = Meter.CreateHistogram<long>("incursa.quic.runtime.receive.retained_buffers", unit: "buffers");
    private static readonly Histogram<long> ReceiveRetainedBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.receive.retained_bytes", unit: "bytes");
    private static readonly Histogram<long> ReceiveBufferedBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.receive.buffered_bytes", unit: "bytes");
    private static readonly Histogram<long> ReceiveBufferedStreams = Meter.CreateHistogram<long>("incursa.quic.runtime.receive.buffered_streams", unit: "streams");
    private static readonly Histogram<long> ApplicationSendBatchStreams = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.batch_streams", unit: "streams");
    private static readonly Counter<long> ApplicationSendRecoveryFlushes = Meter.CreateCounter<long>("incursa.quic.runtime.application_send.recovery.flushes", unit: "flushes");
    private static readonly Histogram<long> ApplicationSendRecoveryCongestionWindow = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.congestion_window.bytes", unit: "bytes");
    private static readonly Histogram<long> ApplicationSendRecoveryBytesInFlight = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.bytes_in_flight.bytes", unit: "bytes");
    private static readonly Histogram<long> ApplicationSendRecoveryAvailableBytes = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.available_send.bytes", unit: "bytes");
    private static readonly Histogram<long> ApplicationSendRecoveryBudgetDatagrams = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.budget.datagrams", unit: "datagrams");
    private static readonly Histogram<long> ApplicationSendRecoveryFlushedDatagrams = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.flushed.datagrams", unit: "datagrams");
    private static readonly Histogram<long> ApplicationSendRecoveryQueueBefore = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.queue.before", unit: "writes");
    private static readonly Histogram<long> ApplicationSendRecoveryQueueAfter = Meter.CreateHistogram<long>("incursa.quic.runtime.application_send.recovery.queue.after", unit: "writes");
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
    private static readonly long[] BufferPoolOwnerRentCounts = new long[(int)QuicBufferPoolOwner.Count];
    private static readonly long[] BufferPoolOwnerRequestedByteCounts = new long[(int)QuicBufferPoolOwner.Count];
    private static readonly long[] BufferPoolOwnerRentedByteCounts = new long[(int)QuicBufferPoolOwner.Count];
    private static readonly ObservableCounter<long> BufferPoolOwnerRents = Meter.CreateObservableCounter(
        "incursa.quic.buffer_pool.owner.rents",
        () => ObserveBufferPoolOwnerMetric(BufferPoolOwnerRentCounts),
        unit: "buffers");
    private static readonly ObservableCounter<long> BufferPoolOwnerBytesRequested = Meter.CreateObservableCounter(
        "incursa.quic.buffer_pool.owner.bytes.requested",
        () => ObserveBufferPoolOwnerMetric(BufferPoolOwnerRequestedByteCounts),
        unit: "bytes");
    private static readonly ObservableCounter<long> BufferPoolOwnerBytesRented = Meter.CreateObservableCounter(
        "incursa.quic.buffer_pool.owner.bytes.rented",
        () => ObserveBufferPoolOwnerMetric(BufferPoolOwnerRentedByteCounts),
        unit: "bytes");
    private static RuntimeShardMetricsRegistration[] runtimeShardMetricsRegistrations = [];
    private static readonly object RuntimeShardMetricsRegistrationsSync = new();

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
        if (!RuntimeShardWorkItemsEnqueued.Enabled)
        {
            return;
        }

        TagList workItemTags = CreateRuntimeShardWorkItemTags(shardIndex, in workItem);
        RuntimeShardWorkItemsEnqueued.Add(1, in workItemTags);
    }

    internal static void RecordRuntimeShardWorkItemDequeued(
        RuntimeShardMetricsRegistration registration,
        in QuicConnectionRuntimeShardWorkItem workItem)
    {
        registration.RecordDequeue(in workItem);

        if (!RuntimeShardWorkItemsDequeued.Enabled
            && !RuntimeShardQueueDelay.Enabled)
        {
            return;
        }

        if (RuntimeShardWorkItemsDequeued.Enabled)
        {
            TagList workItemTags = CreateRuntimeShardWorkItemTags(registration.ShardIndex, in workItem);
            RuntimeShardWorkItemsDequeued.Add(1, in workItemTags);
        }

        if (RuntimeShardQueueDelay.Enabled && workItem.EnqueuedTimestamp != 0)
        {
            TagList queueDelayTags = CreateRuntimeShardWorkItemTags(registration.ShardIndex, in workItem);
            RuntimeShardQueueDelay.Record(
                Stopwatch.GetElapsedTime(workItem.EnqueuedTimestamp).TotalMilliseconds,
                in queueDelayTags);
        }
    }

    internal static RuntimeShardMetricsRegistration RegisterRuntimeShard(
        int shardIndex,
        ChannelReader<QuicConnectionRuntimeShardWorkItem> inbox)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(shardIndex);
        ArgumentNullException.ThrowIfNull(inbox);

        var registration = new RuntimeShardMetricsRegistration(shardIndex, inbox);
        lock (RuntimeShardMetricsRegistrationsSync)
        {
            RuntimeShardMetricsRegistration[] current = runtimeShardMetricsRegistrations;
            var updated = new RuntimeShardMetricsRegistration[current.Length + 1];
            Array.Copy(current, updated, current.Length);
            updated[^1] = registration;
            Volatile.Write(ref runtimeShardMetricsRegistrations, updated);
        }

        return registration;
    }

    internal static void UnregisterRuntimeShard(RuntimeShardMetricsRegistration registration)
    {
        lock (RuntimeShardMetricsRegistrationsSync)
        {
            RuntimeShardMetricsRegistration[] current = runtimeShardMetricsRegistrations;
            int index = Array.IndexOf(current, registration);
            if (index < 0)
            {
                return;
            }

            var updated = new RuntimeShardMetricsRegistration[current.Length - 1];
            Array.Copy(current, 0, updated, 0, index);
            Array.Copy(current, index + 1, updated, index, current.Length - index - 1);
            Volatile.Write(ref runtimeShardMetricsRegistrations, updated);
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

    internal static void RecordRuntimeShardWakeCycle(
        int shardIndex,
        bool completedSynchronously,
        int productiveWorkItems)
    {
        if (!RuntimeShardWakeups.Enabled
            && !RuntimeShardEmptyWakeups.Enabled
            && !RuntimeShardWorkItemsPerWake.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add(RuntimeShardIndexTagName, shardIndex);
        tags.Add(RuntimeShardWakeCompletionTagName, completedSynchronously ? "sync" : "async");
        RuntimeShardWakeups.Add(1, in tags);
        RuntimeShardWorkItemsPerWake.Record(productiveWorkItems, in tags);
        if (productiveWorkItems == 0)
        {
            RuntimeShardEmptyWakeups.Add(1, in tags);
        }
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

    internal static void RecordApplicationSendRecoveryFlush(
        QuicTlsRole role,
        QuicSendPolicySnapshot snapshot,
        QuicQueuedApplicationSendBudget budget,
        int queuedWritesBefore,
        int queuedWritesAfter,
        int flushedDatagrams,
        QuicApplicationSendRecoveryFlushOutcome outcome,
        QuicSendPolicyBlockedReason blockedReason)
    {
        if (!ApplicationSendRecoveryFlushes.Enabled
            && !ApplicationSendRecoveryCongestionWindow.Enabled
            && !ApplicationSendRecoveryBytesInFlight.Enabled
            && !ApplicationSendRecoveryAvailableBytes.Enabled
            && !ApplicationSendRecoveryBudgetDatagrams.Enabled
            && !ApplicationSendRecoveryFlushedDatagrams.Enabled
            && !ApplicationSendRecoveryQueueBefore.Enabled
            && !ApplicationSendRecoveryQueueAfter.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("outcome", FormatApplicationSendRecoveryFlushOutcome(outcome));
        tags.Add("blocked_reason", FormatSendPolicyBlockedReason(blockedReason));

        ApplicationSendRecoveryFlushes.Add(1, in tags);
        ApplicationSendRecoveryCongestionWindow.Record(ToInt64Saturating(snapshot.CongestionWindowBytes), in tags);
        ApplicationSendRecoveryBytesInFlight.Record(ToInt64Saturating(snapshot.BytesInFlightBytes), in tags);
        ApplicationSendRecoveryAvailableBytes.Record(ToInt64Saturating(ComputeAvailableSendBytes(snapshot)), in tags);
        ApplicationSendRecoveryBudgetDatagrams.Record(Math.Max(0, budget.MaxDatagrams), in tags);
        ApplicationSendRecoveryFlushedDatagrams.Record(Math.Max(0, flushedDatagrams), in tags);
        ApplicationSendRecoveryQueueBefore.Record(Math.Max(0, queuedWritesBefore), in tags);
        ApplicationSendRecoveryQueueAfter.Record(Math.Max(0, queuedWritesAfter), in tags);
    }

    internal static string FormatApplicationSendRecoveryFlushOutcome(
        QuicApplicationSendRecoveryFlushOutcome outcome)
        => outcome switch
        {
            QuicApplicationSendRecoveryFlushOutcome.QueueDrained => "queue_drained",
            QuicApplicationSendRecoveryFlushOutcome.BurstLimitReached => "burst_limit_reached",
            QuicApplicationSendRecoveryFlushOutcome.BudgetBlocked => "budget_blocked",
            QuicApplicationSendRecoveryFlushOutcome.RetransmissionPending => "retransmission_pending",
            QuicApplicationSendRecoveryFlushOutcome.FlushBlocked => "flush_blocked",
            QuicApplicationSendRecoveryFlushOutcome.FlushFailed => "flush_failed",
            _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
        };

    internal static string FormatSendPolicyBlockedReason(QuicSendPolicyBlockedReason blockedReason)
        => blockedReason switch
        {
            QuicSendPolicyBlockedReason.None => "none",
            QuicSendPolicyBlockedReason.NoQueuedApplicationData => "no_queued_application_data",
            QuicSendPolicyBlockedReason.NoActivePath => "no_active_path",
            QuicSendPolicyBlockedReason.OrdinaryPacketsUnavailable => "ordinary_packets_unavailable",
            QuicSendPolicyBlockedReason.OneRttProtectionUnavailable => "one_rtt_protection_unavailable",
            QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending => "application_data_retransmission_pending",
            QuicSendPolicyBlockedReason.InvalidPayloadBudget => "invalid_payload_budget",
            QuicSendPolicyBlockedReason.CongestionLimited => "congestion_limited",
            QuicSendPolicyBlockedReason.AntiAmplificationLimited => "anti_amplification_limited",
            QuicSendPolicyBlockedReason.InvalidQueuedApplicationSend => "invalid_queued_application_send",
            _ => throw new ArgumentOutOfRangeException(nameof(blockedReason)),
        };

    private static ulong ComputeAvailableSendBytes(QuicSendPolicySnapshot snapshot)
    {
        ulong congestionAvailableBytes = snapshot.CongestionWindowBytes > snapshot.BytesInFlightBytes
            ? snapshot.CongestionWindowBytes - snapshot.BytesInFlightBytes
            : 0;
        return snapshot.IsAddressValidated
            ? congestionAvailableBytes
            : Math.Min(congestionAvailableBytes, snapshot.AntiAmplificationAvailableBytes);
    }

    private static long ToInt64Saturating(ulong value)
        => value > long.MaxValue ? long.MaxValue : (long)value;

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
        bool applicationSendCauseRetentionEnabled =
            ApplicationSendCauseRetainedBuffers.Enabled
            || ApplicationSendCauseRetainedBytes.Enabled
            || ApplicationSendCauseOldestAge.Enabled;
        bool sentPacketRetentionEnabled =
            RetainedSentPacketBuffers.Enabled || RetainedSentPacketBytes.Enabled || RetainedSentPacketOldestAge.Enabled;
        bool sentPacketStorageEnabled =
            SentPacketStorageCapacity.Enabled
            || SentPacketNumberSpan.Enabled;
        bool sentPacketNumberSpanEnabled = SentPacketNumberSpan.Enabled;
        bool retransmissionRetentionEnabled =
            PendingRetransmissionBuffers.Enabled || PendingRetransmissionBytes.Enabled || PendingRetransmissionOldestAge.Enabled;
        bool receiveRetentionEnabled =
            ReceiveRetainedBuffers.Enabled
            || ReceiveRetainedBytes.Enabled
            || ReceiveBufferedBytes.Enabled
            || ReceiveBufferedStreams.Enabled;
        if (!DelayedApplicationSends.Enabled
            && !RetainedSentPackets.Enabled
            && !PendingRetransmissions.Enabled
            && !applicationSendRetentionEnabled
            && !applicationSendCauseRetentionEnabled
            && !sentPacketRetentionEnabled
            && !sentPacketStorageEnabled
            && !retransmissionRetentionEnabled
            && !receiveRetentionEnabled)
        {
            return;
        }

        if (!runtime.TryBeginRuntimePressureSnapshot(
                Stopwatch.GetTimestamp(),
                RuntimePressureSnapshotMinimumIntervalTicks,
                MaximumRuntimePressureWorkItemsPerSnapshot))
        {
            return;
        }

        TagList tags = default;
        tags.Add(RuntimeShardIndexTagName, shardIndex);
        if (DelayedApplicationSends.Enabled)
        {
            DelayedApplicationSends.Record(runtime.DelayedApplicationSendCount, in tags);
        }

        if (applicationSendCauseRetentionEnabled)
        {
            Span<QuicRetentionSnapshot> causeSnapshots =
                stackalloc QuicRetentionSnapshot[QuicApplicationSendQueue.QueueCauseCount];
            QuicRetentionSnapshot snapshot = runtime.CaptureApplicationSendRetentionSnapshots(causeSnapshots);
            if (applicationSendRetentionEnabled)
            {
                if (ApplicationSendRetainedBuffers.Enabled)
                {
                    ApplicationSendRetainedBuffers.Record(snapshot.RetainedBufferCount, in tags);
                }

                if (ApplicationSendRetainedBytes.Enabled)
                {
                    ApplicationSendRetainedBytes.Record(snapshot.RetainedByteCount, in tags);
                }
            }

            RecordApplicationSendCauseRetention(shardIndex, causeSnapshots);
        }
        else if (applicationSendRetentionEnabled)
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

        if (sentPacketRetentionEnabled && sentPacketNumberSpanEnabled)
        {
            QuicRetentionSnapshot snapshot = runtime.CaptureSentPacketRetentionSnapshot(
                out QuicSentPacketStorageSnapshot storageSnapshot);
            RecordSentPacketRetentionSnapshot(in tags, snapshot);
            RecordSentPacketStorageSnapshot(in tags, storageSnapshot);
        }
        else
        {
            if (sentPacketRetentionEnabled)
            {
                RecordSentPacketRetentionSnapshot(in tags, runtime.CaptureSentPacketRetentionSnapshot());
            }

            if (sentPacketNumberSpanEnabled)
            {
                RecordSentPacketStorageSnapshot(in tags, runtime.CaptureSentPacketStorageSnapshot());
            }
            else if (SentPacketStorageCapacity.Enabled)
            {
                SentPacketStorageCapacity.Record(runtime.SentPacketStorageCapacity, in tags);
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

        if (receiveRetentionEnabled)
        {
            QuicReceiveRetentionSnapshot snapshot = runtime.CaptureReceiveRetentionSnapshot();
            if (ReceiveRetainedBuffers.Enabled)
            {
                ReceiveRetainedBuffers.Record(snapshot.RetainedBufferCount, in tags);
            }

            if (ReceiveRetainedBytes.Enabled)
            {
                ReceiveRetainedBytes.Record(snapshot.RetainedBufferBytes, in tags);
            }

            if (ReceiveBufferedBytes.Enabled)
            {
                ReceiveBufferedBytes.Record(snapshot.BufferedBytes, in tags);
            }

            if (ReceiveBufferedStreams.Enabled)
            {
                ReceiveBufferedStreams.Record(snapshot.BufferedStreamCount, in tags);
            }
        }
    }

    private static void RecordSentPacketStorageSnapshot(
        in TagList shardTags,
        QuicSentPacketStorageSnapshot snapshot)
    {
        if (SentPacketNumberSpan.Enabled)
        {
            QuicSentPacketNumberSpaceStorageSnapshot applicationData =
                snapshot.GetPacketNumberSpace(QuicPacketNumberSpace.ApplicationData);
            if (applicationData.RetainedPacketCount > 0)
            {
                SentPacketNumberSpan.Record((long)applicationData.PacketNumberSpan, in shardTags);
            }
        }

        if (SentPacketStorageCapacity.Enabled)
        {
            SentPacketStorageCapacity.Record(snapshot.Capacity, in shardTags);
        }
    }

    private static void RecordSentPacketRetentionSnapshot(
        in TagList shardTags,
        QuicRetentionSnapshot snapshot)
    {
        if (RetainedSentPacketBuffers.Enabled)
        {
            RetainedSentPacketBuffers.Record(snapshot.RetainedBufferCount, in shardTags);
        }

        if (RetainedSentPacketBytes.Enabled)
        {
            RetainedSentPacketBytes.Record(snapshot.RetainedByteCount, in shardTags);
        }

        if (RetainedSentPacketOldestAge.Enabled && snapshot.OldestAgeMilliseconds.HasValue)
        {
            RetainedSentPacketOldestAge.Record(snapshot.OldestAgeMilliseconds.Value, in shardTags);
        }
    }

    private static void RecordApplicationSendCauseRetention(
        int shardIndex,
        ReadOnlySpan<QuicRetentionSnapshot> causeSnapshots)
    {
        for (int causeIndex = 0; causeIndex < ApplicationSendQueueCauses.Length; causeIndex++)
        {
            RecordApplicationSendCauseRetention(
                shardIndex,
                ApplicationSendQueueCauses[causeIndex],
                causeSnapshots[causeIndex]);
        }
    }

    internal static void RecordApplicationSendCauseRetention(
        int shardIndex,
        QuicApplicationSendQueueCause queueCause,
        QuicRetentionSnapshot snapshot)
    {
        TagList tags = default;
        tags.Add(RuntimeShardIndexTagName, shardIndex);
        tags.Add(QueueCauseTagName, FormatApplicationSendQueueCause(queueCause));
        if (ApplicationSendCauseRetainedBuffers.Enabled)
        {
            ApplicationSendCauseRetainedBuffers.Record(snapshot.RetainedBufferCount, in tags);
        }

        if (ApplicationSendCauseRetainedBytes.Enabled)
        {
            ApplicationSendCauseRetainedBytes.Record(snapshot.RetainedByteCount, in tags);
        }

        if (ApplicationSendCauseOldestAge.Enabled && snapshot.OldestAgeMilliseconds.HasValue)
        {
            ApplicationSendCauseOldestAge.Record(snapshot.OldestAgeMilliseconds.Value, in tags);
        }
    }

    internal static string FormatApplicationSendQueueCause(QuicApplicationSendQueueCause queueCause)
        => queueCause switch
        {
            QuicApplicationSendQueueCause.PendingRetransmission => "pending_retransmission",
            QuicApplicationSendQueueCause.OversizedWrite => "oversized_write",
            QuicApplicationSendQueueCause.SmallWriteDelay => "small_write_delay",
            QuicApplicationSendQueueCause.DirectSendBlocked => "direct_send_blocked",
            _ => throw new ArgumentOutOfRangeException(nameof(queueCause)),
        };

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

    internal static void RecordBufferRent(
        int requestedLength,
        int rentedLength,
        QuicBufferPoolOwner owner)
    {
        bool ownerMetricsEnabled = BufferPoolOwnerRents.Enabled
            || BufferPoolOwnerBytesRequested.Enabled
            || BufferPoolOwnerBytesRented.Enabled;
        if (!BufferPoolRents.Enabled
            && !BufferPoolRequestedRents.Enabled
            && !BufferPoolBytesRequested.Enabled
            && !BufferPoolBytesRented.Enabled
            && !BufferPoolOutstandingBuffers.Enabled
            && !BufferPoolOutstandingBytes.Enabled
            && !BufferPoolOversizedRents.Enabled
            && !ownerMetricsEnabled)
        {
            return;
        }

        if (ownerMetricsEnabled)
        {
            int ownerIndex = (int)owner;
            Interlocked.Increment(ref BufferPoolOwnerRentCounts[ownerIndex]);
            Interlocked.Add(ref BufferPoolOwnerRequestedByteCounts[ownerIndex], requestedLength);
            Interlocked.Add(ref BufferPoolOwnerRentedByteCounts[ownerIndex], rentedLength);
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

    private static IEnumerable<Measurement<long>> ObserveBufferPoolOwnerMetric(long[] values)
    {
        for (int ownerIndex = 0; ownerIndex < values.Length; ownerIndex++)
        {
            yield return new Measurement<long>(
                Volatile.Read(ref values[ownerIndex]),
                new KeyValuePair<string, object?>(
                    BufferOwnerTagName,
                    FormatBufferPoolOwner((QuicBufferPoolOwner)ownerIndex)));
        }
    }

    internal static string FormatBufferPoolOwner(QuicBufferPoolOwner owner)
        => owner switch
        {
            QuicBufferPoolOwner.Other => "other",
            QuicBufferPoolOwner.Acknowledgment => "acknowledgment",
            QuicBufferPoolOwner.Handshake => "handshake",
            QuicBufferPoolOwner.InboundDatagram => "inbound_datagram",
            QuicBufferPoolOwner.ReceiveSegment => "receive_segment",
            QuicBufferPoolOwner.StreamWriteRequest => "stream_write_request",
            QuicBufferPoolOwner.OutboundStreamPayload => "outbound_stream_payload",
            QuicBufferPoolOwner.CombinedApplicationSend => "combined_application_send",
            QuicBufferPoolOwner.InboundPacketProtection => "inbound_packet_protection",
            QuicBufferPoolOwner.OutboundPacketProtection => "outbound_packet_protection",
            QuicBufferPoolOwner.SentPacketRetention => "sent_packet_retention",
            QuicBufferPoolOwner.Retransmission => "retransmission",
            QuicBufferPoolOwner.ControlFrame => "control_frame",
            QuicBufferPoolOwner.ListenerResponse => "listener_response",
            _ => throw new ArgumentOutOfRangeException(nameof(owner)),
        };

    private static IEnumerable<Measurement<long>> ObserveRuntimeShardInboxDepth()
    {
        RuntimeShardMetricsRegistration[] registrations = Volatile.Read(ref runtimeShardMetricsRegistrations);
        var depthsByShard = new Dictionary<int, long>();
        foreach (RuntimeShardMetricsRegistration registration in registrations)
        {
            depthsByShard.TryGetValue(registration.ShardIndex, out long depth);
            depthsByShard[registration.ShardIndex] = depth + registration.InboxDepth;
        }

        foreach ((int shardIndex, long depth) in depthsByShard)
        {
            yield return new Measurement<long>(
                depth,
                new KeyValuePair<string, object?>(RuntimeShardIndexTagName, shardIndex));
        }
    }

    private static IEnumerable<Measurement<long>> ObserveRuntimeShardWorkItemDepth()
    {
        RuntimeShardMetricsRegistration[] registrations = Volatile.Read(ref runtimeShardMetricsRegistrations);
        var depthsByShard = new Dictionary<int, long[]>();
        foreach (RuntimeShardMetricsRegistration registration in registrations)
        {
            if (!depthsByShard.TryGetValue(registration.ShardIndex, out long[]? depths))
            {
                depths = new long[RuntimeShardWorkItemKindCount];
                depthsByShard.Add(registration.ShardIndex, depths);
            }

            for (var workItemKindIndex = 0; workItemKindIndex < RuntimeShardWorkItemKindCount; workItemKindIndex++)
            {
                depths[workItemKindIndex] += registration.GetWorkItemDepth(workItemKindIndex);
            }
        }

        foreach ((int shardIndex, long[] depths) in depthsByShard)
        {
            for (var workItemKindIndex = 0; workItemKindIndex < RuntimeShardWorkItemKindCount; workItemKindIndex++)
            {
                yield return new Measurement<long>(
                    depths[workItemKindIndex],
                    new KeyValuePair<string, object?>(RuntimeShardIndexTagName, shardIndex),
                    new KeyValuePair<string, object?>(RuntimeShardWorkItemKindTagName, GetRuntimeShardWorkItemKindTag(workItemKindIndex)));
            }
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

    private static string GetRuntimeShardWorkItemKindTag(int workItemKindIndex)
    {
        if (workItemKindIndex == RuntimeShardDeadlineWakeWorkItemKindIndex)
        {
            return "deadline_wake";
        }

        return ((QuicConnectionRuntimeShardWorkItemKind)workItemKindIndex) switch
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
