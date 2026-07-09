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

    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> ConnectionsStarted = Meter.CreateCounter<long>("incursa.quic.connections.started", unit: "connections");
    private static readonly UpDownCounter<long> ConnectionsActive = Meter.CreateUpDownCounter<long>("incursa.quic.connections.active", unit: "connections");
    private static readonly Counter<long> ConnectionsClosed = Meter.CreateCounter<long>("incursa.quic.connections.closed", unit: "connections");
    private static readonly Counter<long> StreamsOpened = Meter.CreateCounter<long>("incursa.quic.streams.opened", unit: "streams");
    private static readonly UpDownCounter<long> StreamsActive = Meter.CreateUpDownCounter<long>("incursa.quic.streams.active", unit: "streams");
    private static readonly Counter<long> StreamsClosed = Meter.CreateCounter<long>("incursa.quic.streams.closed", unit: "streams");
    private static readonly Counter<long> DatagramsReceived = Meter.CreateCounter<long>("incursa.quic.datagrams.received", unit: "datagrams");
    private static readonly Counter<long> DatagramsSent = Meter.CreateCounter<long>("incursa.quic.datagrams.sent", unit: "datagrams");
    private static readonly Counter<long> BytesReceived = Meter.CreateCounter<long>("incursa.quic.bytes.received", unit: "bytes");
    private static readonly Counter<long> BytesSent = Meter.CreateCounter<long>("incursa.quic.bytes.sent", unit: "bytes");
    private static readonly Counter<long> PacketsDropped = Meter.CreateCounter<long>("incursa.quic.packets.dropped", unit: "packets");
    private static readonly Counter<long> FlowControlBlocked = Meter.CreateCounter<long>("incursa.quic.flow_control.blocked", unit: "events");
    private static readonly Counter<long> StreamLimitBlocked = Meter.CreateCounter<long>("incursa.quic.stream_limit.blocked", unit: "events");
    private static readonly Counter<long> AntiAmplificationBlocked = Meter.CreateCounter<long>("incursa.quic.anti_amplification.blocked", unit: "events");
    private static readonly Counter<long> ProbeTimeoutCount = Meter.CreateCounter<long>("incursa.quic.pto.count", unit: "events");
    private static readonly Counter<long> AeadOpenFailures = Meter.CreateCounter<long>("incursa.quic.aead.open_failures", unit: "events");
    private static readonly Counter<long> UdpErrors = Meter.CreateCounter<long>("incursa.quic.udp.errors", unit: "events");
    private static readonly Histogram<double> Rtt = Meter.CreateHistogram<double>("incursa.quic.rtt.ms", unit: "ms");
    private static readonly Counter<long> BufferPoolRents = Meter.CreateCounter<long>("incursa.quic.buffer_pool.rents", unit: "buffers");
    private static readonly Counter<long> BufferPoolRequestedRents = Meter.CreateCounter<long>("incursa.quic.buffer_pool.requested_rents", unit: "buffers");
    private static readonly Counter<long> BufferPoolReturns = Meter.CreateCounter<long>("incursa.quic.buffer_pool.returns", unit: "buffers");
    private static readonly Counter<long> BufferPoolBytesRequested = Meter.CreateCounter<long>("incursa.quic.buffer_pool.bytes.requested", unit: "bytes");
    private static readonly Counter<long> BufferPoolBytesRented = Meter.CreateCounter<long>("incursa.quic.buffer_pool.bytes.rented", unit: "bytes");
    private static readonly Counter<long> BufferPoolBytesReturned = Meter.CreateCounter<long>("incursa.quic.buffer_pool.bytes.returned", unit: "bytes");
    private static readonly ObservableGauge<long> BufferPoolOutstandingBuffers = Meter.CreateObservableGauge("incursa.quic.buffer_pool.outstanding.buffers", ObserveBufferPoolOutstandingBuffers, unit: "buffers");
    private static readonly ObservableGauge<long> BufferPoolOutstandingBytes = Meter.CreateObservableGauge("incursa.quic.buffer_pool.outstanding.bytes", ObserveBufferPoolOutstandingBytes, unit: "bytes");
    private static readonly Counter<long> BufferPoolOversizedRents = Meter.CreateCounter<long>("incursa.quic.buffer_pool.oversized_rents", unit: "buffers");
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

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        DatagramsReceived.Add(1, in tags);
        BytesReceived.Add(datagramLength, in tags);
    }

    internal static void RecordDatagramSent(QuicTlsRole role, int datagramLength)
    {
        if (datagramLength <= 0 || (!DatagramsSent.Enabled && !BytesSent.Enabled))
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        DatagramsSent.Add(1, in tags);
        BytesSent.Add(datagramLength, in tags);
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
        TagList tags = CreateBufferPoolTags(bucketIndex);
        TagList requestedTags = CreateBufferPoolRequestedTags(requestedBucketIndex);
        BufferPoolRequestedRents.Add(1, in requestedTags);
        BufferPoolBytesRequested.Add(requestedLength, in requestedTags);
        BufferPoolRents.Add(1, in tags);
        BufferPoolBytesRented.Add(rentedLength, in tags);
        Interlocked.Increment(ref BufferPoolOutstandingBufferCounts[bucketIndex]);
        Interlocked.Add(ref BufferPoolOutstandingByteCounts[bucketIndex], rentedLength);

        if (rentedLength > requestedLength)
        {
            BufferPoolOversizedRents.Add(1, in tags);
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
        TagList tags = CreateBufferPoolTags(bucketIndex);
        BufferPoolReturns.Add(1, in tags);
        BufferPoolBytesReturned.Add(bufferLength, in tags);
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

    private static TagList CreateBufferPoolTags(int bucketIndex)
    {
        TagList tags = default;
        tags.Add("size_bucket", GetBufferSizeBucket(bucketIndex));
        return tags;
    }

    private static TagList CreateBufferPoolRequestedTags(int requestedBucketIndex)
    {
        TagList tags = default;
        tags.Add("requested_size_bucket", GetBufferSizeBucket(requestedBucketIndex));
        return tags;
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
