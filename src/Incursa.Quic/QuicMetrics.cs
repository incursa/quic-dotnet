using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Incursa.Quic;

/// <summary>
/// Owns the standard QUIC metrics surface without coupling the transport to a collector.
/// </summary>
internal static class QuicMetrics
{
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
    private static readonly Histogram<double> Rtt = Meter.CreateHistogram<double>("incursa.quic.rtt.ms", unit: "ms");

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

    private static TagList CreateStreamTags(QuicTlsRole role, ulong streamId, QuicStreamType streamType)
    {
        TagList tags = default;
        tags.Add("role", GetRoleTag(role));
        tags.Add("direction", GetDirectionTag(streamType));
        tags.Add("initiator", GetInitiatorTag(role, streamId));
        return tags;
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
