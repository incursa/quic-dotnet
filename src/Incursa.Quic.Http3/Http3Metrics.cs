// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Diagnostics.Metrics;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Owns the standard HTTP/3 metrics surface without depending on a collector.
/// </summary>
internal static class Http3Metrics
{
    internal const string MeterName = "Incursa.Quic.Http3";

    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> RequestsStarted = Meter.CreateCounter<long>("incursa.http3.requests.started", unit: "requests");
    private static readonly Counter<long> RequestsCompleted = Meter.CreateCounter<long>("incursa.http3.requests.completed", unit: "requests");
    private static readonly Counter<long> RequestsFailed = Meter.CreateCounter<long>("incursa.http3.requests.failed", unit: "requests");
    private static readonly Histogram<double> RequestDuration = Meter.CreateHistogram<double>("incursa.http3.request.duration.ms", unit: "ms");

    internal static long GetTimestamp()
    {
        return Stopwatch.GetTimestamp();
    }

    internal static void RecordRequestStarted(string role)
    {
        if (!RequestsStarted.Enabled)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", NormalizeRole(role));
        RequestsStarted.Add(1, in tags);
    }

    internal static void RecordRequestCompleted(string role, int statusCode, long startedTimestamp)
    {
        if (RequestsCompleted.Enabled)
        {
            TagList tags = default;
            tags.Add("role", NormalizeRole(role));
            tags.Add("status_class", QuicMetrics.GetStatusClass(statusCode));
            RequestsCompleted.Add(1, in tags);
        }

        RecordDuration(role, startedTimestamp);
    }

    internal static void RecordRequestFailed(string role, string failureReason, long startedTimestamp)
    {
        if (RequestsFailed.Enabled)
        {
            TagList tags = default;
            tags.Add("role", NormalizeRole(role));
            tags.Add("failure_reason", NormalizeFailureReason(failureReason));
            RequestsFailed.Add(1, in tags);
        }

        RecordDuration(role, startedTimestamp);
    }

    internal static string NormalizeFailureReason(Exception exception)
    {
        return exception switch
        {
            OperationCanceledException => "canceled",
            QuicException => "quic",
            QPackException => "qpack",
            Http3Exception => "http3",
            ArgumentException => "argument",
            _ => "exception",
        };
    }

    internal static string NormalizeFailureReason(string failureReason)
    {
        return failureReason switch
        {
            "canceled" => "canceled",
            "quic" => "quic",
            "qpack" => "qpack",
            "http3" => "http3",
            "argument" => "argument",
            _ => "exception",
        };
    }

    private static void RecordDuration(string role, long startedTimestamp)
    {
        if (!RequestDuration.Enabled || startedTimestamp == 0)
        {
            return;
        }

        TagList tags = default;
        tags.Add("role", NormalizeRole(role));
        RequestDuration.Record(Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds, in tags);
    }

    private static string NormalizeRole(string role)
    {
        return string.Equals(role, "server", StringComparison.Ordinal) ? "server" : "client";
    }
}
