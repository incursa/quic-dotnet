// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures HTTP/3 diagnostic emission allocation in enabled and disabled sink configurations.
/// </summary>
[MemoryDiagnoser]
public class Http3DiagnosticAllocationBenchmarks
{
    private const string Role = "server";
    private const long RequestStreamId = 4;
    private const string Method = "GET";
    private const string Path = "/plaintext";
    private readonly CountingHttp3DiagnosticsSink disabledSink = new(enabled: false);
    private readonly CountingHttp3DiagnosticsSink enabledSink = new(enabled: true);

    /// <summary>
    /// Measures the hot disabled-sink stream-opened diagnostic path.
    /// </summary>
    [Benchmark]
    public int DiagnosticsDisabled_StreamOpened()
    {
        Http3Server.EmitStreamOpenedDiagnostic(disabledSink, Role, RequestStreamId, Http3StreamKind.Request);
        return disabledSink.EmitCalls;
    }

    /// <summary>
    /// Measures the enabled-sink stream-opened diagnostic path.
    /// </summary>
    [Benchmark]
    public int DiagnosticsEnabled_StreamOpened()
    {
        Http3Server.EmitStreamOpenedDiagnostic(enabledSink, Role, RequestStreamId, Http3StreamKind.Request);
        return enabledSink.EmitCalls;
    }

    /// <summary>
    /// Measures the hot disabled-sink frame diagnostic path.
    /// </summary>
    [Benchmark]
    public int DiagnosticsDisabled_FrameEmitted()
    {
        Http3Server.EmitFrameDiagnostic(
            disabledSink,
            Http3DiagnosticKind.FrameSent,
            Role,
            RequestStreamId,
            Http3FrameType.Data,
            payloadLength: 13);
        return disabledSink.EmitCalls;
    }

    /// <summary>
    /// Measures the enabled-sink frame diagnostic path.
    /// </summary>
    [Benchmark]
    public int DiagnosticsEnabled_FrameEmitted()
    {
        Http3Server.EmitFrameDiagnostic(
            enabledSink,
            Http3DiagnosticKind.FrameSent,
            Role,
            RequestStreamId,
            Http3FrameType.Data,
            payloadLength: 13);
        return enabledSink.EmitCalls;
    }

    /// <summary>
    /// Measures a request lifecycle-shaped sequence when diagnostics are disabled.
    /// </summary>
    [Benchmark]
    public int DiagnosticsDisabled_RequestLifecycleShape()
    {
        EmitRequestLifecycleShape(disabledSink);
        return disabledSink.EmitCalls;
    }

    /// <summary>
    /// Measures a request lifecycle-shaped sequence when diagnostics are enabled.
    /// </summary>
    [Benchmark]
    public int DiagnosticsEnabled_RequestLifecycleShape()
    {
        EmitRequestLifecycleShape(enabledSink);
        return enabledSink.EmitCalls;
    }

    private static void EmitRequestLifecycleShape(IHttp3DiagnosticsSink sink)
    {
        Http3Server.EmitStreamOpenedDiagnostic(sink, Role, RequestStreamId, Http3StreamKind.Request);
        Http3Server.EmitFrameDiagnostic(sink, Http3DiagnosticKind.FrameReceived, Role, RequestStreamId, Http3FrameType.Headers, payloadLength: 36);
        Http3Server.EmitRequestStartedDiagnostic(sink, Role, RequestStreamId, Method, Path);
        Http3Server.EmitFrameDiagnostic(sink, Http3DiagnosticKind.FrameSent, Role, RequestStreamId, Http3FrameType.Headers, payloadLength: 67);
        Http3Server.EmitResponseStartedDiagnostic(sink, Role, RequestStreamId, statusCode: 200);
        Http3Server.EmitFrameDiagnostic(sink, Http3DiagnosticKind.FrameSent, Role, RequestStreamId, Http3FrameType.Data, payloadLength: 13);
        Http3Server.EmitResponseCompletedDiagnostic(sink, Role, RequestStreamId, statusCode: 200, payloadLength: 13);
        Http3Server.EmitRequestCompletedDiagnostic(sink, Role, RequestStreamId, Method, Path, statusCode: 200, payloadLength: 13);
        Http3Server.EmitStreamClosedDiagnostic(sink, Role, RequestStreamId, Http3StreamKind.Request);
    }

    private sealed class CountingHttp3DiagnosticsSink(bool enabled) : IHttp3DiagnosticsSink
    {
        private int emitCalls;

        public bool IsEnabled => enabled;

        public int EmitCalls => emitCalls;

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            ArgumentNullException.ThrowIfNull(diagnosticEvent);
            emitCalls++;
        }
    }
}
