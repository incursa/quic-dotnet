// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic.Http3;
using Incursa.Quic.Qlog;

namespace Incursa.Quic.Tests;

public sealed class Http3QlogDiagnosticsTests
{
    [Fact]
    public void SinkWritesHttp3EventsIntoContainedQlog()
    {
        QuicQlogCapture capture = new(title: "http3 diagnostics");
        QuicQlogHttp3DiagnosticsSink sink = new(capture, isServer: false);

        sink.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.FrameSent)
        {
            StreamId = 0,
            StreamKind = Http3StreamKind.Control,
            FrameType = Http3FrameType.Settings,
            RawFrameType = 4,
            PayloadLength = 6,
        });
        sink.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.QPackInstructionReceived)
        {
            StreamKind = Http3StreamKind.QPackEncoder,
            QPackInstruction = "insert-without-name-reference",
        });

        string json = capture.ToJson();

        Assert.Contains("http3:frame_sent", json, StringComparison.Ordinal);
        Assert.Contains("http3:q_pack_instruction_received", json, StringComparison.Ordinal);
        Assert.Contains("\"frame_type\":\"Settings\"", json, StringComparison.Ordinal);
        Assert.Contains("\"qpack_instruction\":\"insert-without-name-reference\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void SinkDefaultsRoleFromConfiguredVantagePoint()
    {
        QuicQlogCapture capture = new(title: "http3 server diagnostics");
        QuicQlogHttp3DiagnosticsSink sink = new(capture, isServer: true);

        sink.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionStarted));

        string json = capture.ToJson();

        Assert.Contains("\"role\":\"server\"", json, StringComparison.Ordinal);
        Assert.Contains("\"type\":\"server\"", json, StringComparison.Ordinal);
    }
}
