// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Receives hot-path HTTP/3 lifecycle diagnostics without requiring allocation of full diagnostic event records.
/// </summary>
public interface IHttp3LifecycleDiagnosticsSink : IHttp3DiagnosticsSink
{
    /// <summary>
    /// Emits an HTTP/3 request-started lifecycle event.
    /// </summary>
    void EmitRequestStarted(string role, long streamId, string method, string path);

    /// <summary>
    /// Emits an HTTP/3 response-started lifecycle event.
    /// </summary>
    void EmitResponseStarted(string role, long streamId, int statusCode);

    /// <summary>
    /// Emits an HTTP/3 response-completed lifecycle event.
    /// </summary>
    void EmitResponseCompleted(string role, long streamId, int statusCode, int payloadLength);

    /// <summary>
    /// Emits an HTTP/3 request-completed lifecycle event.
    /// </summary>
    void EmitRequestCompleted(string role, long streamId, string method, string path, int statusCode, int payloadLength);
}
