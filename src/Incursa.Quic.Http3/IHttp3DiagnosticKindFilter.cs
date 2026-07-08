// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Allows diagnostics sinks to opt in to only the HTTP/3 diagnostic event kinds they consume.
/// </summary>
public interface IHttp3DiagnosticKindFilter : IHttp3DiagnosticsSink
{
    /// <summary>
    /// Gets a value indicating whether the sink wants the specified event kind.
    /// </summary>
    bool IsEnabledFor(Http3DiagnosticKind kind);
}
