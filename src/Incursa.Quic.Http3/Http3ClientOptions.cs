// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Configures the minimal HTTP/3 client facade.
/// </summary>
public sealed class Http3ClientOptions
{
    private const int DefaultReadBufferSize = 16 * 1024;

    /// <summary>
    /// Gets or sets the local HTTP/3 SETTINGS sent on the client control stream.
    /// </summary>
    public Http3Settings Settings { get; set; } = new();

    /// <summary>
    /// Gets or sets the optional User-Agent field sent by the minimal GET request API.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Gets or sets the response read buffer size.
    /// </summary>
    public int ReadBufferSize { get; set; } = DefaultReadBufferSize;

    /// <summary>
    /// Gets or sets whether a response with a validated Content-Length can complete before stream FIN is observed.
    /// </summary>
    public bool CompleteResponseOnContentLength { get; set; }

    /// <summary>
    /// Gets or sets an optional diagnostics sink for HTTP/3 and QPACK stream events.
    /// </summary>
    public IHttp3DiagnosticsSink? DiagnosticsSink { get; set; }
}
