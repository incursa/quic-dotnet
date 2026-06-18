// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Configures the minimal HTTP/3 server facade.
/// </summary>
public sealed class Http3ServerOptions
{
    private const int DefaultReadBufferSize = 16 * 1024;
    private const ushort DefaultWebSocketHandlerExceptionCloseStatusCode = 1011;
    private const string DefaultWebSocketHandlerExceptionCloseReason = "internal error";

    /// <summary>
    /// Gets or sets the local HTTP/3 SETTINGS sent on the server control stream.
    /// </summary>
    public Http3Settings Settings { get; set; } = new();

    /// <summary>
    /// Gets or sets the request-stream read buffer size.
    /// </summary>
    public int ReadBufferSize { get; set; } = DefaultReadBufferSize;

    /// <summary>
    /// Gets or sets an optional diagnostics sink for HTTP/3 and QPACK stream events.
    /// </summary>
    public IHttp3DiagnosticsSink? DiagnosticsSink { get; set; }

    /// <summary>
    /// Gets or sets an optional handler for accepted RFC 9220 WebSocket Extended CONNECT tunnels.
    /// </summary>
    public IHttp3WebSocketHandler? WebSocketHandler { get; set; }

    /// <summary>
    /// Gets or sets the optional interval for automatic server WebSocket ping frames on accepted tunnels.
    /// </summary>
    public TimeSpan? WebSocketKeepAliveInterval { get; set; }

    /// <summary>
    /// Gets or sets the payload sent with automatic server WebSocket ping frames on accepted tunnels.
    /// </summary>
    public ReadOnlyMemory<byte> WebSocketKeepAlivePayload { get; set; } = ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Gets or sets the WebSocket close status used for unexpected accepted tunnel handler exceptions.
    /// </summary>
    public ushort WebSocketHandlerExceptionCloseStatusCode { get; set; } = DefaultWebSocketHandlerExceptionCloseStatusCode;

    /// <summary>
    /// Gets or sets the WebSocket close reason used for unexpected accepted tunnel handler exceptions.
    /// </summary>
    public string? WebSocketHandlerExceptionCloseReason { get; set; } = DefaultWebSocketHandlerExceptionCloseReason;
}
