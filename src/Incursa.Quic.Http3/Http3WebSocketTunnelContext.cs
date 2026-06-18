// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides access to an accepted RFC 9220 WebSocket tunnel stream.
/// </summary>
public sealed class Http3WebSocketTunnelContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3WebSocketTunnelContext" /> class.
    /// </summary>
    public Http3WebSocketTunnelContext(Http3Request request, QuicStream stream)
    {
        Request = request ?? throw new ArgumentNullException(nameof(request));
        Stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    /// <summary>
    /// Gets the decoded Extended CONNECT request that opened the tunnel.
    /// </summary>
    public Http3Request Request { get; }

    /// <summary>
    /// Gets the bidirectional HTTP/3 request stream carrying WebSocket bytes after the response headers.
    /// </summary>
    public QuicStream Stream { get; }
}
