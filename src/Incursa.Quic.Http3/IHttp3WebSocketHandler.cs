// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Handles an accepted RFC 9220 WebSocket tunnel.
/// </summary>
public interface IHttp3WebSocketHandler
{
    /// <summary>
    /// Handles one accepted WebSocket-over-HTTP/3 tunnel stream.
    /// </summary>
    ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default);
}
