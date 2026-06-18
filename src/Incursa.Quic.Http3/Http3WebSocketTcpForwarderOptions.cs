// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Configures RFC 9220 WebSocket-to-TCP forwarding.
/// </summary>
public sealed class Http3WebSocketTcpForwarderOptions
{
    private const int DefaultBufferSize = 16 * 1024;

    /// <summary>
    /// Gets or sets the maximum TCP read size forwarded as one binary WebSocket message.
    /// </summary>
    public int BufferSize { get; set; } = DefaultBufferSize;
}
