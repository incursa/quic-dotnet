// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a decoded WebSocket close payload carried on an RFC 9220 HTTP/3 tunnel stream.
/// </summary>
/// <param name="StatusCode">The optional close status code.</param>
/// <param name="Reason">The optional close reason.</param>
public sealed record Http3WebSocketCloseStatus(ushort? StatusCode, string? Reason);
