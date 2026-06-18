// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents one parsed WebSocket frame carried on an RFC 9220 HTTP/3 tunnel stream.
/// </summary>
/// <param name="IsFinal">Whether this frame carries the FIN bit.</param>
/// <param name="Opcode">The frame opcode.</param>
/// <param name="Payload">The unmasked frame payload.</param>
/// <param name="IsMasked">Whether the wire frame carried a masking key.</param>
public sealed record Http3WebSocketFrame(
    bool IsFinal,
    Http3WebSocketOpcode Opcode,
    ReadOnlyMemory<byte> Payload,
    bool IsMasked);
