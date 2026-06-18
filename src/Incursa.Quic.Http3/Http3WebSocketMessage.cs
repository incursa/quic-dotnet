// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents a complete WebSocket message reconstructed from an RFC 9220 HTTP/3 tunnel stream.
/// </summary>
/// <param name="Opcode">The message opcode. Data messages use <see cref="Http3WebSocketOpcode.Text" /> or <see cref="Http3WebSocketOpcode.Binary" />.</param>
/// <param name="Payload">The complete unmasked message payload.</param>
public sealed record Http3WebSocketMessage(Http3WebSocketOpcode Opcode, ReadOnlyMemory<byte> Payload);
