// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// WebSocket opcodes used by RFC 9220 WebSocket-over-HTTP/3 streams.
/// </summary>
public enum Http3WebSocketOpcode : byte
{
    /// <summary>
    /// Continuation frame for a fragmented data message.
    /// </summary>
    Continuation = 0x0,

    /// <summary>
    /// UTF-8 text data message.
    /// </summary>
    Text = 0x1,

    /// <summary>
    /// Binary data message.
    /// </summary>
    Binary = 0x2,

    /// <summary>
    /// Close control message.
    /// </summary>
    Close = 0x8,

    /// <summary>
    /// Ping control message.
    /// </summary>
    Ping = 0x9,

    /// <summary>
    /// Pong control message.
    /// </summary>
    Pong = 0xA,
}
