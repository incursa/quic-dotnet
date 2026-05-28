// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed HANDSHAKE_DONE frame.
/// </summary>
internal readonly struct QuicHandshakeDoneFrame
{
    /// <summary>
    /// RFC 9000 HANDSHAKE_DONE frame type.
    /// </summary>
    private const byte FrameTypeValue = 0x1E;

    /// <summary>
    /// Gets the frame type carried on the wire.
    /// </summary>
    internal byte FrameType => FrameTypeValue;
}

