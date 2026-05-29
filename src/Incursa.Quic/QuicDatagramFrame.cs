// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Represents an RFC 9221 DATAGRAM frame.
/// </summary>
internal sealed class QuicDatagramFrame
{
    /// <summary>
    /// Gets or sets the DATAGRAM frame type. Valid values are 0x30 and 0x31.
    /// </summary>
    internal byte FrameType { get; set; }

    /// <summary>
    /// Gets whether the frame type carries an explicit Length field.
    /// </summary>
    internal bool HasLength => (FrameType & 0x01) != 0;

    /// <summary>
    /// Gets or sets the application datagram payload.
    /// </summary>
    internal ReadOnlyMemory<byte> DatagramData { get; set; } = ReadOnlyMemory<byte>.Empty;
}
