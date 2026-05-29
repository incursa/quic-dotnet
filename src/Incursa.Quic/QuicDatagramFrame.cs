// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Represents an RFC 9221 DATAGRAM frame.
/// </summary>
internal readonly struct QuicDatagramFrame
{
    internal QuicDatagramFrame(byte frameType, ReadOnlyMemory<byte> datagramData)
    {
        FrameType = frameType;
        DatagramData = datagramData;
    }

    /// <summary>
    /// Gets or sets the DATAGRAM frame type. Valid values are 0x30 and 0x31.
    /// </summary>
    internal byte FrameType { get; init; }

    /// <summary>
    /// Gets whether the frame type carries an explicit Length field.
    /// </summary>
    internal bool HasLength => (FrameType & 0x01) != 0;

    /// <summary>
    /// Gets or sets the application datagram payload.
    /// </summary>
    internal ReadOnlyMemory<byte> DatagramData { get; init; }
}
