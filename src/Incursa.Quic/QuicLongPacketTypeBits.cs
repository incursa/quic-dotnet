// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Long-packet type bits are the wire values used by the RFC 9000 long-header packet
// type field, so the constants stay aligned with the parsed packet enums.
// SEE: QuicLongHeaderPacket
/// <summary>
/// Logical QUIC long-header packet types.
/// </summary>
internal enum QuicLongPacketType
{
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    Retry = 3,
}

/// <summary>
/// Long-header packet type values from the RFC 9000 packet-type field.
/// </summary>
internal static class QuicLongPacketTypeBits
{
    /// <summary>
    /// The Initial packet type value.
    /// </summary>
    internal const byte Initial = 0x00;

    /// <summary>
    /// The 0-RTT packet type value.
    /// </summary>
    internal const byte ZeroRtt = 0x01;

    /// <summary>
    /// The Handshake packet type value.
    /// </summary>
    internal const byte Handshake = 0x02;

    /// <summary>
    /// The Retry packet type value.
    /// </summary>
    internal const byte Retry = 0x03;
}
