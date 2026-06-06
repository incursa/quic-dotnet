// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: These STREAM frame bit values are the shared wire contract used by parsing, framing,
// and legality checks, so the bit positions should not be renumbered.
// SEE: QuicStreamParser and QuicPacketFrameLegality
/// <summary>
/// STREAM frame type values and type-specific flag bits from the RFC 9000 frame registry.
/// </summary>
internal static class QuicStreamFrameBits
{
    /// <summary>
    /// The minimum STREAM frame type value.
    /// </summary>
    internal const byte StreamFrameTypeMinimum = 0x08;

    /// <summary>
    /// The maximum STREAM frame type value.
    /// </summary>
    internal const byte StreamFrameTypeMaximum = 0x0F;

    /// <summary>
    /// The optional offset-present bit.
    /// </summary>
    internal const byte OffsetBitMask = 0x04;

    /// <summary>
    /// The optional length-present bit.
    /// </summary>
    internal const byte LengthBitMask = 0x02;

    /// <summary>
    /// The FIN bit.
    /// </summary>
    internal const byte FinBitMask = 0x01;
}
