// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The two values mirror the single high bit in the first packet byte so parser branching
// stays aligned with the wire layout instead of introducing an extra translation layer.
// SEE: QuicLongHeaderPacket
/// <summary>
/// Identifies the version-independent QUIC packet header form.
/// </summary>
internal enum QuicHeaderForm
{
    /// <summary>
    /// A packet with the first byte high bit cleared.
    /// </summary>
    Short = 0,

    /// <summary>
    /// A packet with the first byte high bit set.
    /// </summary>
    Long = 1,
}
