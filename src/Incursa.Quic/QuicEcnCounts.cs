// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: ECN counters are carried as an ACK-side snapshot, so this value type stays tiny and
// ordered to match the wire fields used during per-space validation.
// SEE: QuicEcnValidationState
/// <summary>
/// Parsed ECN counters carried by ACK frame type 0x03.
/// </summary>
internal readonly struct QuicEcnCounts
{
    /// <summary>
    /// Initializes a new ECN counter set.
    /// </summary>
    internal QuicEcnCounts(ulong ect0Count, ulong ect1Count, ulong ecnCeCount)
    {
        Ect0Count = ect0Count;
        Ect1Count = ect1Count;
        EcnCeCount = ecnCeCount;
    }

    /// <summary>
    /// Gets the ECT(0) count.
    /// </summary>
    internal ulong Ect0Count { get; }

    /// <summary>
    /// Gets the ECT(1) count.
    /// </summary>
    internal ulong Ect1Count { get; }

    /// <summary>
    /// Gets the ECN-CE count.
    /// </summary>
    internal ulong EcnCeCount { get; }
}
