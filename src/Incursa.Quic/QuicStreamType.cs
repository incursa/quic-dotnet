// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The byte values mirror the low-order stream-ID bits so direction and initiator checks
// stay wire-aligned instead of introducing an extra translation layer.
// SEE: QuicStreamId
/// <summary>
/// Identifies the direction of a QUIC stream.
/// </summary>
public enum QuicStreamType : byte
{
    /// <summary>
    /// A unidirectional stream.
    /// </summary>
    Unidirectional = 0,

    /// <summary>
    /// A bidirectional stream.
    /// </summary>
    Bidirectional = 1,
}
