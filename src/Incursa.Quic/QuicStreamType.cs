// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

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

