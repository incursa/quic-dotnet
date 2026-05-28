// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the QUIC stream direction.
/// </summary>
public enum Http3StreamDirection
{
    /// <summary>
    /// Bidirectional stream.
    /// </summary>
    Bidirectional,

    /// <summary>
    /// Unidirectional stream.
    /// </summary>
    Unidirectional,
}
