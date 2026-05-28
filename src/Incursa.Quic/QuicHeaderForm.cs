// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

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

