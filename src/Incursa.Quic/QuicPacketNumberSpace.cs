// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Identifies the QUIC packet number space for ACK generation and scheduling.
/// </summary>
internal enum QuicPacketNumberSpace
{
    /// <summary>
    /// The Initial packet number space.
    /// </summary>
    Initial = 0,

    /// <summary>
    /// The Handshake packet number space.
    /// </summary>
    Handshake = 1,

    /// <summary>
    /// The Application Data packet number space.
    /// </summary>
    ApplicationData = 2,
}

