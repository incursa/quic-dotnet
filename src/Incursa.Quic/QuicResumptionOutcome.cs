// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// The public outcome of a connection's resumption attempt.
/// </summary>
public enum QuicResumptionOutcome
{
    /// <summary>
    /// No resumption ticket was supplied, or the connection completed on the full-handshake path.
    /// </summary>
    NotAttempted = 0,

    /// <summary>
    /// A valid resumption ticket was accepted and the connection resumed.
    /// </summary>
    Resumed = 1,

    /// <summary>
    /// A valid resumption ticket was supplied but the peer rejected it.
    /// </summary>
    Rejected = 2,

    /// <summary>
    /// The supplied ticket could not participate in the resumption path.
    /// </summary>
    InvalidTicket = 3,
}
