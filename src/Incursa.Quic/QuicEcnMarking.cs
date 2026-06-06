// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The ECN codepoint order matches the native socket/TOS mapping used by the runtime, so
// the numeric values are part of the send-path contract.
// SEE: QuicSocketEcnControl
/// <summary>
/// Describes the ECN codepoint an endpoint applied when sending a QUIC packet.
/// </summary>
internal enum QuicEcnMarking
{
    /// <summary>
    /// The packet was sent without an ECN marking.
    /// </summary>
    NotEct = 0,

    /// <summary>
    /// The packet was sent with the ECT(0) codepoint.
    /// </summary>
    Ect0 = 1,

    /// <summary>
    /// The packet was sent with the ECT(1) codepoint.
    /// </summary>
    Ect1 = 2,
}
