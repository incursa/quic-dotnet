// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Identifies the QUIC encryption epoch in which application stream data was received.
/// </summary>
/// <remarks>
/// This is an internal tracking marker. It is not exposed on the public <see cref="QuicStream"/> API.
/// Application protocols cannot distinguish 0-RTT from 1-RTT data through the public surface.
/// </remarks>
internal enum QuicApplicationDataEpoch
{
    /// <summary>
    /// Data received in a 1-RTT protected packet, after the handshake completed.
    /// </summary>
    OneRtt = 0,

    /// <summary>
    /// Data received in a 0-RTT protected packet, before the handshake completed.
    /// This data is replayable and must not be processed as if it were 1-RTT data
    /// unless the application protocol has explicitly opted into replay-safe semantics.
    /// </summary>
    ZeroRtt = 1,
}
