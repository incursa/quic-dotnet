// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The sequence number is the only payload because CID retirement is ordered solely by
// sequence, and the frame exists to drive retire-prior-to processing.
// SEE: QuicConnectionPeerConnectionIdState
/// <summary>
/// A parsed or constructed RETIRE_CONNECTION_ID frame.
/// </summary>
internal readonly struct QuicRetireConnectionIdFrame
{
    /// <summary>
    /// Initializes a RETIRE_CONNECTION_ID frame view.
    /// </summary>
    internal QuicRetireConnectionIdFrame(ulong sequenceNumber)
    {
        SequenceNumber = sequenceNumber;
    }

    /// <summary>
    /// Gets the retired connection ID sequence number.
    /// </summary>
    internal ulong SequenceNumber { get; }
}
