// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

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

