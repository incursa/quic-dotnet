// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_STREAM_DATA frame.
/// </summary>
internal readonly struct QuicMaxStreamDataFrame
{
    /// <summary>
    /// Initializes a MAX_STREAM_DATA frame view.
    /// </summary>
    internal QuicMaxStreamDataFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }

    /// <summary>
    /// Gets the affected stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the maximum stream data limit.
    /// </summary>
    internal ulong MaximumStreamData { get; }
}

