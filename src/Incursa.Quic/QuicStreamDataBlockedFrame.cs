// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The stream-scoped blocked notification reports the exact stream limit that stalled
// progress, which is different from the MAX_STREAM_DATA credit grant.
// SEE: QuicMaxStreamDataFrame
/// <summary>
/// A parsed or constructed STREAM_DATA_BLOCKED frame.
/// </summary>
internal readonly struct QuicStreamDataBlockedFrame
{
    /// <summary>
    /// Initializes a STREAM_DATA_BLOCKED frame view.
    /// </summary>
    internal QuicStreamDataBlockedFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }

    /// <summary>
    /// Gets the blocked stream identifier.
    /// </summary>
    internal ulong StreamId { get; }

    /// <summary>
    /// Gets the stream data offset at which blocking occurred.
    /// </summary>
    internal ulong MaximumStreamData { get; }
}
