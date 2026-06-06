// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: This notification keeps the blocked stream-count limit separate from MAX_STREAMS so the
// runtime can surface the limit that was actually exhausted rather than the latest grant.
// SEE: QuicMaxStreamsFrame
/// <summary>
/// A parsed or constructed STREAMS_BLOCKED frame.
/// </summary>
internal readonly struct QuicStreamsBlockedFrame
{
    /// <summary>
    /// Initializes a STREAMS_BLOCKED frame view.
    /// </summary>
    internal QuicStreamsBlockedFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }

    /// <summary>
    /// Gets whether the frame applies to bidirectional streams.
    /// </summary>
    internal bool IsBidirectional { get; }

    /// <summary>
    /// Gets the maximum number of streams allowed at the time the frame was sent.
    /// </summary>
    internal ulong MaximumStreams { get; }
}
